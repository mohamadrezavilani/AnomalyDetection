"""Restore a pinned accepted release after PostgreSQL recovery, without an upgrade.

Run with the project's Python as Windows Administrator. The failed upgrade
receipt supplies the previous release and checkpoint floor. Never reset data,
prepare a history job, terminate processes, or retry a failed launch blindly.
"""

import argparse
from datetime import datetime
import json
import ntpath
from pathlib import Path
import re
import sys
import time

sys.dont_write_bytecode = True


def norm(value):
    return ntpath.normcase(ntpath.normpath(str(value)))


def require(condition, code):
    if not condition:
        raise ValueError(code)


def validate_receipt(receipt, root):
    require(receipt.get("status") == "COMPACT_UPGRADE_RESTORE_NEEDS_ATTENTION",
            "FAILED_UPGRADE_RECEIPT_REQUIRED")
    require(receipt.get("data_reset") is False, "RECEIPT_DATA_RESET_NOT_FALSE")
    require(norm(receipt.get("previous_code_root", "")) == norm(root),
            "PREVIOUS_RELEASE_PATH_MISMATCH")
    before = receipt.get("before") or {}
    require(type(before.get("input_next_ns")) is int and
            isinstance(before.get("history"), dict), "RECEIPT_CHECKPOINTS_REQUIRED")
    return before


def preserved(before, after):
    require(type(after.get("input_next_ns")) is int and
            after["input_next_ns"] >= before["input_next_ns"], "INPUT_CHECKPOINT_REWOUND")
    old, new = before.get("history"), after.get("history")
    require(bool(old and new) and old.get("job_id") == new.get("job_id") and
            type(old.get("next_ns")) is int and type(new.get("next_ns")) is int and
            new["next_ns"] >= old["next_ns"], "HISTORY_CHECKPOINT_CHANGED_OR_REWOUND")
    for field in ("from_ns", "target_ns"):
        if field in old:
            require(old[field] == new.get(field), "HISTORY_RANGE_CHANGED")


def validate_roles(roles, expected):
    for role, info in roles.items():
        if info.get("running"):
            require(info.get("package", {}).get("source_sha256") == expected,
                    "RUNNING_RELEASE_MISMATCH:" + role)


def validate_task_root(snapshot, root):
    if snapshot.get("exists"):
        require(len(snapshot.get("actions", [])) == 1 and
                norm(snapshot["actions"][0].get("WorkingDirectory", "")) == norm(root),
                "AUTOSTART_RELEASE_PATH_MISMATCH")


def ready(info):
    age = info.get("heartbeat_age_seconds")
    return (info.get("running") and isinstance(age, (int, float)) and age < 15 and
            not info.get("failure") and info.get("state") not in
            (None, "STARTING", "STOPPED", "RETRYING"))


def validate_processes(processes, roles, project, words):
    """Reject unleased launchers too; a DB lease alone misses pre-init children.

    A Windows venv redirector may be the parent of the leased Python process.
    Allow only that immediate parent with the identical command arguments.
    Nothing here kills a process or trusts a PID without birth and command checks.
    """
    candidates = {}
    for item in processes:
        args = words(item.get("CommandLine") or "")
        if "-m" not in args or "--project" not in args:
            continue
        mi, pi = args.index("-m"), args.index("--project")
        if mi + 2 >= len(args) or pi + 1 >= len(args):
            continue
        if args[mi + 1] != "compact_product" or norm(args[pi + 1]) != norm(project):
            continue
        action = args[mi + 2]
        if action == "worker":
            role = args[mi + 3] if mi + 3 < len(args) else "invalid"
        else:
            role = {"supervise": "supervisor", "history-worker": "history"}.get(action)
        if role:
            candidates[item["ProcessId"]] = (item, args, role)
    allowed = set()
    for role, info in roles.items():
        if not info.get("running"):
            continue
        pid = info.get("process_pid")
        require(pid in candidates, "LEASED_PROCESS_NOT_IN_INVENTORY:" + role)
        item, args, found_role = candidates[pid]
        require(found_role == role, "PROCESS_ROLE_MISMATCH:" + role)
        created = datetime.fromisoformat(item["CreationDate"].replace("Z", "+00:00")).timestamp()
        require(abs(created - info.get("process_created_epoch_seconds", 0)) < 2,
                "PROCESS_BIRTH_MISMATCH:" + role)
        if role in ("web", "ingest", "analysis") or "--token" in args:
            require("--token" in args and args.index("--token") + 1 < len(args) and
                    args[args.index("--token") + 1] == info.get("command_token"),
                    "PROCESS_TOKEN_MISMATCH:" + role)
        allowed.add(pid)
        parent = candidates.get(item.get("ParentProcessId"))
        if parent and parent[1][1:] == args[1:] and parent[2] == role:
            allowed.add(parent[0]["ProcessId"])
    extras = sorted(set(candidates) - allowed)
    require(not extras, "UNLEASED_COMPACT_PROCESSES:" + ",".join(map(str, extras[:20])))


INVENTORY = r"""
$ErrorActionPreference='Stop'
$p=@(Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" -OperationTimeoutSec 10 |
  Select-Object -First 513 ProcessId,ParentProcessId,CommandLine,@{Name='CreationDate';Expression={$_.CreationDate.ToUniversalTime().ToString('o')}})
if($p.Count -gt 512){throw 'Process inventory budget exceeded'}
$m=Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory -OperationTimeoutSec 10
@{processes=$p;commit_bytes=[long]$m.CommittedBytes;commit_limit_bytes=[long]$m.CommitLimit} | ConvertTo-Json -Depth 5 -Compress
"""


def recover(host, baseline, expected, emit):
    """No automatic rollback/start loop on failure; safe to inspect and rerun."""
    emit("CHECKING_DATABASE_AND_CHECKPOINTS")
    before = host.checkpoint()
    preserved(baseline, before)
    validate_roles(host.roles(), expected)
    emit("DISABLING_OWNED_AUTOSTART")
    host.task("core", "disable")
    host.task("history", "disable")
    if host.roles().get("supervisor", {}).get("running"):
        emit("STOPPING_SUPERVISOR_COOPERATIVELY")
        host.stop_supervisor()
    host.guard(expected)
    for role in ("web", "ingest", "analysis"):
        emit("STARTING_" + role.upper())
        host.guard(expected)
        require(not host.roles().get("supervisor", {}).get("running"),
                "SUPERVISOR_REAPPEARED_DURING_SEQUENTIAL_START")
        if not host.roles().get(role, {}).get("running"):
            host.start(role)
        host.wait(role, expected)
    emit("CHECKING_WEB")
    host.probe()
    emit("STARTING_SUPERVISOR")
    host.guard(expected)
    host.task("core", "register")
    host.wait("supervisor", expected)
    current = host.checkpoint()
    preserved(before, current)
    if current["history"].get("state") != "COMPLETE":
        require(current["history"].get("state") in ("ACTIVE", "SOURCE_COMPLETE"),
                "HISTORY_JOB_NOT_RESUMABLE")
        emit("RESUMING_EXISTING_HISTORY_JOB")
        host.guard(expected)
        host.task("history", "register")
        host.wait("history", expected)
    emit("VERIFYING_RECOVERED_PRODUCT")
    after = host.checkpoint()
    preserved(before, after)
    roles = host.roles()
    validate_roles(roles, expected)
    require(all(ready(roles.get(r, {})) for r in ("web", "ingest", "analysis", "supervisor")),
            "CORE_READINESS_NOT_CONFIRMED")
    if after["history"]["state"] != "COMPLETE":
        require(ready(roles.get("history", {})), "HISTORY_READINESS_NOT_CONFIRMED")
    host.probe()
    return dict(before=before, after=after, roles=roles)


class WindowsHost:
    def __init__(self, project, *, allowed_core_task_roots=()):
        from compact_product.config import load
        self.project = project
        self.cfg, self.source, self.stream = load(project)
        self.supervision_enabled = False
        self.allowed_core_task_roots = tuple(allowed_core_task_roots)

    def database(self):
        from compact_behavior.store import Store
        db = Store(self.source["DATABASE"], schema=self.cfg.source_schema, application="recovery-check")
        try:
            db.conn.execute("SET statement_timeout='10s'")
            db.conn.execute("SET default_transaction_read_only=on")
            require(not db.conn.execute("SELECT pg_is_in_recovery() AS r").fetchone()["r"],
                    "DATABASE_STILL_IN_RECOVERY")
            return db
        except BaseException:
            db.close()
            raise

    def checkpoint(self):
        db = self.database()
        try:
            with db.conn.transaction():
                db.conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                history = db.conn.execute(
                    f"SELECT job_id,from_ns,target_ns,next_ns,state FROM {self.cfg.source_schema}.history_jobs "
                    "WHERE stream_id=%s ORDER BY created_at_ns DESC LIMIT 1", (self.stream,)).fetchone()
                return dict(input_next_ns=db.cursor(self.stream), history=history)
        finally:
            db.close()

    def roles(self):
        # Only the five lease rows; no historical AD or evidence scans.
        from compact_product.runtime import role_key
        db = self.database()
        try:
            result = {}
            for role in ("web", "ingest", "analysis", "supervisor", "history"):
                key = role_key(self.cfg, self.stream, role)
                row = db.conn.execute(f"""SELECT r.*,EXISTS(
                    SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid
                    WHERE l.pid=r.backend_pid AND a.backend_start=r.backend_start
                    AND l.locktype='advisory' AND l.granted AND l.objsubid=1
                    AND l.classid=(%s::bigint >> 32)::oid
                    AND l.objid=(%s::bigint & 4294967295)::oid) AS locked
                    FROM {self.cfg.source_schema}.runtime_roles r WHERE role=%s""", (key, key, role)).fetchone()
                result[role] = dict(**(row["info"] if row else {}),
                                    running=bool(row and row["locked"]),
                                    heartbeat_age_seconds=(time.time_ns()-row["heartbeat_ns"])/1e9 if row else None)
            return result
        finally:
            db.close()

    def guard(self, expected):
        from viewer_performance.financial_screen.host import powershell
        from viewer_performance.financial_screen.reviewed_host import words
        inventory = powershell(INVENTORY)
        require(inventory["commit_limit_bytes"] - inventory["commit_bytes"] >= 4 * 1024**3,
                "WINDOWS_COMMIT_HEADROOM_BELOW_4_GIB")
        roles = self.roles()
        validate_roles(roles, expected)
        validate_processes(inventory["processes"], roles, self.project, words)
        if not self.supervision_enabled:
            value = powershell(r"""
$ErrorActionPreference='Stop'
$t=Get-ScheduledTask -TaskName 'P24-CompactProduct' -ErrorAction SilentlyContinue
@{enabled=($t -and [bool]$t.Settings.Enabled);active=($t -and ([int]$t.State -in @(2,4)))} | ConvertTo-Json -Compress
""")
            require(not value["enabled"] and not value["active"], "SUPERVISOR_TASK_NOT_QUIESCENT")

    def task(self, which, operation):
        from viewer_performance.financial_screen.host import powershell
        from compact_product import __file__ as package_file
        # The old core task helper verifies interpreter/arguments, but not cwd.
        # Add that check before any scheduler mutation in this recovery path.
        snapshot = powershell(r"""
$ErrorActionPreference='Stop'
$t=Get-ScheduledTask -TaskName $env:P24_RECOVERY_TASK -ErrorAction SilentlyContinue
@{exists=[bool]$t;actions=@($t.Actions | Select-Object WorkingDirectory)} | ConvertTo-Json -Depth 4 -Compress
""", {"P24_RECOVERY_TASK": "P24-CompactProduct" if which == "core" else "P24-CompactHistory"})
        current_root = Path(package_file).resolve().parents[1]
        allowed = (current_root, *self.allowed_core_task_roots) if which == 'core' else (current_root,)
        if snapshot.get('exists'):
            require(len(snapshot.get('actions', [])) == 1 and
                    any(norm(snapshot['actions'][0].get('WorkingDirectory', '')) == norm(r) for r in allowed),
                    'AUTOSTART_RELEASE_PATH_MISMATCH')
        if which == "core":
            from compact_product.operations import task
        else:
            from compact_product.history import task
        task(self.project, operation)
        if which == "core" and operation == "register":
            self.supervision_enabled = True

    def stop_supervisor(self):
        from compact_product.runtime import stop
        stop(self.project, roles=("supervisor",), timeout=45)

    def start(self, role):
        from compact_product.runtime import start
        start(self.project, roles=(role,))

    def wait(self, role, expected):
        deadline = time.monotonic() + 60
        while True:
            roles = self.roles()
            validate_roles(roles, expected)
            info = roles.get(role, {})
            if ready(info):
                return
            require(not info.get("running") or not info.get("failure"), "ROLE_FAILURE:" + role)
            if time.monotonic() >= deadline:
                raise TimeoutError("ROLE_NOT_READY:" + role)
            time.sleep(1)

    def probe(self):
        from compact_product.operations import probe
        probe(self.cfg)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--code-root", type=Path, required=True, help="Accepted previous release, not the failed candidate")
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    project, root = args.project.resolve(), args.code_root.resolve()
    output = project / "AnomalyDetection/reports" / ("Compact_Recovery_" + time.strftime("%Y%m%d_%H%M%S") + ".json")
    result = dict(status="COMPACT_RECOVERY_STARTED", code_root=str(root), data_reset=False)

    def emit(stage):
        result["stage"] = stage
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        print(json.dumps(dict(status="COMPACT_RECOVERY_PROGRESS", stage=stage, output=str(output))), flush=True)

    try:
        emit("VERIFYING_PINNED_PREVIOUS_RELEASE")
        require(args.receipt.stat().st_size <= 1024**2, "RECEIPT_SIZE_LIMIT")
        baseline = validate_receipt(json.loads(args.receipt.read_text(encoding="utf-8-sig")), root)
        sys.path.insert(0, str(root))
        from compact_product.version import verify
        from compact_product.operations import require_windows_admin
        from viewer_performance.Diagnose_Three_Modes import controller_lock
        require_windows_admin()
        result["package"] = verify(root)
        require(result["package"]["source_sha256"] == args.expected_source_sha, "PINNED_RELEASE_HASH_MISMATCH")
        with controller_lock(project):
            result.update(recover(WindowsHost(project), baseline, args.expected_source_sha, emit))
        result["status"] = "COMPACT_PREVIOUS_RELEASE_RECOVERED_HISTORY_PRESERVED"
    except BaseException as exc:
        # Never put arbitrary SQL/connection errors or source contents in receipts.
        code = str(exc)
        safe = isinstance(exc, (ValueError, TimeoutError)) and re.fullmatch(r"[A-Z0-9_:,a-z.-]{1,240}", code)
        result.update(status="COMPACT_RECOVERY_NEEDS_ATTENTION", failure=dict(
            type=type(exc).__name__, code=code if safe else None, sqlstate=getattr(exc, "sqlstate", None)))
    output.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    print(json.dumps(dict(status=result["status"], output=str(output), data_reset=False,
                          stage=result.get("stage"), failure=result.get("failure"))), flush=True)
    return 0 if result["status"] == "COMPACT_PREVIOUS_RELEASE_RECOVERED_HISTORY_PRESERVED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
