"""Owner-server trial/cutover with durable rollback and honest capacity receipts."""

from datetime import datetime, timezone
import copy
import http.client
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time
import uuid
import zipfile
from compact_behavior import FIVE
from compact_behavior.__main__ import save, notice
from compact_behavior.store import Store
from compact_behavior.extract import digest
from compact_ad.store import AnalysisStore
from .runtime import status, start, stop, ROLES, role_key
from .config import load
from .health import health
from . import BUILD


def read(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (ValueError, OSError):
        return None


def legacy_receipt(project, explicit=None):
    if explicit:
        value = read(explicit)
        if value and value.get("before", {}).get("restore_plan"):
            return Path(explicit), value
        raise ValueError("legacy_restore_receipt_invalid")
    root = project / "AnomalyDetection/reports"
    paths = sorted(
        (
            p
            for p in root.rglob("*.json")
            if p.stat().st_size < 8 * 1024 * 1024
            and any(
                v in p.name.lower()
                for v in ("release", "trial", "maintenance", "screen")
            )
        ),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for p in paths[:300]:
        value = read(p)
        if value and value.get("before", {}).get("restore_plan"):
            old_project = value.get("project")
            if old_project and Path(old_project).resolve() != project:
                continue
            return p, value
    raise ValueError("legacy_restore_receipt_required_use_legacy_receipt_option")


def probe(config):
    values = []
    for port in config.web_ports:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        began = time.monotonic()
        try:
            conn.request("GET", "/healthz")
            response = conn.getresponse()
            packet = json.loads(response.read(65536))
            if (
                response.status != 200
                or packet.get("service") != "compact_product"
                or packet.get("build") != BUILD
            ):
                raise ValueError("compact_web_origin_mismatch")
            conn.request("GET", "/")
            response = conn.getresponse()
            response.read(2 * 1024 * 1024)
            if response.status != 200:
                raise ValueError("compact_web_home_not_ready")
            values.append(dict(port=port, status=200, seconds=time.monotonic() - began))
        finally:
            conn.close()
    return values


def short_gate_checks(observed):
    """A current analyzed revision and drained work, not just three live PIDs."""
    m = observed.get("measurement", {})
    samples = observed.get("samples", [])
    latest = samples[-1].get("health", {}) if samples else {}
    roles = latest.get("roles", {})
    def below(value, limit):
        return isinstance(value, (int, float)) and 0 <= value < limit
    n = m.get("fresh_windows", 0)
    return dict(
        three_fresh_windows=n >= 3 and m.get("new_source_records", 0) > 0,
        measured_rate_or_no_backlog=(
            m.get("fresh_windows_per_hour", 0) > 12
            or bool(samples) and all(
                sample["health"].get("source_backlog_windows") == 0
                and sample["health"].get("reference_pending_windows") == 0
                for sample in samples
            )
        ),
        fresh_windows_analyzed=n > 0 and m.get("fresh_windows_analyzed") == n,
        latest_revisions_consumed=n > 0 and m.get("latest_revisions_consumed") == n,
        latest_revision_timings_confirmed=n > 0 and m.get("fresh_windows_timing_confirmed") == n,
        source_caught_up=latest.get("source_backlog_windows") == 0,
        reference_warmup_complete=latest.get("reference_pending_windows") == 0,
        no_pending_analysis=latest.get("analysis_pending_windows") == 0
            and latest.get("dirty_keys") == 0 and latest.get("reanalysis_windows") == 0,
        latest_source_analyzed=latest.get("latest_received_end_ns") is not None
            and latest.get("latest_analyzed_end_ns") == latest.get("latest_received_end_ns"),
        no_unconfirmed_timings=latest.get("analysis_timing_unconfirmed_windows") == 0
            and latest.get("latest_analysis_timing_confirmed") is True,
        some_methods_ready=any(
            counts.get("NORMAL", 0) + counts.get("ANOMALY", 0) > 0
            for counts in latest.get("latest_readiness", {}).values()
        ),
        current_analysis_latency=below(latest.get("analysis_latency_p95_seconds"), 300),
        first_analysis_latency=below(latest.get("first_analysis_latency_p95_seconds"), 300),
        web_responsive=below(observed.get("web_p95_seconds"), 5),
        roles_healthy=all(
            roles.get(role, {}).get("running") is True
            and below(roles[role].get("heartbeat_age_seconds"), 15)
            and not roles[role].get("failure")
            and roles[role].get("state") not in ("STARTING", "STOPPED", "RETRYING")
            for role in ROLES
        ),
    )


def assert_legacy_frozen(host, project, state, *, allow_compact=True):
    from compact_behavior.server_trial import verify_frozen

    if not allow_compact:
        verify_frozen(host)
    else:
        ad, _ = host.command("AnomalyDetection/run_anomaly.py", "worker-status")
        viewer, _ = host.command("viewer_performance/Stop_Viewer_Worker.py")
        if (
            ad["process"]["locked"]
            or ad["web"]["locked"]
            or viewer.get("status")
            not in ("NO_VIEWER_LOCK_OWNER_OBSERVED", "VIEWER_BACKEND_STOPPED")
        ):
            raise ValueError("legacy_worker_restarted_during_compact_trial")
    snapshot = host.inventory()
    plan = state["before"]["restore_plan"]
    # Include reviewed idle shells; the current installer ancestors are not
    # workers. Nothing unknown is killed or ignored as a project collector.
    allowed = host.h.own_process_ids(snapshot)
    if allow_compact:
        current = status(project)
        allowed |= {
            v["process_pid"]
            for v in current.values()
            if v.get("running") and v.get("process_pid")
        }
        web_pid = current["web"].get("process_pid")
        if any(int(p["OwningProcess"]) != web_pid for p in snapshot["listeners"]):
            raise ValueError("uncontrolled_frontend_during_trial")
    from viewer_performance.financial_screen.reviewed_host import idle_ids

    allowed |= idle_ids(
        snapshot, plan, {}, wait=lambda seconds: time.sleep(min(seconds, 1))
    )
    processes = {int(p["ProcessId"]): p for p in snapshot["processes"]}
    if allow_compact:
        from viewer_performance.financial_screen.reviewed_host import words, norm

        for role in ROLES:
            child = processes.get(current[role].get("process_pid"))
            parent = (
                processes.get(int(child.get("ParentProcessId", 0))) if child else None
            )
            if parent and (parent.get("ExecutablePath") or "").lower().endswith(
                ("python.exe", "pythonw.exe")
            ):
                if [norm(x) for x in words(parent.get("CommandLine") or "")[1:]] == [
                    norm(x) for x in words(child.get("CommandLine") or "")[1:]
                ]:
                    allowed.add(int(parent["ProcessId"]))
    # Validate the actual ancestor chain of this controller, including venv
    # redirectors and its waiting PowerShell installer. Never all PowerShells.
    current = processes.get(os.getpid())
    for _ in range(6):
        if not current:
            break
        allowed.add(int(current["ProcessId"]))
        parent = processes.get(int(current.get("ParentProcessId", 0)))
        if not parent or not (parent.get("ExecutablePath") or "").lower().endswith(
            ("python.exe", "pythonw.exe", "powershell.exe", "pwsh.exe")
        ):
            break
        current = parent
    residual = [
        p
        for p in host.h.project_processes(snapshot, project)
        if int(p["ProcessId"]) not in allowed
    ]
    tasks = [t for t in snapshot["tasks"] if t["Enabled"] or t["State"] == "Running"]
    if (
        residual
        or tasks
        or any(
            s["State"] == "Running" or s["StartMode"] == "Auto"
            for s in snapshot["services"]
        )
    ):
        raise ValueError("other_project_process_or_autostart_active")
    with host.reader() as db:
        sessions = db.execute(
            """SELECT pid,application_name,state FROM pg_stat_activity WHERE datname=current_database()
            AND pid<>pg_backend_pid() AND backend_type='client backend' AND state<>'idle'
            AND application_name NOT LIKE 'P24.Compact.%%' AND application_name NOT LIKE 'P24.ScopeScreen.%%'"""
        ).fetchall()
        if sessions:
            raise ValueError("uncontrolled_project_database_activity")


def observe(project, seconds, folder, *, check_exclusive=None):
    if not 10 <= seconds <= 86400:
        raise ValueError("observation_seconds_10_to_86400")
    cfg, source, stream = load(project)
    db = Store(source["DATABASE"], schema=cfg.source_schema, application="observation")
    began = time.monotonic()
    begin_ns = time.time_ns()
    base = status(project)
    from .version import verify

    expected_package = verify()["source_sha256"]
    samples = []
    web_times = []
    backend_ids = {}
    active_ids = {
        r: (
            base[r].get("command_token"),
            base[r].get("process_pid"),
            base[r].get("package", {}).get("source_sha256"),
        )
        for r in ROLES
    }
    if not all(
        base[r]["running"]
        and base[r].get("package", {}).get("source_sha256") == expected_package
        for r in ROLES
    ):
        db.close()
        raise ValueError("all_three_compact_roles_required")

    def report(final=False):
        elapsed = time.monotonic() - began
        s = cfg.source_schema
        a = cfg.ad_schema
        commits = db.conn.execute(
            f"""SELECT w.start_ns,w.first_published_ns,w.source_records,r.first_analyzed_ns,
            r.timing_confirmed_revision=r.revision AS revision_timing_confirmed,
            (r.source_published_ns=w.published_at_ns AND
             NOT EXISTS(SELECT 1 FROM {s}.dirty_windows d WHERE d.stream_id=w.stream_id
                AND d.start_ns=w.start_ns AND d.session_id='@all' AND d.processed_version<d.version) AND
             NOT EXISTS(SELECT 1 FROM {a}.reanalysis j WHERE j.stream_id=w.stream_id
                AND j.start_ns=w.start_ns AND j.processed_version<j.version)) AS latest_revision_consumed
            FROM {s}.windows w LEFT JOIN {a}.window_results r USING(stream_id,start_ns)
            WHERE w.stream_id=%s AND w.first_published_ns>=%s ORDER BY w.start_ns""",
            (stream, begin_ns),
        ).fetchall()
        stats = dict(
            seconds=elapsed,
            fresh_windows=len(commits),
            new_source_records=sum(r["source_records"] for r in commits),
            fresh_windows_per_hour=len(commits) * 3600 / max(1, elapsed),
            fresh_windows_analyzed=sum(
                r["first_analyzed_ns"] is not None for r in commits
            ),
            fresh_windows_timing_confirmed=sum(
                bool(r["first_analyzed_ns"]) and bool(r["revision_timing_confirmed"]) for r in commits
            ),
            latest_revisions_consumed=sum(
                bool(r["latest_revision_consumed"]) for r in commits
            ),
            forward_fresh_windows=sum(
                r["start_ns"] >= begin_ns // FIVE * FIVE - FIVE for r in commits
            ),
            history_fresh_windows=sum(
                r["start_ns"] < begin_ns // FIVE * FIVE - FIVE for r in commits
            ),
        )
        value = dict(
            status="COMPACT_OBSERVATION_COMPLETE" if final else "COMPACT_OBSERVING",
            build=BUILD,
            role_identities=active_ids,
            samples=samples,
            measurement=stats,
            web_p95_seconds=(
                sorted(web_times)[
                    max(0, __import__("math").ceil(len(web_times) * 0.95) - 1)
                ]
                if web_times
                else None
            ),
            counting="FRESH_DURABLY_PUBLISHED_WINDOWS_ONLY_NO_SKIP_RECHECK_OR_STAGED_CREDIT",
            throughput_kind="OBSERVED_WORKLOAD_NOT_SATURATED_CAPACITY_UNLESS_SOURCE_BACKLOG_PRESENT",
            server_capacity_acceptance=(
                "NOT_ASSIGNED_SHORT_TRIAL" if elapsed < 28800 else "REVIEW_REQUIRED"
            ),
            labeled_accuracy="NOT_EVALUATED",
        )
        save(folder / "observation.json", value)
        return value

    try:
        while True:
            current = status(project)
            if any(
                not current[r]["running"]
                or (
                    current[r].get("command_token"),
                    current[r].get("process_pid"),
                    current[r].get("package", {}).get("source_sha256"),
                )
                != active_ids[r]
                for r in ROLES
            ):
                raise ValueError("observation_role_identity_changed")
            if check_exclusive:
                check_exclusive()
            backend_stats = []
            for role in ("ingest", "analysis"):
                identity = (
                    current[role].get("writer_backend_pid"),
                    current[role].get("writer_backend_start"),
                )
                if identity[0] is None:
                    continue
                if role in backend_ids and backend_ids[role] != identity:
                    raise ValueError("observation_writer_connection_changed")
                backend_ids[role] = identity
                backend = db.conn.execute(
                    "SELECT pid,backend_start FROM pg_stat_activity WHERE pid=%s",
                    (identity[0],),
                ).fetchone()
                if not backend or str(backend["backend_start"]) != identity[1]:
                    raise ValueError("observation_writer_connection_not_verified")
                if db.conn.info.server_version >= 180000:
                    backend_stats.append(
                        dict(
                            role=role,
                            pid=identity[0],
                            backend_start=identity[1],
                            io=[
                                dict(v)
                                for v in db.conn.execute(
                                    "SELECT * FROM pg_stat_get_backend_io(%s)",
                                    (identity[0],),
                                )
                            ],
                            wal=[
                                dict(v)
                                for v in db.conn.execute(
                                    "SELECT * FROM pg_stat_get_backend_wal(%s)",
                                    (identity[0],),
                                )
                            ],
                        )
                    )
            h = health(db.conn, cfg, stream)
            web = probe(cfg)
            web_times.extend(w["seconds"] for w in web)
            sample = dict(
                writer_backend_cumulative_stats=json.loads(
                    json.dumps(backend_stats, default=str)
                ),
                backend_counter_limits="PER_IDENTIFIED_BACKEND_NOT_CLUSTER_TOTALS; STATS_MAY_LAG; OS_CACHE_NOT_DISK_IO",
                elapsed_seconds=round(time.monotonic() - began, 2),
                health=h,
                roles={
                    r: dict(
                        state=current[r].get("state"),
                        heartbeat_age_seconds=current[r].get("heartbeat_age_seconds"),
                        process_peak_rss_bytes=current[r].get("process_peak_rss_bytes"),
                        failure=current[r].get("failure"),
                    )
                    for r in ROLES
                },
            )
            if os.name == "nt":
                from viewer_performance.financial_screen.resources import process_usage

                sample["process_resources"] = {
                    r: process_usage(current[r]["process_pid"]) for r in ROLES
                }
            samples.append(sample)
            if len(samples) > 3000:
                samples.pop(0)
            value = report()
            notice(
                "COMPACT_PRODUCT_OBSERVING",
                elapsed_seconds=round(time.monotonic() - began),
                fresh_windows=value["measurement"]["fresh_windows"],
                dirty_keys=h["dirty_keys"],
                source_backlog=h["source_backlog_windows"],
            )
            remaining = seconds - (time.monotonic() - began)
            if remaining <= 0:
                m = value["measurement"]
                drained = (
                    m["fresh_windows"]
                    == m["fresh_windows_analyzed"]
                    == m["latest_revisions_consumed"]
                )
                if drained or time.monotonic() - began >= seconds + 30:
                    break
                time.sleep(1)
            else:
                time.sleep(min(15, remaining))
        return report(final=True)
    except BaseException as exc:
        value = report(final=True)
        value.update(
            status="COMPACT_OBSERVATION_INVALID",
            failure=dict(
                type=type(exc).__name__,
                code=str(exc) if isinstance(exc, ValueError) else None,
            ),
        )
        save(folder / "observation.json", value)
        raise
    finally:
        db.close()


def collect_role_diagnostics(project, folder):
    """Only known role files; never local settings, keys or credentials."""
    source = Path(project) / "compact_runtime"
    destination = Path(folder) / "compact_runtime"
    failures = []
    names = [role + suffix for role in (*ROLES, "supervisor") for suffix in ("-launcher.log", ".log", ".json")]
    names.append("startup-failure.local.json")
    for name in names:
        path = source / name
        try:
            if not path.is_file():
                continue
            with path.open("rb") as file:
                size = file.seek(0, 2)
                file.seek(max(0, size - 131072))
                data = file.read(131072)
            destination.mkdir(parents=True, exist_ok=True)
            (destination / name).write_bytes(data)
        except OSError as exc:
            failures.append(dict(file=name, type=type(exc).__name__))
    return failures


def bundle(folder):
    out = folder.with_suffix(".zip")
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for p in folder.rglob("*"):
            if p.is_file():
                z.write(p, p.relative_to(folder).as_posix())
    return str(out)


def task(project, operation):
    from viewer_performance.financial_screen.host import powershell

    args = subprocess.list2cmdline(
        [
            "-X",
            "utf8",
            "-B",
            "-m",
            "compact_product",
            "supervise",
            "--project",
            str(project),
        ]
    )
    environment = dict(
        P24_COMPACT_PYTHON=sys.executable,
        P24_COMPACT_ROOT=str(project),
        P24_COMPACT_CODE_ROOT=str(Path(__file__).resolve().parents[1]),
        P24_COMPACT_ARGS=args,
    )
    script = r"""
$ErrorActionPreference='Stop'
$name='P24-CompactProduct'
$old=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
if($old){
  $actions=@($old.Actions)
  if($actions.Count -ne 1 -or $actions[0].Execute -ne $env:P24_COMPACT_PYTHON -or $actions[0].Arguments -ne $env:P24_COMPACT_ARGS){throw 'Compact task identity mismatch'}
}
"""
    if operation == "register":
        script += r"""
$action=New-ScheduledTaskAction -Execute $env:P24_COMPACT_PYTHON -Argument $env:P24_COMPACT_ARGS -WorkingDirectory $env:P24_COMPACT_CODE_ROOT
$trigger=New-ScheduledTaskTrigger -AtStartup
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $name
@{status='COMPACT_AUTOSTART_REGISTERED'} | ConvertTo-Json -Compress
"""
    elif operation == "disable":
        script += r"""
if($old){Disable-ScheduledTask -TaskName $name | Out-Null}
@{status='COMPACT_AUTOSTART_DISABLED'} | ConvertTo-Json -Compress
"""
    elif operation == "stop":
        script += r"""
if($old -and $old.State -eq 'Running'){Stop-ScheduledTask -TaskName $name}
@{status='COMPACT_AUTOSTART_STOPPED'} | ConvertTo-Json -Compress
"""
    return powershell(script, environment)


def wait_for_supervisor(project, *, timeout=45):
    deadline = time.monotonic() + timeout
    from .version import verify
    package = verify()["source_sha256"]
    while True:
        supervisor = status(project).get("supervisor", {})
        if (supervisor.get("running") and supervisor.get("state") == "SUPERVISING"
            and supervisor.get("package", {}).get("source_sha256") == package
            and isinstance(supervisor.get("heartbeat_age_seconds"), (int, float))
            and supervisor["heartbeat_age_seconds"] < 15):
            return supervisor
        if time.monotonic() >= deadline:
            raise TimeoutError("COMPACT_AUTOSTART_SUPERVISOR_NOT_CONFIRMED")
        time.sleep(.5)


def require_windows_admin():
    if os.name != "nt" or not __import__("ctypes").windll.shell32.IsUserAnAdmin():
        raise ValueError("WINDOWS_ADMINISTRATOR_REQUIRED_FOR_CUTOVER")


def execute(project, args):
    project = Path(project).resolve()
    if args.action == "observe":
        folder = (
            project
            / "AnomalyDetection/reports"
            / (
                "Compact_Observation_"
                + datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_")
                + uuid.uuid4().hex[:8]
            )
        )
        folder.mkdir(parents=True)
        try:
            value = observe(project, args.seconds, folder)
        except Exception:
            value = read(folder / "observation.json") or dict(
                status="COMPACT_OBSERVATION_INVALID", measurement={}
            )
        return dict(
            status=value["status"],
            output=bundle(folder),
            measurement=value["measurement"],
        )
    require_windows_admin()
    from viewer_performance.Diagnose_Three_Modes import ProductionHost, controller_lock
    from viewer_performance.Behavior_Release import restore
    from compact_behavior.server_trial import freeze

    cfg, source, stream = load(project)
    with controller_lock(project):
        if args.action == "rollback":
            if not args.receipt:
                pointer = (
                    read(project / "compact_runtime/latest-cutover.local.json") or {}
                )
                if not pointer.get("receipt"):
                    raise ValueError("rollback_receipt_required")
                args.receipt = Path(pointer["receipt"])
            state = read(args.receipt)
            if not state or Path(state["project"]).resolve() != project:
                raise ValueError("rollback_project_mismatch")
            if not state.get("stopping_started"):
                raise ValueError(
                    "receipt_has_no_started_cutover_existing_roles_preserved"
                )
            task(project, "disable")
            stop(project)
            task(project, "stop")
            stop(project)
            restore(project, args.receipt, state)
            return dict(
                status="COMPACT_ROLLED_BACK_PREVIOUS_ROLES_RESTORED",
                receipt=str(args.receipt),
                compact_data_preserved=True,
            )
        if not 60 <= args.seconds <= 86400:
            raise ValueError("trial_seconds_60_to_86400")
        old_path, old = legacy_receipt(project, args.legacy_receipt)
        # First source check runs with all previous roles still available.
        from compact_behavior.probe_elastic import probe as source_probe

        closed = (time.time_ns() - cfg.source_lag_seconds * 10**9) // FIVE * FIVE
        preflight = source_probe(source["ELASTICSEARCH"], closed - FIVE)
        if preflight.get("status") != "FIRST_SEARCH_PAGE_VALID":
            raise ValueError("compact_source_preflight_failed_no_services_stopped")
        from .version import verify

        package = verify()
        folder = (
            project
            / "AnomalyDetection/reports"
            / (
                "Compact_Product_"
                + datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_")
                + uuid.uuid4().hex[:8]
            )
        )
        folder.mkdir(parents=True)
        receipt = folder / "cutover.json"
        state = dict(
            project=str(project),
            code_root=str(Path(__file__).resolve().parents[1]),
            build=BUILD,
            package=package,
            legacy_receipt=str(old_path),
            before=copy.deepcopy(old["before"]),
            disabled_tasks=[],
            attempted_roles=[],
            restore_failures=[],
            stopping_started=False,
            status="PREPARING",
        )
        save(receipt, state)
        save(folder / "source-preflight.json", preflight)
        notice("COMPACT_CUTOVER_PREPARED", receipt=str(receipt), action=args.action)
        keep = False
        host = ProductionHost(project)
        try:
            existing = status(project)
            if any(v["running"] for v in existing.values()):
                raise ValueError("stop_existing_compact_roles_before_trial")
            save(
                project / "compact_runtime/latest-cutover.local.json",
                dict(receipt=str(receipt)),
            )
            freeze(project, state, receipt, host)
            assert_legacy_frozen(host, project, state, allow_compact=False)
            db = AnalysisStore(
                source["DATABASE"], schema=cfg.source_schema, ad_schema=cfg.ad_schema
            )
            try:
                db.init()
            finally:
                db.close()
            state["compact_started"] = True
            save(receipt, state)
            start(project)
            deadline = time.monotonic() + 45
            while True:
                try:
                    probe(cfg)
                    break
                except Exception:
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(1)
            observed = observe(
                project,
                args.seconds,
                folder,
                check_exclusive=lambda: assert_legacy_frozen(host, project, state),
            )
            with host.reader() as control:
                if host.h.cursors(control) != state["frozen_cursors"]:
                    raise ValueError("legacy_cursors_changed_during_compact_trial")
            state["observation"] = observed["measurement"]
            state["status"] = "COMPACT_TRIAL_MEASURED"
            state["short_gate_checks"] = short_gate_checks(observed)
            state["short_operational_gate"] = all(state["short_gate_checks"].values())
            if args.action == "install":
                if not state["short_operational_gate"]:
                    raise ValueError(
                        "compact_short_gate_not_passed_restoring_previous_roles"
                    )
                # Installation is a monitored candidate, not eight-hour or
                # real labelled accuracy certification.
                state["task_registration_attempted"] = True
                save(receipt, state)
                state["autostart"] = task(project, "register")
                state["supervisor"] = wait_for_supervisor(project)
                state["installed_web"] = probe(cfg)
                keep = True
                state["status"] = "COMPACT_CANDIDATE_INSTALLED_LONG_RUN_PENDING"
        except BaseException as exc:
            state["status"] = (
                "COMPACT_INSTALL_ROLLED_BACK"
                if args.action == "install"
                else "COMPACT_TRIAL_INCOMPLETE"
            )
            state["failure"] = dict(
                type=type(exc).__name__,
                code=str(exc) if isinstance(exc, (ValueError, TimeoutError)) else None,
                sqlstate=getattr(exc, "sqlstate", None),
                details=getattr(exc, "details", None),
            )
        finally:
            if state.get("compact_started"):
                state["startup_diagnostic_failures"] = collect_role_diagnostics(project, folder)
            if not keep and state.get("task_registration_attempted"):
                try:
                    task(project, "disable")
                except Exception as exc:
                    state["compact_stop_failure"] = (
                        "AUTOSTART_DISABLE_FAILED:" + type(exc).__name__
                    )
            if (
                not keep
                and state.get("compact_started")
                and not state.get("compact_stop_failure")
            ):
                try:
                    stop(project)
                    if state.get("task_registration_attempted"):
                        task(project, "stop")
                        stop(project)
                except Exception as exc:
                    state["compact_stop_failure"] = type(exc).__name__
            if (
                not keep
                and state.get("stopping_started")
                and not state.get("compact_stop_failure")
            ):
                outcome = state["status"]
                try:
                    restore(project, receipt, state)
                except BaseException as exc:
                    state["restore_failure"] = dict(
                        type=type(exc).__name__,
                        code=str(exc) if isinstance(exc, ValueError) else None,
                    )
                if state.get("restore_failure") or state.get("restore_failures"):
                    state["status"] = "COMPACT_RESTORE_INCOMPLETE"
                elif args.action == "trial" and not state.get("failure"):
                    state["status"] = "COMPACT_TRIAL_COMPLETE_PREVIOUS_ROLES_RESTORED"
                else:
                    state["status"] = outcome
            if state.get("compact_stop_failure"):
                state["status"] = "COMPACT_RESTORE_INCOMPLETE"
            save(receipt, state)
        return dict(
            status=state["status"],
            output=bundle(folder),
            receipt=str(receipt),
            short_operational_gate=state.get("short_operational_gate"),
            compact_data_preserved=True,
            legacy_data_reset=False,
            failure=state.get("failure"),
            restore_failure=state.get("restore_failure"),
        )
