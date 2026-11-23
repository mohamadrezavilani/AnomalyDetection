"""Singleton roles, durable identity, cooperative stop and bounded retries."""

from contextlib import contextmanager
from dataclasses import asdict
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import uuid
from compact_behavior import FIVE
from compact_behavior.store import Store, stream_lock
from compact_behavior.__main__ import save, process_info, measure_window
from compact_behavior.source import ElasticWindow
from compact_ad.store import AnalysisStore, ChangedDuringAnalysis
from .config import load
from . import BUILD

ROLES = ("ingest", "analysis", "web")
_children = {}


def paths(project, role):
    root = Path(project) / "compact_runtime"
    root.mkdir(parents=True, exist_ok=True)
    return root, root / (role + ".json"), root / (role + ".stop")


def role_key(config, stream, role):
    return stream_lock(["compact-role", config.source_schema, stream, role])


def runtime_init(db, s):
    with db.transaction():
        # IF NOT EXISTS does not serialize concurrent pg_type/catalog inserts.
        # Use the same schema lock as Store.init before any runtime DDL.
        db.execute("SELECT pg_advisory_xact_lock(%s)", (stream_lock("schema:" + s),))
        db.execute(
            f"""CREATE TABLE IF NOT EXISTS {s}.runtime_roles(role TEXT PRIMARY KEY,token TEXT NOT NULL,
            backend_pid INTEGER NOT NULL,backend_start TIMESTAMPTZ NOT NULL,heartbeat_ns BIGINT NOT NULL,info JSONB NOT NULL)"""
        )
        db.execute(
            f"""CREATE TABLE IF NOT EXISTS {s}.reference_cursor(stream_id TEXT PRIMARY KEY,next_ns BIGINT NOT NULL,
            target_ns BIGINT NOT NULL,overlap_next_ns BIGINT,overlap_target_ns BIGINT,last_recheck_ns BIGINT NOT NULL DEFAULT 0)"""
        )

        from .error_catalog import ensure_catalog

        ensure_catalog(db, s)
        from . import provider_contracts
        provider_contracts.initialize(db, s)
        from .performance import initialize
        initialize(db, s)


class Lease:
    def __init__(self, project, role, token):
        from psycopg.types.json import Jsonb

        self.project = Path(project)
        self.role = role
        self.token = token
        self.config, source, self.stream = load(project)
        self.db = Store(
            source["DATABASE"],
            schema=self.config.source_schema,
            application="lease." + role,
        )
        # A scheduled supervisor attaches after the core has installed its
        # lease table. Repeating source ALTERs here competes with live ingest.
        attached_supervisor = role == "supervisor" and self.db.conn.execute(
            "SELECT to_regclass(%s) IS NOT NULL AS installed",
            (self.config.source_schema + ".runtime_roles",),
        ).fetchone()["installed"]
        if role == "history":
            from .history_schema import validate_installed
            try:
                validate_installed(self.db, self.stream, history_required=True)
            except Exception:
                self.db.close()
                raise
        elif not attached_supervisor:
            self.db.init()
        streams = self.db.conn.execute(
            f"SELECT stream_id FROM {self.config.source_schema}.streams LIMIT 2"
        ).fetchall()
        if any(v["stream_id"] != self.stream for v in streams):
            self.db.close()
            raise ValueError("new_source_requires_new_compact_namespace")
        self.db.conn.execute("SET statement_timeout=5000")
        if role != "history" and not attached_supervisor:
            runtime_init(self.db.conn, self.config.source_schema)
        ok = self.db.conn.execute(
            "SELECT pg_try_advisory_lock(%s) AS ok",
            (role_key(self.config, self.stream, role),),
        ).fetchone()["ok"]
        if not ok:
            self.db.close()
            raise ValueError("COMPACT_ROLE_ALREADY_RUNNING:" + role)
        _, self.report, self.stop_file = paths(project, role)
        self.stop_file.unlink(missing_ok=True)
        self.stop = threading.Event()
        self.done = threading.Event()
        self.fatal = None
        self.lock = threading.Lock()
        from .version import verify

        self.info = dict(
            role=role,
            command_token=token,
            state="STARTING",
            build=BUILD,
            package=verify(),
            **process_info(),
        )
        self.package_stamp = (
            (Path(__file__).with_name("MANIFEST.json")).stat().st_mtime_ns
        )
        self.backend = self.db.conn.execute(
            "SELECT pid,backend_start FROM pg_stat_activity WHERE pid=pg_backend_pid()"
        ).fetchone()
        self.db.conn.execute(
            f"""INSERT INTO {self.config.source_schema}.runtime_roles VALUES(%s,%s,%s,%s,%s,%s)
            ON CONFLICT(role) DO UPDATE SET token=excluded.token,backend_pid=excluded.backend_pid,
            backend_start=excluded.backend_start,heartbeat_ns=excluded.heartbeat_ns,info=excluded.info""",
            (
                role,
                token,
                self.backend["pid"],
                self.backend["backend_start"],
                time.time_ns(),
                Jsonb(self.info),
            ),
        )
        self.thread = threading.Thread(target=self.monitor, daemon=True)
        self.thread.start()

    def update(self, **values):
        with self.lock:
            self.info.update(values)

    def monitor(self):
        from psycopg.types.json import Jsonb

        while not self.done.is_set():
            try:
                if (
                    self.stop_file.exists()
                    and json.loads(self.stop_file.read_text(encoding="utf-8")).get(
                        "token"
                    )
                    == self.token
                ):
                    self.stop.set()
                with self.lock:
                    info = dict(
                        self.info,
                        heartbeat_ns=time.time_ns(),
                        **{
                            k: v
                            for k, v in process_info().items()
                            if k != "process_pid"
                        },
                    )
                save(self.report, info)
                n = self.db.conn.execute(
                    f"""UPDATE {self.config.source_schema}.runtime_roles SET heartbeat_ns=%s,info=%s
                    WHERE role=%s AND token=%s""",
                    (info["heartbeat_ns"], Jsonb(info), self.role, self.token),
                ).rowcount
                if n != 1:
                    raise ValueError("runtime_identity_replaced")
            except Exception as exc:
                self.fatal = type(exc).__name__
                self.stop.set()
                break
            self.done.wait(2)

    def check(self):
        if (
            Path(__file__).with_name("MANIFEST.json").stat().st_mtime_ns
            != self.package_stamp
        ):
            raise InterruptedError("compact_package_changed_restart_required")
        if self.fatal:
            raise RuntimeError("compact_role_lease_lost")
        if self.stop.is_set():
            raise InterruptedError("compact_stop_requested")

    def close(self):
        self.done.set()
        self.thread.join(10)
        with self.lock:
            self.info.update(state="STOPPED", heartbeat_ns=time.time_ns())
        save(self.report, self.info)
        self.db.close()


def ingest(lease, source, logger):
    cfg = lease.config
    s = cfg.source_schema
    stream = lease.stream
    db = Store(source["DATABASE"], schema=s)
    db.init()
    retry = 0
    try:
        while not lease.stop.is_set():
            try:
                lease.check()
                closed = (
                    (time.time_ns() - cfg.source_lag_seconds * 10**9) // FIVE * FIVE
                )
                cursor = db.cursor(stream)
                control = db.conn.execute(
                    f"SELECT * FROM {s}.reference_cursor WHERE stream_id=%s", (stream,)
                ).fetchone()
                if cursor is not None and control is None:
                    first = db.conn.execute(
                        f"SELECT start_ns FROM {s}.windows WHERE stream_id=%s ORDER BY start_ns LIMIT 1",
                        (stream,),
                    ).fetchone()["start_ns"]
                    db.conn.execute(
                        f"INSERT INTO {s}.reference_cursor(stream_id,next_ns,target_ns,last_recheck_ns) VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                        (
                            stream,
                            first - (cfg.reference_windows - 1) * FIVE,
                            first,
                            time.time_ns(),
                        ),
                    )
                    continue
                if cursor is None:
                    begin = closed - FIVE
                    mode = "forward"
                elif cursor < closed:
                    begin = cursor
                    mode = "forward"
                elif control and control["next_ns"] < control["target_ns"]:
                    begin = control["next_ns"]
                    mode = "reference"
                    if begin < cursor - 288 * FIVE:
                        db.conn.execute(
                            f"UPDATE {s}.reference_cursor SET next_ns=%s WHERE stream_id=%s",
                            (cursor - 288 * FIVE, stream),
                        )
                        continue
                elif (
                    control
                    and control["overlap_next_ns"] is not None
                    and control["overlap_next_ns"] < control["overlap_target_ns"]
                ):
                    begin = control["overlap_next_ns"]
                    mode = "recheck"
                elif (
                    cfg.overlap_windows
                    and control
                    and time.time_ns() - control["last_recheck_ns"]
                    >= cfg.recheck_seconds * 10**9
                ):
                    floor = max(
                        cursor - cfg.overlap_windows * FIVE,
                        db.conn.execute(
                            f"SELECT start_ns FROM {s}.streams WHERE stream_id=%s",
                            (stream,),
                        ).fetchone()["start_ns"],
                    )
                    db.conn.execute(
                        f"""UPDATE {s}.reference_cursor SET overlap_next_ns=%s,overlap_target_ns=%s,last_recheck_ns=%s
                        WHERE stream_id=%s""",
                        (floor, cursor, time.time_ns(), stream),
                    )
                    continue
                else:
                    lease.update(state="WAITING_FOR_CLOSED_WINDOW")
                    lease.stop.wait(cfg.idle_seconds)
                    continue
                lease.update(
                    state="RECEIVING",
                    active_window_start_ns=begin,
                    active_window_end_ns=begin + FIVE,
                    mode=mode,
                )
                src = ElasticWindow(
                    source["ELASTICSEARCH"],
                    begin,
                    begin + FIVE,
                    page_size=source["ELASTICSEARCH"].get("compact_page_size", 500),
                    budget=cfg.ingest_budget_seconds,
                )

                # Reuse validated streaming source; history publication has its
                # own explicit bounded permit and never rewinds the live cursor.
                class Publisher:
                    limits = db.limits

                    def publish(self, *args, **kw):
                        lease.check()
                        return db.publish(
                            *args, allow_history=mode == "reference", **kw
                        )

                backend = db.conn.execute(
                    "SELECT pid,backend_start FROM pg_stat_activity WHERE pid=pg_backend_pid()"
                ).fetchone()
                lease.update(
                    writer_backend_pid=backend["pid"],
                    writer_backend_start=str(backend["backend_start"]),
                )
                result = measure_window(
                    Publisher(), stream, src, progress=lambda **kw: lease.check()
                )
                try:
                    from .performance import record
                    record(db.conn, s, stream, 'ingest', result, mode)
                except Exception:
                    logger.warning('performance_sample_not_recorded')
                if cursor is None:
                    db.conn.execute(
                        f"""INSERT INTO {s}.reference_cursor(stream_id,next_ns,target_ns,last_recheck_ns)
                        VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                        (
                            stream,
                            begin - (cfg.reference_windows - 1) * FIVE,
                            begin,
                            time.time_ns(),
                        ),
                    )
                elif mode == "reference":
                    db.conn.execute(
                        f"UPDATE {s}.reference_cursor SET next_ns=%s WHERE stream_id=%s",
                        (begin + FIVE, stream),
                    )
                elif mode == "recheck":
                    db.conn.execute(
                        f"UPDATE {s}.reference_cursor SET overlap_next_ns=%s WHERE stream_id=%s",
                        (begin + FIVE, stream),
                    )
                lease.update(
                    state="PUBLISHED",
                    last_publication=result,
                    last_success_ns=time.time_ns(),
                    failure=None,
                )
                logger.info(json.dumps(dict(event="PUBLICATION", mode=mode, **result)))
                retry = 0
            except InterruptedError:
                break
            except Exception as exc:
                retry += 1
                lease.update(
                    state="RETRYING",
                    failure=dict(
                        type=type(exc).__name__,
                        code=str(exc) if isinstance(exc, ValueError) else None,
                        sqlstate=getattr(exc, "sqlstate", None),
                        details=getattr(exc, "details", None),
                    ),
                    retry=retry,
                )
                logger.error(
                    "ingest retry type=%s sqlstate=%s code=%s",
                    type(exc).__name__,
                    getattr(exc, "sqlstate", None),
                    str(exc) if isinstance(exc, ValueError) else None,
                )
                if db.conn.closed:
                    db.close()
                    db = Store(source["DATABASE"], schema=s)
                    db.init()
                lease.stop.wait(min(30, 2 ** min(retry, 5)))
    finally:
        db.close()


def analyze(lease, source, logger):
    cfg = lease.config
    db = AnalysisStore(
        source["DATABASE"], schema=cfg.source_schema, ad_schema=cfg.ad_schema
    )
    db.init()
    retry = 0
    try:
        while not lease.stop.is_set():
            try:
                lease.check()
                lease.update(state="ANALYZING")
                backend = db.conn.execute(
                    "SELECT pid,backend_start FROM pg_stat_activity WHERE pid=pg_backend_pid()"
                ).fetchone()
                lease.update(
                    writer_backend_pid=backend["pid"],
                    writer_backend_start=str(backend["backend_start"]),
                )
                result = db.step(lease.stream)
                if result['status'] == 'ANALYSIS_COMMITTED':
                    try:
                        from .performance import record
                        record(db.conn, cfg.source_schema, lease.stream, 'analysis', result, 'analysis')
                    except Exception:
                        logger.warning('performance_sample_not_recorded')
                elif result['status'] in ('LONGITUDINAL_WINDOW_PREPARED','LONGITUDINAL_DAY_PREPARED','LONGITUDINAL_PERIOD_REVIEWED'):
                    try:
                        from .performance import record
                        record(db.conn,cfg.source_schema,lease.stream,'longitudinal',result,result['status'])
                    except Exception:
                        logger.warning('longitudinal_performance_sample_not_recorded')
                lease.update(
                    state=result["status"],
                    last_analysis=result,
                    last_success_ns=time.time_ns(),
                    failure=None,
                )
                if result["status"] == "ANALYSIS_IDLE":
                    lease.stop.wait(cfg.idle_seconds)
                else:
                    logger.info(json.dumps(dict(event="ANALYSIS", **result)))
                retry = 0
            except InterruptedError:
                break
            except ChangedDuringAnalysis:
                lease.update(state="SOURCE_REVISION_RETRY")
                lease.stop.wait(0.1)
            except Exception as exc:
                retry += 1
                lease.update(
                    state="RETRYING",
                    failure=dict(
                        type=type(exc).__name__,
                        code=str(exc) if isinstance(exc, ValueError) else None,
                        sqlstate=getattr(exc, "sqlstate", None),
                    ),
                    retry=retry,
                )
                logger.error(
                    "analysis retry type=%s sqlstate=%s",
                    type(exc).__name__,
                    getattr(exc, "sqlstate", None),
                )
                if db.conn.closed:
                    db.close()
                    db = AnalysisStore(
                        source["DATABASE"],
                        schema=cfg.source_schema,
                        ad_schema=cfg.ad_schema,
                    )
                    db.init()
                lease.stop.wait(min(30, 2 ** min(retry, 5)))
    finally:
        db.close()


def worker(project, role, token):
    root, report, stop = paths(project, role)
    logger = logging.getLogger("compact." + role)
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(
        root / (role + ".log"),
        maxBytes=8 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    logger.addHandler(handler)
    lease = None
    try:
        lease = Lease(project, role, token)
        if threading.current_thread() is threading.main_thread():
            for sig in (signal.SIGINT, signal.SIGTERM):
                signal.signal(sig, lambda *args: lease.stop.set())
        _, source, _ = load(project)
        if role == "ingest":
            ingest(lease, source, logger)
        elif role == "analysis":
            analyze(lease, source, logger)
        else:
            from .web import serve

            serve(lease, source)
        return 1 if lease.fatal else 0
    except BaseException:
        logger.exception("compact role initialization or execution failed")
        raise
    finally:
        if lease:
            lease.close()
        handler.close()
        logger.removeHandler(handler)


def status(project):
    cfg, source, stream = load(project)
    db = Store(source["DATABASE"], schema=cfg.source_schema, application="control")
    try:
        present = db.conn.execute(
            "SELECT to_regclass(%s) AS name", (cfg.source_schema + ".runtime_roles",)
        ).fetchone()["name"]
        if not present:
            return {
                r: dict(running=False, state="NOT_STARTED")
                for r in (*ROLES, "supervisor")
            }
        result = {}
        for role in (*ROLES, "supervisor"):
            key = role_key(cfg, stream, role)
            row = db.conn.execute(
                f"""SELECT r.*,EXISTS(SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid
                WHERE l.pid=r.backend_pid AND a.backend_start=r.backend_start AND l.locktype='advisory' AND l.granted
                AND l.classid=(%s::bigint >> 32)::oid AND l.objid=(%s::bigint & 4294967295)::oid AND l.objsubid=1) AS locked
                FROM {cfg.source_schema}.runtime_roles r WHERE role=%s""",
                (key, key, role),
            ).fetchone()
            result[role] = dict(
                running=bool(row and row["locked"]),
                heartbeat_age_seconds=(
                    (time.time_ns() - row["heartbeat_ns"]) / 1e9 if row else None
                ),
                **(row["info"] if row else dict(state="NOT_STARTED")),
            )
        return result
    finally:
        db.close()


def startup_failure(project, code, started, observed):
    details = dict(code_root=str(Path(__file__).resolve().parents[1]), roles={})
    for role, token in started:
        child = _children.get((role, token))
        current = observed.get(role, {})
        details["roles"][role] = dict(
            requested_token=token,
            launcher_pid=child.pid if child else None,
            exit_code=child.poll() if child else None,
            observed={k: current.get(k) for k in ("running", "state", "command_token", "process_pid", "heartbeat_age_seconds", "failure")},
        )
    record = dict(status=code, recorded_at_ns=time.time_ns(), **details)
    try:
        save(paths(project, "ingest")[0] / "startup-failure.local.json", record)
    except OSError as exc:
        details["diagnostic_write_failure"] = type(exc).__name__
    error = ValueError(code)
    error.details = details
    return error


def start(project, roles=ROLES, *, with_supervisor=False):
    for key, child in list(_children.items()):
        if child.poll() is not None:
            child.wait()
            del _children[key]
    previous = status(project)
    started = []
    for role in roles:
        if previous[role]["running"]:
            continue
        root, report, stop = paths(project, role)
        token = uuid.uuid4().hex
        with (root / (role + "-launcher.log")).open("wb") as log:
            child = subprocess.Popen(
                [
                    sys.executable,
                    "-X",
                    "utf8",
                    "-B",
                    "-m",
                    "compact_product",
                    *(["supervise"] if role == "supervisor" else ["worker", role]),
                    "--project",
                    str(Path(project).resolve()),
                    "--token",
                    token,
                ],
                cwd=Path(__file__).resolve().parents[1],
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
                env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
            )
        _children[(role, token)] = child
        started.append((role, token))
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        value = status(project)
        if any(_children[(r, t)].poll() is not None for r, t in started):
            raise startup_failure(project, "COMPACT_ROLE_EXITED_DURING_START", started, value)
        if all(
            value[r]["running"] and value[r].get("command_token") == t
            for r, t in started
        ):
            if with_supervisor:
                return start(project, roles=("supervisor",))
            return value
        time.sleep(0.5)
    raise startup_failure(project, "COMPACT_START_NOT_CONFIRMED_READ_LAUNCHER_LOG", started, value)


def stop(project, roles=ROLES, *, timeout=45):
    before = status(project)
    # Stop supervision first; otherwise it could restart a role during stop.
    if before.get("supervisor", {}).get("running") and "supervisor" not in roles:
        stop(project, roles=("supervisor",), timeout=timeout)
        before = status(project)
    for role in roles:
        if before[role]["running"]:
            save(paths(project, role)[2], dict(token=before[role]["command_token"]))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        now = status(project)
        for role in roles:
            if (
                before[role]["running"]
                and now[role]["running"]
                and now[role].get("command_token") != before[role].get("command_token")
            ):
                raise ValueError("COMPACT_STOP_OWNER_REPLACED")
        if not any(now[role]["running"] for role in roles):
            for role in roles:
                child = _children.pop((role, before[role].get("command_token")), None)
                if child:
                    child.wait(timeout=10)
            return now
        time.sleep(0.5)
    # No blind PID kill. A caller can wait for the capture/transaction to finish.
    raise TimeoutError("COMPACT_STOP_PENDING_RETRY_STATUS")


def supervise(project, token):
    lease = Lease(project, "supervisor", token)
    try:
        while not lease.stop.is_set():
            lease.check()
            values = status(project)
            if any(not values[r]["running"] for r in ROLES):
                start(project)
            lease.update(
                state="SUPERVISING",
                roles={r: v.get("state") for r, v in values.items()},
            )
            lease.stop.wait(5)
    finally:
        lease.close()
