"""A separately managed backfill worker; the accepted live product keeps running."""

import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import signal
import threading
from datetime import datetime
from zoneinfo import ZoneInfo
from psycopg.errors import InsufficientPrivilege

from compact_behavior import FIVE, FEATURES
from compact_behavior.extract import instant, iso
from compact_behavior.source import ElasticWindow
from compact_behavior.store import Store
from compact_behavior.__main__ import measure_window, save
from compact_behavior.history import initialize, prepare, latest, finish
from compact_ad import MODEL
from .config import load
from .health import health
from .runtime import Lease, paths
from .version import verify


def core_ready(value):
    for role in ("ingest", "analysis", "web"):
        state = value.get("roles", {}).get(role, {})
        age = state.get("heartbeat_age_seconds")
        if not state.get("running") or not isinstance(age, (int,float)) or age > 15 or state.get("failure") or state.get("state") in ("STARTING","STOPPED","RETRYING"):
            return False
    return all(value.get(k) == 0 for k in ("source_backlog_windows","reference_pending_windows","analysis_pending_windows","dirty_keys","reanalysis_windows","analysis_timing_unconfirmed_windows")) and value.get("latest_received_end_ns") is not None and value.get("latest_received_end_ns") == value.get("latest_analyzed_end_ns") and value.get("latest_analysis_timing_confirmed") is True


def storage_status(store):
    result = dict(database_bytes=store.conn.execute("SELECT pg_database_size(current_database()) AS n").fetchone()["n"])
    if store.conn.info.host not in ("127.0.0.1","localhost","::1"):
        return dict(result, local_free_space="NOT_OBSERVED_REMOTE_DATABASE")
    try:
        data = Path(store.conn.execute("SHOW data_directory").fetchone()["data_directory"])
    except InsufficientPrivilege:
        return dict(result,local_free_space="NOT_OBSERVED_PERMISSION")
    try:
        result["local_data_volume_free_bytes"] = shutil.disk_usage(data).free
    except OSError:
        result["local_free_space"] = "NOT_OBSERVED"
    return result


def progress(store, cfg, stream):
    job = latest(store, stream)
    value = health(store.conn, cfg, stream)
    result = dict(status="COMPACT_HISTORY_STATUS", job=job, core=value,
        history_role=value.get("roles",{}).get("history",dict(running=False)),
        history_package=verify(), storage=storage_status(store))
    if job:
        result.update(from_tehran=datetime.fromtimestamp(job["from_ns"]/1e9,ZoneInfo('Asia/Tehran')).isoformat(),
            from_utc=iso(job["from_ns"]), next_utc=iso(job["next_ns"]), target_utc=iso(job["target_ns"]),
            total_windows=(job["target_ns"]-job["from_ns"])//FIVE,
            remaining_windows=(job["target_ns"]-job["next_ns"])//FIVE,
            input_checkpoint_rewound=(store.cursor(stream) or 0)<job["live_next_at_prepare_ns"])
    return result


def log_tails(project):
    result={}
    for name in ("history.log","history-launcher.log"):
        path=Path(project)/"compact_runtime"/name
        try:
            with path.open("rb") as file:
                size=file.seek(0,2);file.seek(max(0,size-8192))
                data=file.read(8192)
                codec="utf-16-le" if data.count(b"\x00")>len(data)//4 else "utf-8-sig"
                result[name]=data.decode(codec,errors="replace")
        except FileNotFoundError:
            pass
        except OSError as exc:
            result[name]=dict(read_failure=type(exc).__name__)
    return result


def tick(store, cfg, source, stream, check, *, source_factory=ElasticWindow):
    job = latest(store, stream)
    if not job or job["state"] == "COMPLETE":
        return dict(state="COMPLETE", job=job)
    current = health(store.conn, cfg, stream)
    if current.get("analysis_timing_unconfirmed_windows",0):
        # A crash after semantic commit must trigger a real re-evaluation,
        # never manufacture a timing acknowledgement for the old revision.
        store.conn.execute(f"""INSERT INTO {cfg.ad_schema}.reanalysis(stream_id,start_ns,updated_at_ns)
            SELECT r.stream_id,r.start_ns,%s FROM {cfg.ad_schema}.window_results r
            WHERE r.stream_id=%s AND r.feature_version=%s AND r.model_version=%s
            AND r.timing_confirmed_revision<>r.revision
            AND NOT EXISTS(SELECT 1 FROM {cfg.ad_schema}.reanalysis j WHERE j.stream_id=r.stream_id
                AND j.start_ns=r.start_ns AND j.processed_version<j.version)
            ORDER BY r.start_ns DESC LIMIT 1
            ON CONFLICT(stream_id,start_ns) DO UPDATE SET version={cfg.ad_schema}.reanalysis.version+1,updated_at_ns=excluded.updated_at_ns""",
            (time.time_ns(),stream,FEATURES,MODEL))
        return dict(state="WAITING_FOR_ANALYSIS_TIMING",job=job)
    if not core_ready(current):
        return dict(state="WAITING_FOR_LIVE_AND_ANALYSIS", job=job)
    if job["state"] == "SOURCE_COMPLETE":
        complete = finish(store, stream, job, cfg.ad_schema, MODEL)
        return dict(state="COMPLETE" if complete else "WAITING_FOR_HISTORY_ANALYSIS", job=latest(store,stream))
    disk = storage_status(store)
    free=disk.get("local_data_volume_free_bytes")
    if free is not None and free < 10*1024**3:
        return dict(state="WAITING_FOR_STORAGE_HEADROOM", storage=disk, job=job)
    start = job["next_ns"]
    source_window = source_factory(source["ELASTICSEARCH"],start,start+FIVE,
        page_size=source["ELASTICSEARCH"].get("compact_page_size",500), budget=cfg.ingest_budget_seconds)

    class Publisher:
        limits = store.limits
        def publish(self, *args, **kwargs):
            check()
            return store.publish(*args, allow_history=True, history_job=job["job_id"], **kwargs)

    result = measure_window(Publisher(),stream,source_window,progress=lambda **kwargs: check())
    return dict(state="PUBLISHED", publication=result, job=latest(store,stream))


def worker(project, token):
    root, _, _ = paths(project,"history")
    logger = logging.getLogger("compact.history")
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(root/"history.log",maxBytes=8*1024**2,backupCount=3,encoding="utf-8")
    logger.addHandler(handler)
    lease = store = None
    try:
        lease = Lease(project,"history",token)
        if threading.current_thread() is threading.main_thread():
            for sig in (signal.SIGINT,signal.SIGTERM):
                signal.signal(sig,lambda *args: lease.stop.set())
        cfg, source, stream = load(project)
        store = Store(source["DATABASE"],schema=cfg.source_schema,application="history")
        store.init(); initialize(store)
        lease.update(state="CHECKING_HISTORY")
        retry = 0
        while not lease.stop.is_set():
            try:
                lease.check()
                value = tick(store,cfg,source,stream,lease.check)
                job = value.get("job") or {}
                lease.update(state=value["state"],job_id=job.get("job_id"),next_ns=job.get("next_ns"),target_ns=job.get("target_ns"),
                    remaining_windows=(job.get("target_ns",0)-job.get("next_ns",0))//FIVE,failure=None)
                save(root/"history-progress.local.json",dict(status=value["state"],job=job,recorded_at_ns=time.time_ns()))
                if value["state"] == "COMPLETE":
                    return 0
                if value["state"] == "PUBLISHED":
                    logger.info(json.dumps(dict(event="HISTORY_PUBLICATION",**value["publication"])))
                else:
                    lease.stop.wait(cfg.idle_seconds)
                retry = 0
            except InterruptedError:
                break
            except Exception as exc:
                retry += 1
                failure = dict(type=type(exc).__name__,code=str(exc) if isinstance(exc,ValueError) else None,sqlstate=getattr(exc,"sqlstate",None),details=getattr(exc,"details",None))
                lease.update(state="RETRYING",retry=retry,failure=failure)
                logger.error(json.dumps(dict(event="HISTORY_RETRY",**failure)))
                if store.conn.closed:
                    store.close()
                    store = Store(source["DATABASE"],schema=cfg.source_schema,application="history")
                    store.init(); initialize(store)
                lease.stop.wait(min(30,2**min(retry,5)))
        if lease.fatal:
            logger.error("history lease lost: %s",lease.fatal)
        return 1 if lease.fatal else 0
    except BaseException:
        logger.exception("history worker stopped unexpectedly")
        raise
    finally:
        if store: store.close()
        if lease: lease.close()
        handler.close(); logger.removeHandler(handler)


def task(project, operation):
    from viewer_performance.financial_screen.host import powershell
    code = Path(__file__).resolve().parents[1]
    args = subprocess.list2cmdline(["-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",str(code/"compact_product/History_Compact_Product.ps1"),"-Action","Worker","-Project",str(project),"-Python",sys.executable])
    environment = dict(P24_HISTORY_ROOT=str(project),P24_HISTORY_CODE=str(code),P24_HISTORY_ARGS=args)
    script = r"""
$ErrorActionPreference='Stop'
$name='P24-CompactHistory'
$old=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
if($old){
  $a=@($old.Actions)
  if($a.Count -ne 1 -or $a[0].Execute -ne 'powershell.exe' -or $a[0].Arguments -ne $env:P24_HISTORY_ARGS -or $a[0].WorkingDirectory -ne $env:P24_HISTORY_CODE){throw 'History task identity mismatch'}
}
"""
    if operation == "register":
        script += r"""
$action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $env:P24_HISTORY_ARGS -WorkingDirectory $env:P24_HISTORY_CODE
$trigger=New-ScheduledTaskTrigger -AtStartup
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $name
@{status='HISTORY_AUTOSTART_REGISTERED'} | ConvertTo-Json -Compress
"""
    elif operation == "disable":
        script += "\nif($old){Disable-ScheduledTask -TaskName $name | Out-Null}\n@{status='HISTORY_AUTOSTART_DISABLED'} | ConvertTo-Json -Compress\n"
    else:
        raise ValueError("unknown_history_task_operation")
    return powershell(script,environment)


def control(project, action, *, from_value=None):
    from .operations import require_windows_admin
    cfg, source, stream = load(project)
    if action in ("install","stop"):
        require_windows_admin()
    store = Store(source["DATABASE"],schema=cfg.source_schema,application="history.control")
    try:
        if action == "install":
            store.init(); initialize(store)
        if action == "status":
            result = progress(store,cfg,stream)
        elif action == "stop":
            task(project,"disable")
            before = health(store.conn,cfg,stream).get("roles",{}).get("history",{})
            if before.get("running"):
                save(paths(project,"history")[2],dict(token=before["command_token"]))
                deadline = time.monotonic()+60
                while time.monotonic()<deadline:
                    role = health(store.conn,cfg,stream).get("roles",{}).get("history",{})
                    if not role.get("running"): break
                    if role.get("command_token") != before["command_token"]: raise ValueError("history_stop_owner_replaced")
                    time.sleep(.5)
                else: raise TimeoutError("history_stop_pending")
            result = progress(store,cfg,stream)
            result["status"] = "COMPACT_HISTORY_STOPPED_LIVE_PRESERVED"
        elif action == "install":
            if not from_value: raise ValueError("explicit_history_from_required")
            floor = instant(from_value)
            current = health(store.conn,cfg,stream)
            for role in ("ingest","analysis","web"):
                entry = current.get("roles",{}).get(role,{})
                if not entry.get("running") or entry.get("heartbeat_age_seconds",999)>15 or entry.get("failure"):
                    raise ValueError("healthy_live_roles_required_before_history")
            from compact_behavior.probe_elastic import probe
            check = probe(source["ELASTICSEARCH"],floor)
            if check.get("status") != "FIRST_SEARCH_PAGE_VALID": raise ValueError("historical_source_preflight_failed")
            job = prepare(store,stream,floor)
            expected = verify()["source_sha256"]
            existing = current.get("roles",{}).get("history",{})
            if existing.get("running") and existing.get("package",{}).get("source_sha256") != expected:
                raise ValueError("stop_existing_history_worker_before_history_code_update")
            if job["state"] != "COMPLETE":
                task(project,"register")
                deadline = time.monotonic()+45
                while time.monotonic()<deadline:
                    role = health(store.conn,cfg,stream).get("roles",{}).get("history",{})
                    if role.get("running") and role.get("failure"):
                        raise ValueError("history_start_failed_read_history_role_failure")
                    if role.get("running") and role.get("state") not in ("STARTING","STOPPED") and role.get("package",{}).get("source_sha256")==expected and role.get("heartbeat_age_seconds",999)<15:
                        break
                    time.sleep(.5)
                else: raise TimeoutError("history_start_not_confirmed")
            result = progress(store,cfg,stream)
            result["status"] = "COMPACT_HISTORY_COMPLETE" if job["state"]=="COMPLETE" else "COMPACT_HISTORY_STARTED_LIVE_PRESERVED"
            result["source_preflight"] = check
        else:
            raise ValueError("unknown_history_control_action")
        if (result.get("job") or {}).get("state")!="COMPLETE" and not result["history_role"].get("running"):
            result["history_log_tails"]=log_tails(project)
        path = Path(project)/"AnomalyDetection/reports/Compact_History_Status.json"
        save(path,result)
        return dict(status=result["status"],output=str(path),from_tehran=result.get("from_tehran"),
            next_utc=result.get("next_utc"),target_utc=result.get("target_utc"),remaining_windows=result.get("remaining_windows"),
            history_state=result.get("job",{}).get("state") if result.get("job") else None,
            history_worker_running=result["history_role"].get("running",False),
            source_backlog_windows=result["core"].get("source_backlog_windows"),
            analysis_pending_windows=result["core"].get("analysis_pending_windows"),
            input_checkpoint_rewound=result.get("input_checkpoint_rewound",False),storage=result["storage"],
            history_worker_state=result["history_role"].get("state"),history_failure=result["history_role"].get("failure"),
            total_windows=result.get("total_windows"),
            deployed_role_builds={r:v.get("build") for r,v in result["core"].get("roles",{}).items()})
    except Exception as exc:
        path = Path(project)/"AnomalyDetection/reports/Compact_History_Status.json"
        failure = dict(type=type(exc).__name__,code=str(exc) if isinstance(exc,(ValueError,TimeoutError)) else None,sqlstate=getattr(exc,"sqlstate",None))
        value = dict(status="COMPACT_HISTORY_OPERATION_INCOMPLETE",failure=failure)
        value["history_log_tails"]=log_tails(project)
        try:
            value["diagnostic"] = progress(store,cfg,stream)
        except Exception as diagnostic_error:
            value["diagnostic_error_type"] = type(diagnostic_error).__name__
        save(path,value)
        exc.details = dict(report=str(path),failure=failure)
        raise
    finally:
        store.close()
