"""Development probe: verified installed AD, Viewer byte pin and own PG activity.

Run with the existing application Python and --project pointing to pishkhan24.
This optional tool is separate from the release Manifest: adding it through Git
does not change the live worker's release identity or request a restart. The
application code it imports still passes the installed launcher's verification.
It never initializes Viewer, starts/stops a process, evaluates a model, changes
ACLs or executes database mutations. Only a private diagnostic JSON is written.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import runpy
import sys
import time
import traceback
import uuid


ACTIVITY_SQL = """SELECT pid, application_name, state, wait_event_type, wait_event,
    EXTRACT(EPOCH FROM (clock_timestamp()-query_start))::double precision AS query_age_seconds,
    EXTRACT(EPOCH FROM (clock_timestamp()-xact_start))::double precision AS transaction_age_seconds,
    pg_blocking_pids(pid) AS blocking_pids,
    CASE WHEN query LIKE 'SELECT w.body FROM anomaly_detection.adp_windows w WHERE %%' THEN 'OWNED_HISTORY'
         WHEN query LIKE 'UPDATE anomaly_detection.adp_jobs%%' THEN 'OWNED_JOB_UPDATE'
         WHEN query ~ '^\\s*SELECT\\s' THEN 'SELECT'
         WHEN query ~ '^\\s*UPDATE\\s' THEN 'UPDATE'
         ELSE 'OTHER' END AS statement_class
    FROM pg_catalog.pg_stat_activity
    WHERE usename=current_user AND datname=current_database()
      AND application_name LIKE 'AnomalyDetection.%%' AND pid<>pg_backend_pid()
    ORDER BY pid LIMIT 32"""


def failure(exc, project):
    """Export fixed metadata, never exception text, source lines or SQL values."""
    code = str(exc)
    result = {'error_type':type(exc).__name__}
    if type(exc).__name__=='ContractError' and re.fullmatch('[A-Z0-9_]+', code):
        result['code'] = code
    for field in ('errno', 'winerror'):
        value = getattr(exc, field, None)
        if type(value) is int:
            result[field] = value
    sqlstate = getattr(exc, 'sqlstate', None)
    if isinstance(sqlstate, str) and re.fullmatch('[A-Z0-9]{5}', sqlstate):
        result['sqlstate'] = sqlstate
    filename = getattr(exc, 'filename', None)
    if isinstance(filename, str):
        path = Path(filename).resolve()
        result['file'] = path.relative_to(project).as_posix() if path.is_relative_to(project) else 'OUTSIDE_PROJECT'
    frames = []
    for frame in traceback.extract_tb(exc.__traceback__):
        path = Path(frame.filename).resolve()
        if path.is_relative_to(project):
            frames.append({'file':path.relative_to(project).as_posix(), 'line':frame.lineno, 'function':frame.name})
    result['frames'] = frames[-8:]
    return result


def attempt(call, project):
    try:
        return {'status':'READ', 'value':call()}
    except Exception as exc:
        return {'status':'READ_FAILED', 'failure':failure(exc, project)}


def process_summary(status):
    result = {key:status.get(key) for key in ('health','running','observation_matches_process','heartbeat_age_seconds','diagnostic_failures')}
    for resource in ('process','web'):
        observed = status.get(resource) or {}
        owner = observed.get('owner') or {}
        result[resource] = {key:observed.get(key) for key in ('locked','owner_read_status','owner_read_failure')}
        result[resource]['owner'] = {key:owner.get(key) for key in ('job','pid','build_id','source_sha256','started_at_utc')}
    worker = status.get('worker') or status.get('unverified_worker_status') or {}
    result['worker'] = {key:worker.get(key) for key in ('state','phase','heartbeat_ns','source_pages','evaluated_jobs','audited_requests','content_reads','scenario_evaluations','last_source_failure','last_source_failure_event','last_storage_failure','evaluating_target','owned_statement','last_owned_query_metrics')}
    # The selected target is unnecessary for diagnosing a blocked SQL call.
    result['worker'].pop('evaluating_target', None)
    return result


def activity(database, root):
    with database(root, readonly=True) as raw:
        return [dict(row) for row in raw.execute(ACTIVITY_SQL).fetchall()]


def collect(project, *, source_identity, status, database, wait=time.sleep, clock=time.time_ns):
    project = Path(project).resolve()
    root = project/'AnomalyDetection'
    value = {'probe':'AD_LIVE_READ_ONLY_DIAGNOSTIC_1', 'source_check':attempt(lambda:source_identity(project),project),
             'samples':[], 'database_modified':False, 'installation_source_modified':False,
             'models_executed':False, 'project_acceptance':'NOT_ASSIGNED_BY_PROBE'}
    for number in range(2):
        if number:
            wait(2)
        value['samples'].append({'observed_ns':clock(),
            'worker':attempt(lambda:process_summary(status(root)),project),
            'own_postgresql_activity':attempt(lambda:activity(database,root),project)})
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',required=True,type=Path)
    parser.add_argument('--output',type=Path)
    args = parser.parse_args()
    project = args.project.resolve(); root = project/'AnomalyDetection'
    try:
        launcher = runpy.run_path(str(root/'run_anomaly.py'))
        sha = launcher['verify_build']()
        sys.path.insert(0,str(root))
        sys.meta_path.insert(0,launcher['VerifiedApplicationFinder']())
        from anomaly_detection.pg_source import installed_source_identity
        from anomaly_detection.product_control import status
        from anomaly_detection.native_pg import database
        value = collect(project,source_identity=installed_source_identity,status=status,database=database)
        value['installed_build_id'] = launcher['EXPECTED_BUILD']
        value['installed_source_sha256'] = sha
        output = args.output or root/'reports'/('AD_Live_ReadOnly_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')+'_'+uuid.uuid4().hex[:8]+'.json')
        output = output.resolve(); output.parent.mkdir(parents=True,exist_ok=True)
        with output.open('x',encoding='utf-8') as stream:
            json.dump(value,stream,ensure_ascii=False,indent=2,default=str)
            stream.write('\n')
        print(json.dumps({'status':'READ_ONLY_DIAGNOSTIC_EXPORTED','output':str(output),
            'source_check':value['source_check']['status'],'database_modified':False,'installation_source_modified':False}))
        return 0
    except Exception as exc:
        print(json.dumps({'status':'READ_ONLY_DIAGNOSTIC_FAILED','failure':failure(exc,project)}))
        return 1


if __name__=='__main__':
    raise SystemExit(main())
