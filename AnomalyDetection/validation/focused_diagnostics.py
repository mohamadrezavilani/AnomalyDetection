"""Bounded READ ONLY case-job metadata and delegated journey diagnostics.

Run this standalone helper with --project pointing to the installed project.
It verifies that installation, never starts workers, and never saves a journey
projection or evaluates a model. Only a new reports JSON file is written.
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

sys.dont_write_bytecode = True
MAX_SCOPES = 1024
BATCH = 16
MAX_BYTES = 8 * 1024 * 1024
MAX_JOURNEYS = 3
VERSION = 'AD_FOCUSED_DIAGNOSTICS_1'


def problem(exc, project):
    """Public code locations only: no exception text, source lines or locals."""
    project = Path(project).resolve()
    result = {'error_type': type(exc).__name__, 'sites': []}
    state = getattr(exc, 'sqlstate', None)
    if isinstance(state, str) and re.fullmatch('[0-9A-Z]{5}', state):
        result['sqlstate'] = state
    for frame in traceback.extract_tb(exc.__traceback__):
        path = Path(frame.filename).resolve()
        if not path.is_relative_to(project):
            continue
        name = path.relative_to(project).as_posix()
        if not name.startswith(('AnomalyDetection/anomaly_detection/', 'p24_foundation/')):
            continue
        function = frame.name if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,79}', frame.name) else 'anonymous'
        result['sites'].append({'file': name, 'line': frame.lineno, 'function': function})
    result['sites'] = result['sites'][-6:]
    return result


def case_jobs(raw, deadline, *, clock=time.monotonic, project=Path('.')):
    """Read exact case-linked job PKs, omitting large window/proof payloads."""
    out = {'complete': False, 'scope': 'NON_NULL_ACTOR_CASE_SCOPES',
           'feature_and_population_jobs': 'NOT_COLLECTED', 'rows': [],
           'scope_keys': [], 'missing_job_keys': [], 'error': None}
    used = 0
    try:
        if clock() >= deadline:
            out['error'] = {'error_type': 'OBSERVATION_DEADLINE'}
            return out
        with raw.transaction():
            scopes = [dict(r) for r in raw.execute(
                'SELECT DISTINCT job_session AS session_key,target_ns FROM anomaly_detection.adp_case_signals '
                "WHERE source_kind='actor' AND job_session IS NOT NULL "
                'ORDER BY job_session,target_ns LIMIT ' + str(MAX_SCOPES + 1)).fetchall()]
        overflow = len(scopes) > MAX_SCOPES
        scopes = scopes[:MAX_SCOPES]
        out['scope_keys'] = scopes
        for begin in range(0, len(scopes), BATCH):
            if clock() >= deadline:
                out['error'] = {'error_type': 'OBSERVATION_DEADLINE'}
                return out
            batch = scopes[begin:begin+BATCH]
            params = tuple(value for row in batch for value in (row['session_key'], row['target_ns']))
            sql = ('SELECT j.session_key,j.target_ns,j.version,j.processed_version,j.primary_version,'
                   'j.primary_processed_version,j.dirty,j.due_ns,j.last_evaluated_ns,j.evaluation,j.target_scope '
                   'FROM (VALUES ' + ','.join(['(%s::text,%s::bigint)']*len(batch)) + ') s(session_key,target_ns) '
                   'JOIN LATERAL (SELECT j.* FROM anomaly_detection.adp_jobs j '
                   'WHERE j.session_key=s.session_key AND j.target_ns=s.target_ns LIMIT 1) j ON TRUE '
                   'ORDER BY j.session_key,j.target_ns')
            with raw.transaction():
                values = [dict(row) for row in raw.execute(sql, params).fetchall()]
            found = {(r['session_key'], r['target_ns']) for r in values}
            out['missing_job_keys'].extend(r for r in batch if (r['session_key'], r['target_ns']) not in found)
            for row in values:
                used += len(json.dumps(row, ensure_ascii=False).encode('utf-8'))
                if used > MAX_BYTES:
                    out['error'] = {'error_type': 'DATASET_BYTE_BUDGET'}
                    return out
                out['rows'].append(row)
        out['complete'] = not overflow
        if overflow:
            out['error'] = {'error_type': 'CASE_SCOPE_BUDGET_EXCEEDED', 'limit': MAX_SCOPES}
    except Exception as exc:
        out['error'] = problem(exc, project)
    return out


def journey_probes(source, keys, deadline, *, read, clock=time.monotonic):
    result = []
    for key in keys[:MAX_JOURNEYS]:
        if clock() >= deadline:
            result.append({'status': 'NOT_RUN_DEADLINE'})
            break
        try:
            packet = read(source, key)
            result.append({'status': 'READ_MODELS_COMPLETED', 'request_key': key,
                           'semantic_present': packet.get('semantic') is not None,
                           'journey_present': packet.get('journey') is not None,
                           'context_present': packet.get('service_context') is not None,
                           'payment_present': packet.get('payment') is not None})
        except Exception as exc:
            result.append({'status': 'READ_MODELS_FAILED', 'request_key': key,
                           'failure': problem(exc, source.project)})
    return result


def collect(project, *, seconds=45):
    started = time.monotonic()
    deadline = started + seconds
    project = Path(project).resolve()
    ad = project/'AnomalyDetection'
    out = {'probe': VERSION, 'observed_at_utc': datetime.now(timezone.utc).isoformat(),
           'identity_scope': 'VERIFIED_INSTALLED_FILES_NOT_RUNNING_WORKER',
           'database_modified': False, 'models_executed': False, 'workers_restarted': False,
           'checkpoint_modified': False, 'owned_projection_save': 'NOT_RUN_READ_ONLY',
           'production_accuracy': 'NOT_ASSIGNED', 'failures': []}
    try:
        launcher = runpy.run_path(str(ad/'run_anomaly.py'))
        sha = launcher['verify_build']()
        sys.path.insert(0, str(ad))
        sys.meta_path.insert(0, launcher['VerifiedApplicationFinder']())
        from anomaly_detection import BUILD_ID
        from anomaly_detection.native_pg import connect
        from anomaly_detection.product_source import ProductSource
        from anomaly_detection.viewer_bridge import read_journey
        out.update(installed_build_id=BUILD_ID, installed_source_sha256=sha)
        # connect(readonly=True) validates the product DB and restricted role.
        raw = connect(ad, readonly=True)
        keys = []
        try:
            raw.execute("SET statement_timeout='1200ms'")
            with raw.transaction():
                raw.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
                flags = raw.execute("SELECT current_setting('transaction_read_only') AS ro,"
                                    "current_setting('transaction_isolation') AS isolation").fetchone()
                if flags != {'ro': 'on', 'isolation': 'repeatable read'}:
                    raise ValueError('read-only transaction not verified')
                out['transaction'] = dict(flags)
                out['case_jobs'] = case_jobs(raw, deadline-8, project=project)
                if time.monotonic() < deadline-7:
                    try:
                        with raw.transaction():
                            keys = [row['request_key'] for row in raw.execute(
                                'SELECT request_key FROM anomaly_detection.adp_journeys '
                                "WHERE body::jsonb->>'quality'='WAITING_FOR_BOUNDED_READMODEL' "
                                'ORDER BY next_read_ns DESC,request_key LIMIT 3').fetchall()]
                    except Exception as exc:
                        out['failures'].append({'stage': 'select_journey_samples', **problem(exc, project)})
        finally:
            raw.close()
        if keys and time.monotonic() < deadline-6:
            source = ProductSource(project)
            out['journey_probes'] = journey_probes(source, keys, deadline-3, read=read_journey)
        else:
            out['journey_probes'] = []
        out['journey_scope'] = ('Up to three WAITING_FOR_BOUNDED_READMODEL rows by descending next_read_ns; '
                                'not all failure targets. Successful reads do not test the owned save step '
                                'or establish a fix. An empty list is NOT_RUN, not a successful journey test.')
        out['status'] = 'EXPORTED' if out['case_jobs']['complete'] else 'PARTIAL_EXPORTED'
    except Exception as exc:
        out['status'] = 'BLOCKED_EXPORTED'
        out['failures'].append(problem(exc, project))
    out['elapsed_seconds'] = round(time.monotonic()-started, 3)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', required=True, type=Path)
    args = parser.parse_args()
    project = args.project.resolve()
    if not (project/'AnomalyDetection/run_anomaly.py').is_file():
        print(json.dumps({'status': 'PROJECT_NOT_FOUND'}))
        return 1
    value = collect(project)
    output = project/'AnomalyDetection/reports'/(
        'AD_Focused_Diagnostics_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')+'_'+uuid.uuid4().hex[:8]+'.json')
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'status': value['status'], 'output': str(output),
                      'case_jobs_complete': value.get('case_jobs', {}).get('complete', False),
                      'database_modified': False, 'models_executed': False}, ensure_ascii=True))
    return 0 if value['status']=='EXPORTED' else 2


if __name__ == '__main__':
    raise SystemExit(main())
