#!/usr/bin/env python3
"""Bounded READ ONLY diagnostic export for Compact Product builds 5/6.
No DDL, DML, worker control, reanalysis, Elasticsearch access or raw payload export.
Run with the existing project virtualenv. An export is not an accuracy certificate.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True


def tehran(ns):
    if ns is None:
        return None
    return datetime.fromtimestamp(ns / 1e9, timezone(timedelta(hours=3, minutes=30))).isoformat()


def redact(row):
    if isinstance(row, dict):
        return {('session_pseudonym' if k == 'session_id' else k):
                (hashlib.sha256(str(v).encode()).hexdigest()[:24] if v else None)
                if k == 'session_id' else redact(v) for k, v in row.items()}
    if isinstance(row, list):
        return [redact(x) for x in row]
    return row


def aggregate(windows):
    totals = defaultdict(Counter)
    current = 0
    for w in windows:
        if not w['current']:
            continue
        current += 1
        for method, statuses in (w['readiness'] or {}).items():
            totals[method].update(statuses)
    result = {}
    for method, statuses in sorted(totals.items()):
        ready = statuses['NORMAL'] + statuses['ANOMALY']
        total = sum(statuses.values())
        result[method] = dict(statuses)
        result[method].update(ready_evaluations=ready,
            anomaly_percent_of_ready=100 * statuses['ANOMALY'] / ready if ready else None,
            ready_percent_of_evaluations=100 * ready / total if total else None)
    return {'selected_windows': len(windows), 'current_windows': current, 'methods': result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--code-root', type=Path, required=True)
    parser.add_argument('--windows-per-group', type=int, default=96)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if not 1 <= args.windows_per_group <= 144:
        parser.error('windows-per-group must be 1..144')
    root = args.code_root.resolve()
    if not (root / 'compact_product' / 'config.py').is_file():
        parser.error('code-root must contain compact_product/config.py')
    sys.path.insert(0, str(root))
    from compact_product.config import load
    from compact_behavior import FEATURES, FIVE
    from compact_ad import MODEL
    import psycopg
    from psycopg.rows import dict_row

    started = time.monotonic()
    report = {'format': 'P24_COMPACT_AD_READONLY_REVIEW_1',
              'created_utc': datetime.now(timezone.utc).isoformat(),
              'database_modified': False, 'workers_restarted': False,
              'limitations': ['Bounded recent history/live samples; not all history.',
                  'Readiness denominators are evaluations, not unique people.',
                  'Only current source/model/revision windows enter aggregates.',
                  'Finding samples are the latest 1500 per group, not a random sample.',
                  'Behavior feature diagnostics are latest 400 rows of one window per group; include support operations.',
                  'No raw input/output values, request IDs or original session IDs exported.',
                  'Human labels and known missed cases are required to establish accuracy.'],
              'errors': [], 'groups': {}}
    output = args.output or args.project / 'AnomalyDetection' / 'reports' / (
        'Compact_AD_Review_' + datetime.now().strftime('%Y%m%d_%H%M%S_%f') + '.json')
    conn = None
    try:
        cfg, source, stream = load(args.project)
        s, a = cfg.source_schema, cfg.ad_schema  # validated identifiers by load()
        report.update(stream_id=stream, source_schema=s, ad_schema=a,
                      model_version=MODEL, feature_version=FEATURES)
        params = {k: v for k, v in source['DATABASE'].items()
                  if k not in ('autocommit', 'row_factory', 'options', 'application_name')}
        params.update(autocommit=True, row_factory=dict_row, connect_timeout=10,
                      application_name='P24.Compact.ADReadOnlyReview',
                      options='-c default_transaction_read_only=on -c statement_timeout=8000 '
                      '-c lock_timeout=1000 -c idle_in_transaction_session_timeout=20000 '
                      '-c work_mem=8192 -c jit=off -c max_parallel_workers_per_gather=0')
        conn = psycopg.connect(**params)

        def query(label, sql, values=()):
            if time.monotonic() - started > 150:
                report['errors'].append({'query': label, 'error': 'TOTAL_BUDGET_EXCEEDED'})
                return []
            try:
                with conn.transaction():  # savepoint under outer read-only snapshot
                    return conn.execute(sql, values).fetchall()
            except Exception as exc:
                report['errors'].append({'query': label, 'error': type(exc).__name__,
                                         'sqlstate': getattr(exc, 'sqlstate', None)})
                return []

        with conn.transaction():
            conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
            report['transaction'] = query('transaction', 'SHOW transaction_read_only')
            jobs = query('history_job', f'SELECT * FROM {s}.history_jobs WHERE stream_id=%s ORDER BY created_at_ns DESC LIMIT 1', (stream,))
            report['history_job'] = jobs[0] if jobs else None
            groups = [('recent', 0, 9223372036854775807)]
            if jobs:
                groups = [('history', jobs[0]['from_ns'], jobs[0]['target_ns']),
                          ('live', jobs[0]['target_ns'], 9223372036854775807)]
            for name, low, high in groups:
                print(json.dumps({'status': 'READ_ONLY_REVIEW', 'group': name}), flush=True)
                windows = query(name + '_windows', f'''
                    SELECT w.start_ns,w.end_ns,w.source_records,w.extracted_requests,
                        w.published_at_ns,r.source_published_ns,r.readiness,r.summary,
                        r.model_version,r.feature_version,r.revision,r.timing_confirmed_revision,
                        r.analysis_seconds,r.analyzed_at_ns,
                        EXISTS(SELECT 1 FROM {s}.dirty_windows d WHERE d.stream_id=w.stream_id
                            AND d.start_ns=w.start_ns AND d.session_id='@all' AND d.processed_version<d.version) AS dirty,
                        EXISTS(SELECT 1 FROM {a}.reanalysis j WHERE j.stream_id=w.stream_id
                            AND j.start_ns=w.start_ns AND j.processed_version<j.version) AS reanalysis_pending
                    FROM (SELECT * FROM {s}.windows WHERE stream_id=%s AND start_ns>=%s AND start_ns<%s
                          ORDER BY start_ns DESC LIMIT %s) w
                    LEFT JOIN {a}.window_results r ON r.stream_id=w.stream_id AND r.start_ns=w.start_ns
                    ORDER BY w.start_ns DESC''', (stream, low, high, args.windows_per_group))
                for w in windows:
                    w['start_tehran'] = tehran(w['start_ns'])
                    w['current'] = (w['model_version'] == MODEL and w['feature_version'] == FEATURES
                        and w['source_published_ns'] == w['published_at_ns']
                        and w['revision'] == w['timing_confirmed_revision']
                        and not w['dirty'] and not w['reanalysis_pending'])
                group = {'windows': windows, 'aggregate': aggregate(windows)}
                report['groups'][name] = group
                starts = [w['start_ns'] for w in windows if w['current']]
                if not starts:
                    continue
                criteria = 'status=\'ANOMALY\' AND stream_id=%s AND start_ns=ANY(%s) AND result->>\'model_version\'=%s AND result->>\'feature_version\'=%s'
                values = (stream, starts, MODEL, FEATURES)
                group['finding_counts'] = query(name + '_counts', f'''
                    SELECT method,service,status,count(*) AS findings,count(DISTINCT session_id) AS distinct_sessions,
                           count(DISTINCT start_ns) AS affected_windows
                    FROM {a}.findings WHERE {criteria}
                    GROUP BY method,service,status ORDER BY method,service,status''', values)
                findings = query(name + '_findings', f'''
                    SELECT finding_id,start_ns,method,service,session_id,status,result,revision,first_seen_ns,updated_at_ns
                    FROM {a}.findings WHERE {criteria} AND status='ANOMALY'
                    ORDER BY start_ns DESC,finding_id LIMIT 1501''', values)
                group['findings_truncated'] = len(findings) > 1500
                findings = findings[:1500]
                for finding in findings:
                    finding['start_tehran'] = tehran(finding['start_ns'])
                group['findings'] = findings
                # Primary-key lookup only; no scan of payloads or legacy tables.
                ids = sorted({i for f in findings[:96] for i in f['result'].get('evidence', [])[:12]})[:1152]
                projection = '''behavior_id,observed_at_ns,api,kind,result_code,revision,quality,
                    features->>'version' AS feature_version,features->>'service_key' AS service_key,
                    features->'service_binding' AS service_binding,
                    features->'service_rate_eligible' AS rate_eligible,
                    features->'session_eligible' AS session_eligible,
                    features->'result_eligible' AS result_eligible,
                    features->'input_feature_eligibility' AS input_eligibility,
                    features->'output_feature_eligibility' AS output_eligibility,
                    features->'input_asof_ns' AS input_asof_ns,features->'output_asof_ns' AS output_asof_ns'''
                group['evidence_metadata'] = query(name + '_evidence', f'SELECT {projection} FROM {s}.behaviors WHERE stream_id=%s AND behavior_id=ANY(%s)', (stream, ids)) if ids else []
                latest = max(starts)
                group['feature_sample_start_ns'] = latest
                group['feature_metadata_sample'] = query(name + '_features', f'''
                    SELECT {projection} FROM {s}.behaviors
                    WHERE stream_id=%s AND observed_at_ns>=%s AND observed_at_ns<%s
                    ORDER BY observed_at_ns DESC,behavior_id DESC LIMIT 400''', (stream, latest, latest + FIVE))
                ids = [f['finding_id'] for f in findings]
                group['feedback_counts'] = query(name + '_feedback', f'''
                    SELECT finding_id,finding_revision,verdict,count(*) AS count
                    FROM {a}.feedback WHERE finding_id=ANY(%s)
                    GROUP BY finding_id,finding_revision,verdict''', (ids,)) if ids else []
    except Exception as exc:
        report['errors'].append({'query': 'setup_or_snapshot', 'error': type(exc).__name__,
                                 'sqlstate': getattr(exc, 'sqlstate', None)})
    finally:
        if conn is not None:
            conn.close()
    report['elapsed_seconds'] = round(time.monotonic() - started, 3)
    report['status'] = 'PARTIAL_READ_ONLY_EXPORT' if report['errors'] else 'READ_ONLY_EXPORT_COMPLETE'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(redact(report), ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'status': report['status'], 'output': str(output),
                      'errors': report['errors'], 'database_modified': False,
                      'workers_restarted': False}, ensure_ascii=False), flush=True)
    return 0 if not report['errors'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
