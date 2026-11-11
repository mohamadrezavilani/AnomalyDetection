"""Observe the existing Viewer/AD workload; never start or reconfigure a worker.

Uses the existing Viewer connection data in a read-only PostgreSQL session.
No capture, ingest, seek, recheck, model evaluation, DDL or EXPLAIN ANALYZE.
This optional command is outside both runtime manifests, so pulling it does
not change the running applications' source pins. SQL text and values stay in
memory; the exported report contains fixed classifications and digests only.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import runpy
import statistics
import sys
import time
import uuid

PROBE = 'VIEWER_LIVE_PERFORMANCE_1'
SECOND_NS = 1_000_000_000
FIVE_NS = 300 * SECOND_NS
APP = 'P24.Performance.readonly'
SETTINGS = ('server_version', 'shared_buffers', 'work_mem', 'temp_buffers',
    'effective_cache_size', 'wal_buffers', 'wal_compression', 'max_wal_size',
    'checkpoint_timeout', 'checkpoint_completion_target', 'fsync',
    'full_page_writes', 'synchronous_commit', 'wal_level', 'track_io_timing',
    'track_wal_io_timing', 'max_connections', 'jit')

# Never export arbitrary identifiers extracted from query text. Only names
# found in the installed public source are eligible for the structural summary.
SQL_NAME = re.compile(r'\b(?:viewer_[a-z][a-z0-9_]*|adp_[a-z][a-z0-9_]*)\b', re.I)
SQL_LITERAL = re.compile(r"'(?:''|[^'])*'", re.S)
SQL_NUMBER = re.compile(r'(?<![a-z_])\b\d+(?:\.\d+)?\b', re.I)
SQL_OPERATION = re.compile(r'^\s*(SELECT|INSERT|UPDATE|DELETE|WITH|CREATE|DROP|ALTER|TRUNCATE|ANALYZE|SET|EXPLAIN|VALUES|COPY)\b', re.I)

ACTIVITY_SQL = """SELECT a.pid,a.application_name,a.backend_type,a.state,
    a.wait_event_type,a.wait_event,
    EXTRACT(EPOCH FROM (clock_timestamp()-a.query_start))::double precision AS query_age_seconds,
    EXTRACT(EPOCH FROM (clock_timestamp()-a.xact_start))::double precision AS transaction_age_seconds,
    pg_blocking_pids(a.pid) AS blocking_pids,a.query,
    EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=a.pid
       AND l.locktype='advisory' AND l.classid=240026 AND l.objid=1
       AND l.objsubid=2 AND l.granted) AS viewer_singleton_owner,
    EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=a.pid
       AND l.locktype='advisory' AND l.classid=240026 AND l.objid=2
       AND l.objsubid=2 AND l.granted) AS viewer_write_lock_owner
    FROM pg_catalog.pg_stat_activity a
    WHERE a.datname=current_database() AND a.pid<>pg_backend_pid()
    ORDER BY viewer_singleton_owner DESC,viewer_write_lock_owner DESC,a.pid LIMIT 129"""
STATE_SQL = """SELECT start_ns,next_ns,generation,last_publish_ns,last_success_ns,
    last_attempt_ns,worker_status,overlap_windows,lag_seconds
    FROM public.viewer_live_state WHERE id=1"""
RECEIPTS_SQL = """SELECT start_ns,end_ns,mode,generation,records,new_events,
    impacted_requests,elapsed_seconds,published_ns,capture_seconds,cycle_seconds
    FROM public.viewer_live_receipts WHERE mode='forward'
    ORDER BY start_ns DESC,published_ns DESC LIMIT 24"""
RESUMES_SQL = """SELECT previous_next_ns,resumed_from_ns,resumed_at_ns
    FROM public.viewer_live_resumes ORDER BY resumed_from_ns DESC LIMIT 32"""
TABLES_SQL = """SELECT s.schemaname,s.relname,s.n_live_tup,s.n_dead_tup,
    s.n_mod_since_analyze,s.seq_scan,s.idx_scan,s.last_autovacuum,s.last_autoanalyze,
    s.last_analyze,c.reltuples AS planner_rows,
    c.relpages::bigint*current_setting('block_size')::bigint AS estimated_main_heap_bytes
    FROM pg_catalog.pg_stat_user_tables s JOIN pg_catalog.pg_class c ON c.oid=s.relid
    WHERE (s.schemaname='public' AND left(s.relname,7)='viewer_')
       OR s.schemaname='anomaly_detection'
    ORDER BY s.schemaname,s.relname LIMIT 256"""
AD_COUNTERS_SQL="""SELECT relname,n_tup_ins,n_tup_upd,n_tup_del,n_tup_hot_upd,
    seq_scan,idx_scan,autovacuum_count,n_live_tup,n_dead_tup
    FROM pg_catalog.pg_stat_user_tables WHERE schemaname='anomaly_detection'
    AND relname IN ('adp_scenario_jobs','adp_jobs','adp_facts','adp_population_jobs',
                   'adp_window_members','adp_profile_tasks') ORDER BY relname"""
INDEXES_SQL = """SELECT s.schemaname,s.relname,s.indexrelname,s.idx_scan,
    s.idx_tup_read,s.idx_tup_fetch,i.indisvalid,i.indisready,
    pg_relation_size(s.indexrelid) AS index_bytes
    FROM pg_catalog.pg_stat_user_indexes s JOIN pg_catalog.pg_index i ON i.indexrelid=s.indexrelid
    WHERE (s.schemaname='public' AND left(s.relname,7)='viewer_')
       OR s.schemaname='anomaly_detection'
    ORDER BY s.schemaname,s.relname,s.indexrelname LIMIT 512"""
COUNTERS = {
    'database': """SELECT stats_reset,blks_read,blks_hit,blk_read_time,blk_write_time,
        tup_inserted,tup_updated,temp_files,temp_bytes,deadlocks
        FROM pg_catalog.pg_stat_database WHERE datname=current_database()""",
    'wal_cluster': 'SELECT stats_reset,wal_records,wal_fpi,wal_bytes FROM pg_catalog.pg_stat_wal',
    'checkpointer_cluster': """SELECT stats_reset,num_timed,num_requested,write_time,
        sync_time,buffers_written FROM pg_catalog.pg_stat_checkpointer""",
    'io_cluster': """SELECT string_agg(DISTINCT stats_reset::text,',' ORDER BY stats_reset::text) AS stats_reset,
        sum(reads) AS reads,sum(writes) AS writes,sum(extends) AS extends,
        sum(fsyncs) AS fsyncs,sum(read_time) AS read_time,sum(write_time) AS write_time,
        sum(fsync_time) AS fsync_time FROM pg_catalog.pg_stat_io""",
}


def safe_failure(exc):
    result = {'error_type': type(exc).__name__}
    for key in ('errno', 'winerror'):
        value = getattr(exc, key, None)
        if type(value) is int:
            result[key] = value
    state = getattr(exc, 'sqlstate', None)
    if isinstance(state, str) and re.fullmatch('[A-Z0-9]{5}', state):
        result['sqlstate'] = state
    return result


def attempt(call):
    try:
        return {'status': 'READ', 'value': call()}
    except Exception as exc:
        return {'status': 'READ_FAILED', 'failure': safe_failure(exc)}


def source_inventory(project):
    digest = hashlib.sha256(); count = 0; names = set()
    for folder in ('p24_foundation', 'tools', 'review_ui', 'catalogs'):
        for path in sorted((project / folder).rglob('*')):
            if not path.is_file() or path.suffix not in ('.py', '.html', '.css', '.js', '.json', '.csv') or '__pycache__' in path.parts:
                continue
            if not path.resolve().is_relative_to(project):
                raise ValueError('source_outside_project')
            data = path.read_bytes()
            digest.update(path.relative_to(project).as_posix().encode() + b'\0')
            digest.update(hashlib.sha256(data).digest()); count += 1
            if path.suffix == '.py':
                names.update(n.lower() for n in SQL_NAME.findall(data.decode('utf-8-sig')))
    for name in tuple(names):
        if name.startswith('viewer_'):
            names.add('viewer_stage_' + name.removeprefix('viewer_'))
            names.add('viewer_build_' + name.removeprefix('viewer_'))
    helpers = {}
    for name in ('Start_Viewer.cmd', 'viewer_performance/Run_Viewer_Memory.py', 'viewer_performance/viewer.ps1'):
        path = project / name
        if path.is_file():
            helpers[name] = attempt(lambda path=path: hashlib.sha256(path.read_bytes()).hexdigest())
    return {'runtime_sha256': digest.hexdigest(), 'runtime_files': count,
        'viewer_data_sha256': hashlib.sha256((project / 'p24_foundation/viewer_data.py').read_bytes()).hexdigest(),
        'launcher_file_sha256': helpers}, names


def statement_summary(statement, allowed_names):
    cleaned = re.sub(r'\s+', ' ', SQL_NUMBER.sub('?', SQL_LITERAL.sub('?', statement or ''))).strip().lower()
    operation = SQL_OPERATION.match(cleaned)
    return {'fingerprint': hashlib.sha256(cleaned.encode()).hexdigest()[:16],
        'operation': operation.group(1).upper() if operation else 'OTHER',
        'relations': sorted(set(SQL_NAME.findall(cleaned)) & allowed_names)[:12]}


def activity_rows(rows, allowed_names):
    output = []
    for raw in rows[:128]:
        # application_name is client-supplied: classify it, never copy it.
        app = str(raw.get('application_name') or '')
        role = ('VIEWER_PUBLISHER' if raw.get('viewer_singleton_owner') else
            'AD' if app.startswith('AnomalyDetection.') else
            'VIEWER_WRITER' if raw.get('viewer_write_lock_owner') else 'OTHER')
        item = {key: raw.get(key) for key in ('pid', 'backend_type', 'state',
            'wait_event_type', 'wait_event', 'query_age_seconds', 'transaction_age_seconds',
            'blocking_pids', 'viewer_singleton_owner', 'viewer_write_lock_owner')}
        item['workload'] = role
        # For an idle session pg_stat_activity.query is its *last* statement.
        # Do not attribute that SQL or query_age to active work.
        if raw.get('state') == 'active':
            item['statement'] = statement_summary(raw.get('query'), allowed_names)
        output.append(item)
    return {'sessions': output, 'truncated': len(rows) > 128}


def connection_parameters(database):
    if database.get('dbname') != 'p24_design_viewer':
        raise ValueError('only_p24_design_viewer_allowed')
    result = dict(database)
    for key in ('options', 'autocommit', 'row_factory', 'application_name'):
        result.pop(key, None)
    result.update(connect_timeout=3, application_name=APP, options=
        '-c default_transaction_read_only=on -c statement_timeout=2000 '
        '-c lock_timeout=100 -c idle_in_transaction_session_timeout=5000 '
        '-c search_path=pg_catalog -c jit=off -c max_parallel_workers_per_gather=0 -c work_mem=2MB')
    return result


class Reader:
    def __init__(self, connection):
        self.connection = connection

    def rows(self, statement, parameters=()):
        # All statements are static SELECTs, including the guard itself.
        if not statement.lstrip().startswith('SELECT '):
            raise ValueError('only_select_allowed')
        with self.connection.cursor() as cursor:
            cursor.execute(statement, parameters)
            return [dict(row) for row in cursor.fetchall()]

    def optional(self, statement, parameters=()):
        return attempt(lambda: self.rows(statement, parameters))


def ns_iso(value):
    if type(value) is not int:
        return None
    return datetime.fromtimestamp(value / SECOND_NS, timezone.utc).isoformat()


def state_summary(rows, observed_ns):
    if not rows:
        return None
    value = dict(rows[0])
    closed = (observed_ns - value['lag_seconds'] * SECOND_NS) // FIVE_NS * FIVE_NS
    value.update(next_utc=ns_iso(value['next_ns']),
        backlog_windows=max(0, (closed - value['next_ns']) // FIVE_NS))
    return value


def receipt_summary(rows, backlog=None):
    # One receipt per distinct window; duplicate forwards must not inflate rate.
    windows = {}
    for row in rows:
        if row['mode'] == 'forward' and row['end_ns'] - row['start_ns'] == FIVE_NS:
            old = windows.get(row['start_ns'])
            if old is None or row['published_ns'] > old['published_ns']:
                windows[row['start_ns']] = row
    ordered = sorted(windows.values(), key=lambda row: row['start_ns'])
    result = {'sample_windows': len(ordered), 'arrival_windows_per_hour': 12,
        'throughput_status': 'INSUFFICIENT_RECEIPTS', 'estimated_catchup_hours': None,
        'basis': 'HISTORICAL_RECEIPTS_MAY_SPAN_RELEASES',
        'publisher_timer_excludes_commit': True}
    if not ordered:
        return result
    elapsed = [float(row['elapsed_seconds']) for row in ordered]
    result.update(publish_mean_seconds=round(statistics.mean(elapsed), 3),
        publish_median_seconds=round(statistics.median(elapsed), 3),
        capture_mean_seconds=round(statistics.mean(float(row['capture_seconds']) for row in ordered), 3),
        sample_from_utc=ns_iso(ordered[0]['start_ns']), sample_to_utc=ns_iso(ordered[-1]['end_ns']))
    contiguous = all(a['end_ns'] == b['start_ns'] for a, b in zip(ordered, ordered[1:]))
    advancing = all(a['published_ns'] < b['published_ns'] for a, b in zip(ordered, ordered[1:]))
    span = (ordered[-1]['published_ns'] - ordered[0]['published_ns']) / SECOND_NS
    if len(ordered) < 2 or not contiguous or not advancing or span <= 0:
        result['throughput_status'] = 'INSUFFICIENT_RECEIPTS' if len(ordered) < 2 else 'NONCONTIGUOUS_RECEIPTS'
        return result
    rate = (len(ordered) - 1) * 3600 / span
    result.update(observed_forward_windows_per_hour=round(rate, 3),
        observation_span_seconds=round(span, 3),
        throughput_status='HISTORICAL_SAMPLE_CAN_CATCH_UP' if rate > 12 else 'HISTORICAL_SAMPLE_CANNOT_CATCH_UP',
        net_catchup_windows_per_hour=round(rate - 12, 3))
    if rate > 12 and type(backlog) is int:
        result['estimated_catchup_hours'] = round(backlog / (rate - 12), 2)
    return result


def counter_deltas(before, after):
    result = {}
    for name in COUNTERS:
        a = before.get(name, {}); b = after.get(name, {})
        if a.get('status') != 'READ' or b.get('status') != 'READ' or not a['value'] or not b['value']:
            continue
        left, right = a['value'][0], b['value'][0]
        if left.get('stats_reset') != right.get('stats_reset'):
            result[name] = {'status': 'STATS_RESET'}
            continue
        values = {}
        for key, value in right.items():
            old = left.get(key)
            if key != 'stats_reset' and isinstance(value, (int, float)) and isinstance(old, (int, float)):
                values[key] = round(value - old, 3) if value >= old else None
            elif key != 'stats_reset' and hasattr(value, 'as_tuple') and hasattr(old, 'as_tuple'):
                values[key] = float(value - old) if value >= old else None
        result[name] = {'status': 'DELTA', 'values': values}
    return result


def ad_counter_deltas(before,after,seconds,*,stats_reset=False):
    if stats_reset:return {'status':'STATS_RESET'}
    if before.get('status')!='READ' or after.get('status')!='READ':return {'status':'COUNTERS_UNAVAILABLE'}
    old={row['relname']:row for row in before['value']};result={}
    for row in after['value']:
        name=row['relname'];previous=old.get(name)
        if previous is None:continue
        values={key:row[key]-previous[key] for key in
            ('n_tup_ins','n_tup_upd','n_tup_del','n_tup_hot_upd','seq_scan','idx_scan','autovacuum_count')
            if type(row.get(key)) is int and type(previous.get(key)) is int}
        if any(value<0 for value in values.values()):result[name]={'status':'STATS_RESET_OR_OBJECT_REPLACED'};continue
        result[name]={'status':'DELTA','values':values,
            'updates_per_second':round(values.get('n_tup_upd',0)/max(seconds,.001),3),
            'estimated_live_rows':row['n_live_tup'],'estimated_dead_rows':row['n_dead_tup']}
    return {'status':'DELTA','observation_seconds':round(seconds,3),'tables':result,
            'counts_are_row_mutations_not_unique_jobs_or_sql_calls':True}


def collect(reader, *, seconds, allowed_names, clock=time.monotonic, wall=time.time_ns, wait=time.sleep, progress=lambda _: None):
    guard = reader.rows("SELECT current_database() AS database,current_setting('transaction_read_only') AS read_only")
    if not guard or guard[0] != {'database': 'p24_design_viewer', 'read_only': 'on'}:
        raise ValueError('read_only_database_guard_failed')
    started = clock()
    report = {'probe': PROBE, 'database_guard': guard[0], 'database_modified': False,
        'workers_restarted': False, 'checkpoint_seek_performed': False,
        'observer_session_settings': reader.optional('SELECT name,setting,reset_val,unit,source,pending_restart FROM pg_catalog.pg_settings WHERE name=ANY(%s) ORDER BY name', (list(SETTINGS),)),
        'table_inventory': reader.optional(TABLES_SQL), 'index_inventory': reader.optional(INDEXES_SQL),
        'counters_before': {name: reader.optional(sql) for name, sql in COUNTERS.items()}, 'samples': [],
        'limitations': ['Activity samples are not query execution timings; short statements can be missed.',
            'Other-role SQL may be hidden by PostgreSQL permissions; unavailable is not idle.',
            'Relation counts are PostgreSQL estimates, not exact evidence totals or a bloat measurement.',
            'WAL/checkpointer/pg_stat_io counters cover the cluster; database counters include Viewer, AD and other clients.',
            'I/O time counters require the corresponding PostgreSQL timing setting; zero is not proof of fast storage.',
            'Source hashes describe installed files, not already-imported code in a running process.',
            'pg_settings describes this observer session; publisher memory/JIT overrides are not observable here.',
            'Receipt rates are historical samples, not a sustained capacity qualification.',
            'No SQL, parameters, application names, credentials or user evidence are exported.']}
    report['ad_counters_before']=reader.optional(AD_COUNTERS_SQL);ad_started=clock()
    deadline = clock() + seconds
    next_progress = clock() + 15
    while True:
        at = wall()
        state = reader.optional(STATE_SQL)
        activity = attempt(lambda: activity_rows(reader.rows(ACTIVITY_SQL), allowed_names))
        report['samples'].append({'observed_ns': at, 'observed_utc': ns_iso(at),
            'elapsed_seconds': round(clock() - started, 3), 'viewer_state': state,
            'activity': activity})
        if clock() >= deadline:
            break
        if clock() >= next_progress:
            progress({'status': 'OBSERVING', 'elapsed_seconds': round(clock() - started, 1)})
            next_progress = clock() + 15
        wait(min(3, max(0, deadline - clock())))
    report['counters_after'] = {name: reader.optional(sql) for name, sql in COUNTERS.items()}
    report['counter_deltas'] = counter_deltas(report['counters_before'], report['counters_after'])
    report['ad_counters_after']=reader.optional(AD_COUNTERS_SQL)
    report['ad_counter_deltas']=ad_counter_deltas(report['ad_counters_before'],report['ad_counters_after'],clock()-ad_started,
        stats_reset=report['counter_deltas'].get('database',{}).get('status')=='STATS_RESET')
    report['recent_forward_receipts'] = reader.optional(RECEIPTS_SQL)
    report['recent_resume_records'] = reader.optional(RESUMES_SQL)
    latest = report['samples'][-1]
    state = state_summary(latest['viewer_state']['value'], latest['observed_ns']) if latest['viewer_state']['status'] == 'READ' else None
    report['latest_viewer_state'] = state
    receipts = report['recent_forward_receipts']
    report['throughput'] = receipt_summary(receipts['value'], state['backlog_windows'] if state else None) if receipts['status'] == 'READ' else {'throughput_status': 'RECEIPTS_UNAVAILABLE'}
    waits = Counter(); fingerprints = Counter(); publisher_seen = set(); visibility = Counter()
    for sample in report['samples']:
        if sample['activity']['status'] != 'READ':
            continue
        for session in sample['activity']['value']['sessions']:
            if session['workload'] != 'VIEWER_PUBLISHER':
                continue
            publisher_seen.add(session['pid'])
            visibility[session.get('state') or 'UNAVAILABLE'] += 1
            if session.get('state') == 'active':
                waits[(session.get('wait_event_type') or 'none') + '/' + (session.get('wait_event') or 'none')] += 1
                statement = session.get('statement', {})
                fingerprints[statement.get('fingerprint', 'UNAVAILABLE')] += 1
    report['publisher_observation'] = {'pids_seen': sorted(publisher_seen), 'state_sample_counts': dict(visibility),
        'active_wait_sample_counts': dict(waits), 'active_fingerprint_sample_counts': dict(fingerprints)}
    failures = sum(1 for x in report.values() if isinstance(x, dict) and x.get('status') == 'READ_FAILED')
    failures += sum(1 for sample in report['samples'] for key in ('viewer_state', 'activity') if sample[key]['status'] == 'READ_FAILED')
    failures += sum(1 for key in ('counters_before', 'counters_after') for value in report[key].values() if value['status'] == 'READ_FAILED')
    report.update(status='PARTIAL_READ_ONLY_OBSERVATION' if failures else 'READ_ONLY_OBSERVATION_EXPORTED',
        read_failures=failures, elapsed_seconds=round(clock() - started, 3),
        production_capacity_acceptance='NOT_ASSIGNED_BY_OBSERVER')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', required=True, type=Path)
    parser.add_argument('--seconds', type=int, default=60)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    if not 3 <= args.seconds <= 300:
        parser.error('--seconds must be 3..300')
    project = args.project.resolve(); root = project / 'AnomalyDetection'
    try:
        launcher = runpy.run_path(str(root / 'run_anomaly.py'))
        ad_sha = launcher['verify_build']()
        sys.path.insert(0, str(root)); sys.meta_path.insert(0, launcher['VerifiedApplicationFinder']())
        from anomaly_detection.pg_source import read_database_config
        database = read_database_config(project / 'viewer_config.local.py')
        inventory = attempt(lambda: source_inventory(project))
        allowed_names = inventory['value'][1] if inventory['status'] == 'READ' else set()
        import psycopg
        from psycopg.rows import dict_row
        with psycopg.connect(**connection_parameters(database), autocommit=True, row_factory=dict_row) as conn:
            report = collect(Reader(conn), seconds=args.seconds, allowed_names=allowed_names,
                progress=lambda value: print(json.dumps(value), flush=True))
        report['installed_source'] = {'status': 'READ', 'value': inventory['value'][0]} if inventory['status'] == 'READ' else inventory
        report['installed_ad_build'] = launcher['EXPECTED_BUILD']
        report['installed_ad_source_sha256'] = ad_sha
        status_file=root/'reports/product_status.json'
        if status_file.is_file():
            def owned_progress():
                value=json.loads(status_file.read_text(encoding='utf-8-sig'))
                return {key:value.get(key) for key in ('build_id','source_sha256','state','phase','heartbeat_ns',
                    'evaluated_jobs','audited_requests','scenario_evaluations','scenario_results','scenario_queue_activity','viewer_admission')}
            report['ad_owned_progress']=attempt(owned_progress)
        startup=project/'validation/viewer_startup.json'
        if startup.is_file():
            def read_startup():
                value=json.loads(startup.read_text(encoding='utf-8-sig'))
                return {key:value.get(key) for key in ('pid','mode','runtime_source_sha256','started_at_utc')}
            report['viewer_startup_receipt']=attempt(read_startup)
            if report['viewer_startup_receipt']['status']=='READ_FAILED':
                report['status']='PARTIAL_READ_ONLY_OBSERVATION'
                report['read_failures']+=1
        if inventory['status'] != 'READ':
            report['status'] = 'PARTIAL_READ_ONLY_OBSERVATION'
            report['read_failures'] += 1
        output = args.output or root / 'reports' / ('Viewer_Live_Performance_' + datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_') + uuid.uuid4().hex[:8] + '.json')
        output = output.resolve(); output.parent.mkdir(parents=True, exist_ok=True)
        with output.open('x', encoding='utf-8') as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2, default=str); stream.write('\n')
        print(json.dumps({'status': report['status'], 'output': str(output),
            'database_modified': False, 'workers_restarted': False}))
        return 0
    except Exception as exc:
        print(json.dumps({'status': 'READ_ONLY_OBSERVATION_FAILED', 'failure': safe_failure(exc)}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
