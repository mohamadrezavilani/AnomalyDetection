"""One-off compaction of old Viewer payloads, with a durable receipt."""
from contextlib import contextmanager
import ast
import json
import time
from pathlib import Path
import uuid

from . import FIVE_NS, SOURCE_SHA
from .history_reset import check_links, measured_free_space
from .history_scope import INPUT_LOCK, STATE_KEY, WRITER_LOCK
from .pg_source import installed_source_identity, read_database_config
from .snapshot import require

RAW_COLUMNS = {
    'viewer_raw_events': ('origin_key', 'version_key', 'raw_request_id',
                          'raw_session_id', 'raw_ip', 'payload'),
    'viewer_capture_projections': ('origin_key', 'capture_key', 'canonical_version_key',
                                   'file_hash', 'filename', 'row_number', 'payload'),
}
RECEIPT_KEY = 'viewer_raw_compaction_v1'
GIB = 1024**3
PROFILE_SHA = 'c424ee92b38838d05e3ff343fab25855bbc06b89d01a4e378f172e3dd466babf'


@contextmanager
def viewer_database(project):
    import psycopg
    from psycopg.rows import dict_row

    params = read_database_config(Path(project) / 'viewer_config.local.py')
    hosts = (params.get('host'), params.get('hostaddr'))
    require(all(host is None or host in ('', 'localhost', '127.0.0.1', '::1') for host in hosts),
            'LOCAL_VIEWER_POSTGRESQL_REQUIRED')
    params = {k: v for k, v in params.items()
              if k in ('dbname', 'host', 'hostaddr', 'port', 'user', 'password', 'sslmode')}
    params['host'] = params.get('host') or 'localhost'
    with psycopg.connect(**params, connect_timeout=5, autocommit=True, row_factory=dict_row,
                         application_name='P24.JointRawMaintenance',
                         options='-c default_transaction_read_only=on -c statement_timeout=10000 '
                                 '-c lock_timeout=1000 -c synchronous_commit=on') as raw:
        require(raw.execute('SELECT current_database() AS name').fetchone()['name']=='p24_design_viewer',
                'ONLY_P24_DESIGN_VIEWER_ALLOWED')
        yield raw


def verify_viewer(project):
    import hashlib

    identity = installed_source_identity(project)
    require(identity['runtime_sha256'] == SOURCE_SHA, 'VIEWER_RUNTIME_MISMATCH')
    profile = Path(project) / 'viewer_performance/Run_Viewer_Memory.py'
    require(profile.is_file() and profile.resolve().is_relative_to(Path(project).resolve()) and
            hashlib.sha256(profile.read_bytes()).hexdigest() == PROFILE_SHA,
            'VIEWER_MEMORY_PROFILE_MISMATCH')
    tree = ast.parse((Path(project) / 'p24_foundation/viewer_contract.py').read_text(encoding='utf-8'))
    matches = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
               and any(isinstance(t, ast.Name) and t.id == 'CONTRACT_PATTERNS' for t in node.targets)]
    require(len(matches)==1 and isinstance(matches[0], tuple) and matches[0] and
            all(isinstance(p,str) and p for p in matches[0]), 'VIEWER_CONTRACT_PATTERNS_UNKNOWN')
    return identity, matches[0]


def db_identity(raw):
    return dict(raw.execute(
        'SELECT current_database() AS db,pg_postmaster_start_time() AS started,'
        "current_setting('port') AS port,oid::bigint AS oid "
        'FROM pg_database WHERE datname=current_database()').fetchone())


def state(raw, name):
    row = raw.execute('SELECT body FROM anomaly_detection.adp_state WHERE name=%s',(name,)).fetchone()
    return json.loads(row['body']) if row else {}


def scope_status(raw, cutoff):
    live = raw.execute(
        'SELECT l.next_ns,l.generation,l.stream_key,l.keys_fingerprint,l.last_error,l.overlap_windows,l.lag_seconds,'
        's.state AS semantic_state,s.generation AS semantic_generation '
        'FROM public.viewer_live_state l CROSS JOIN public.viewer_semantic_checkpoint s '
        'WHERE l.id=1 AND s.id=1').fetchone()
    require(live and live['semantic_state']=='ready' and live['generation']>0 and
            live['semantic_generation']==live['generation'], 'VIEWER_PROJECTION_NOT_READY')
    binding = state(raw,'source_binding')
    require(binding.get('namespace')=='viewer:'+live['stream_key'] and
            binding.get('keys_fingerprint')==live['keys_fingerprint'],
            'VIEWER_STREAM_DIFFERS_FROM_AD')
    require(state(raw,STATE_KEY).get('start_ns')==cutoff, 'AD_HISTORY_BOUNDARY_MISMATCH')
    # The existing launcher can resume without seeking to a new cursor.
    require(live['next_ns']>=cutoff, 'VIEWER_CHECKPOINT_BEFORE_REQUESTED_DAY')
    row = raw.execute('SELECT start_ns,end_ns FROM public.viewer_live_windows '
                      'WHERE start_ns>=%s AND start_ns<=%s AND end_ns=start_ns+%s '
                      'ORDER BY start_ns DESC LIMIT 1',
                      (cutoff,live['next_ns']-FIVE_NS,FIVE_NS)).fetchone()
    return {'viewer_checkpoint_ns':live['next_ns'], 'viewer_generation':live['generation'],
            'latest_published_window_end_ns':row['end_ns'] if row else None,
            'viewer_has_error':bool(live['last_error']),
            'overlap_windows':live['overlap_windows'],'lag_seconds':live['lag_seconds']}


def raw_tables(raw):
    rows = raw.execute(
        'SELECT c.oid::bigint AS oid,c.relname AS name,pg_total_relation_size(c.oid) AS bytes,'
        'c.relkind,c.relpersistence,c.relrowsecurity,pg_has_role(c.relowner,\'USAGE\') AS owned,'
        'ARRAY(SELECT a.attname::text FROM pg_attribute a WHERE a.attrelid=c.oid '
        'AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum) AS columns '
        'FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace '
        "WHERE n.nspname='public' AND c.relname=ANY(%s) ORDER BY c.relname",
        (list(RAW_COLUMNS),)).fetchall()
    require({row['name'] for row in rows}==set(RAW_COLUMNS), 'VIEWER_RAW_TABLES_MISSING')
    require(all(row['relkind']=='r' and row['relpersistence']=='p' and row['owned']
                and not row['relrowsecurity'] and tuple(row['columns'])==RAW_COLUMNS[row['name']]
                for row in rows), 'VIEWER_RAW_LAYOUT_MISMATCH')
    require(not raw.execute("SELECT 1 FROM pg_publication_tables WHERE schemaname='public' "
                            "AND tablename=ANY(%s) LIMIT 1",(list(RAW_COLUMNS),)).fetchone(),
            'VIEWER_RAW_TABLE_IS_PUBLISHED')
    check_links(raw, rows)
    return {row['name']:row['bytes'] for row in rows}


def keep_origins(raw, cutoff, patterns):
    raw.execute('CREATE TEMP TABLE p24_keep_request ON COMMIT DROP AS '
                'SELECT request_key FROM public.viewer_requests '
                'WHERE started_ns>=%s OR ended_ns>=%s OR root_ns>=%s UNION '
                'SELECT request_key FROM public.viewer_events WHERE at_ns>=%s '
                'AND request_key IS NOT NULL',(cutoff,cutoff,cutoff,cutoff))
    raw.execute('CREATE UNIQUE INDEX ON p24_keep_request(request_key)')
    raw.execute('ANALYZE p24_keep_request')
    raw.execute('CREATE TEMP TABLE p24_keep_origin(origin_key TEXT PRIMARY KEY) ON COMMIT DROP')
    raw.execute('INSERT INTO pg_temp.p24_keep_origin '
                'SELECT origin_key FROM public.viewer_events WHERE at_ns>=%s OR at_ns IS NULL '
                'ON CONFLICT DO NOTHING',(cutoff,))
    raw.execute('INSERT INTO pg_temp.p24_keep_origin '
                'SELECT e.origin_key FROM pg_temp.p24_keep_request r JOIN public.viewer_events e USING(request_key) '
                'ON CONFLICT DO NOTHING')
    # Incremental rebuilds can reach old requests via payment closure. Keep
    # their raw contract candidates even if the current projection has no fact.
    raw.execute('INSERT INTO pg_temp.p24_keep_origin SELECT origin_key FROM public.viewer_events '
                'WHERE request_key IS NOT NULL AND callpath LIKE ANY(%s) ON CONFLICT DO NOTHING',
                (list(patterns),))
    raw.execute('ANALYZE p24_keep_origin')


def retention_join(table):
    version = 'version_key' if table=='viewer_raw_events' else 'canonical_version_key'
    return (f'FROM public.{table} b LEFT JOIN public.viewer_events e '
            f'ON e.origin_key=b.origin_key AND e.version_key=b.{version} '
            'LEFT JOIN pg_temp.p24_keep_origin k ON k.origin_key=b.origin_key')


def compact(raw, root, cutoff, patterns, *, pg_data_dir=None, progress=None, fault=None):
    """The caller holds all three AD process locks and has stopped Viewer."""
    progress = progress or (lambda stage: None)
    report = {}
    with raw.transaction():
        raw.execute('SET TRANSACTION READ WRITE')
        raw.execute("SET LOCAL statement_timeout='20min'")
        raw.execute("SET LOCAL temp_tablespaces=''")
        raw.execute("SET LOCAL work_mem='64MB'")
        for sql, args in (
            ('SELECT pg_try_advisory_xact_lock(240026,%s) AS ok',(1,)),
            ('SELECT pg_try_advisory_xact_lock(240026,%s) AS ok',(2,)),
            ('SELECT pg_try_advisory_xact_lock(%s) AS ok',(WRITER_LOCK,)),
            ('SELECT pg_try_advisory_xact_lock(%s) AS ok',(INPUT_LOCK,)),
        ):
            require(raw.execute(sql,args).fetchone()['ok'], 'VIEWER_OR_AD_WRITER_STILL_ACTIVE')
        # Acquire locks in the application's writer order before inspecting
        # either retention membership or constraints on the two payload tables.
        raw.execute('LOCK TABLE ONLY public.viewer_events,ONLY public.viewer_requests,'
                    'ONLY public.viewer_live_state,ONLY public.viewer_live_windows,'
                    'ONLY public.viewer_semantic_checkpoint IN SHARE MODE NOWAIT')
        raw.execute('LOCK TABLE ONLY anomaly_detection.adp_state IN SHARE ROW EXCLUSIVE MODE NOWAIT')
        raw.execute('LOCK TABLE ONLY public.viewer_raw_events,ONLY public.viewer_capture_projections '
                    'IN ACCESS EXCLUSIVE MODE NOWAIT')
        before = raw_tables(raw)
        scope = scope_status(raw,cutoff)
        closed=(time.time_ns()-scope['lag_seconds']*10**9)//FIVE_NS*FIVE_NS
        require(closed-scope['overlap_windows']*FIVE_NS>=cutoff, 'VIEWER_OVERLAP_STILL_CROSSES_BOUNDARY')
        old = state(raw,RECEIPT_KEY)
        require(cutoff>=old.get('cutoff_ns',0), 'VIEWER_RAW_BOUNDARY_CANNOT_MOVE_BACKWARD')
        if old.get('cutoff_ns')==cutoff:
            return dict(old,status='VIEWER_RAW_ALREADY_APPLIED',scope=scope)
        progress('plan_viewer_raw_retention')
        disk = measured_free_space(raw,root,pg_data_dir,True)
        require(disk['postgresql_min_free_bytes'] is not None, 'VERIFY_LOCAL_POSTGRESQL_DATA_DIRECTORY')
        require(min(disk.values())>=2*GIB, 'INSUFFICIENT_VIEWER_RAW_DISK_HEADROOM')
        keep_origins(raw,cutoff,patterns)
        keep = 'e.at_ns IS NULL OR k.origin_key IS NOT NULL'
        counts = {}
        for table in RAW_COLUMNS:
            counts[table] = dict(raw.execute(
                'SELECT COUNT(*) AS rows,COUNT(*) FILTER (WHERE '+keep+') AS kept_rows,'
                'COALESCE(SUM(octet_length(b.payload)::bigint) FILTER (WHERE '+keep+'),0)::bigint AS kept_body_bytes '
                +retention_join(table)).fetchone())
        retained = sum(row['kept_body_bytes']+1024*row['kept_rows'] for row in counts.values())
        required = 2*GIB + 4*retained
        report.update(cutoff_ns=cutoff,scope=scope,counts=counts,raw_relation_bytes_before=before,
                      database_bytes_before=raw.execute('SELECT pg_database_size(current_database()) AS bytes').fetchone()['bytes'],
                      preflight_disk=disk,preflight_free_bytes_required=required)
        if all(row['rows']==row['kept_rows'] for row in counts.values()):
            return dict(report,status='NO_OLD_VIEWER_RAW_TO_REMOVE')
        available = measured_free_space(raw,root,pg_data_dir,True)
        if available['postgresql_min_free_bytes'] is None or min(available.values())<required:
            return dict(report,status='VIEWER_RAW_BLOCKED_DISK_HEADROOM',verified_disk=available)
        for table, columns in RAW_COLUMNS.items():
            if counts[table]['kept_rows']:
                progress('copy_retained_'+table)
                column_sql = ','.join('b.'+c for c in columns)
                result = raw.execute(f'CREATE TEMP TABLE keep_{table} ON COMMIT DROP AS '
                                     f'SELECT {column_sql} '+retention_join(table)+' WHERE '+keep)
                require(result.rowcount==counts[table]['kept_rows'], 'VIEWER_RAW_STAGE_COUNT_MISMATCH')
        available = measured_free_space(raw,root,pg_data_dir,True)
        require(available['postgresql_min_free_bytes'] is not None and
                min(available.values())>=2*GIB+2*retained, 'VIEWER_RAW_STAGE_DISK_HEADROOM')
        progress('replace_viewer_raw_tables')
        raw.execute('TRUNCATE TABLE ONLY public.viewer_raw_events,ONLY public.viewer_capture_projections '
                    'CONTINUE IDENTITY RESTRICT')
        if fault:
            fault()
        for table, columns in RAW_COLUMNS.items():
            if counts[table]['kept_rows']:
                names=','.join(columns)
                result=raw.execute(f'INSERT INTO public.{table} ({names}) SELECT {names} FROM pg_temp.keep_{table}')
                require(result.rowcount==counts[table]['kept_rows'], 'VIEWER_RAW_RESTORE_COUNT_MISMATCH')
        require(scope_status(raw,cutoff)==scope, 'VIEWER_CHECKPOINT_CHANGED_DURING_RAW_COMPACTION')
        after = raw_tables(raw)
        report.update(status='VIEWER_RAW_APPLIED',operation_id=uuid.uuid4().hex,raw_relation_bytes_after=after,
                      raw_relation_bytes_reclaimed=sum(before.values())-sum(after.values()))
        raw.execute('INSERT INTO anomaly_detection.adp_state(name,body) VALUES(%s,%s) '
                    'ON CONFLICT(name) DO UPDATE SET body=excluded.body',(RECEIPT_KEY,json.dumps(report)))
        progress('commit_viewer_raw_compaction')
    try:
        report['database_bytes_after']=raw.execute('SELECT pg_database_size(current_database()) AS bytes').fetchone()['bytes']
        report['disk_after']=measured_free_space(raw,root,pg_data_dir,True)
    except Exception:
        # The durable receipt remains authoritative if a measurement fails.
        report['post_commit_measurement']='INCOMPLETE'
    return report
