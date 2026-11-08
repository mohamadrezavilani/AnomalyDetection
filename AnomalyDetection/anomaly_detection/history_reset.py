"""Explicit, transactional AD history reset with bounded retained data."""
from contextlib import ExitStack
from datetime import date, datetime, time, timezone
from pathlib import Path
import os
import shutil

from . import FIVE_NS
from .history_scope import INPUT_LOCK, STATE_KEY, WRITER_LOCK, load_floor
from .process_control import OwnedProcessLock, read_json
from .product_store import ProductStore
from .snapshot import require
from .temporal import TIMEZONE

# An explicit list is intentional: neither a prefix nor catalog membership
# confers permission to truncate an unknown relation.
TABLES = (
    'adp_case_feedback', 'adp_case_lifecycle', 'adp_case_requests', 'adp_case_signals',
    'adp_case_versions', 'adp_cases', 'adp_contexts', 'adp_evidence_ready', 'adp_facts',
    'adp_feedback', 'adp_finding_versions', 'adp_findings', 'adp_http_reference_calls',
    'adp_http_reference_sets', 'adp_incidents', 'adp_jobs', 'adp_journeys', 'adp_model_queue',
    'adp_models', 'adp_peer_dependencies', 'adp_peer_epochs', 'adp_peer_versions', 'adp_peers',
    'adp_population', 'adp_population_jobs', 'adp_profile_scope_members', 'adp_profile_scopes',
    'adp_profile_tasks', 'adp_profile_versions', 'adp_profiles', 'adp_reference_cases',
    'adp_scenario_jobs', 'adp_service_profile_samples', 'adp_service_reference_points',
    'adp_service_reference_scopes', 'adp_service_sample_members', 'adp_source_windows',
    'adp_state', 'adp_traffic_counts', 'adp_traffic_members', 'adp_traffic_staging',
    'adp_versions', 'adp_viewer_relations', 'adp_window_members', 'adp_window_staging',
    'adp_window_versions', 'adp_windows',
)
PRESERVE = {
    'adp_facts': 'request_key,anchor_key,session_key,at_ns,service_path,kind,state,revision,'
                 'eligible,source_present,body,content_digest,details,details_digest,last_seen_ns',
    'adp_profiles': 'request_key,session_key,service_path,at_ns,body,content_digest,observed_ns',
}
# A current case or human review is not a discardable cache. Stop before
# changing anything if a reset would remove a case/review in the retained period.
PROTECT = {
    'adp_cases': 'last_ns IS NULL OR last_ns >= %s',
    'adp_case_signals': 'end_ns > %s',
    'adp_case_feedback': 'created_ns >= %s',
    'adp_feedback': 'created_ns >= %s',
    'adp_incidents': 'target_ns >= %s',
    'adp_findings': 'target_ns >= %s',
}
MAX_KEEP_ROWS = 100_000
MIB = 1024 * 1024
MAX_KEEP_BYTES = 64 * MIB


def tehran_boundary(value):
    try:
        day = date.fromisoformat(value)
    except ValueError:
        require(False, 'INVALID_TEHRAN_HISTORY_START_DATE')
    require(day.isoformat() == value and day <= datetime.now(TIMEZONE).date(),
            'INVALID_TEHRAN_HISTORY_START_DATE')
    start = datetime.combine(day, time.min, TIMEZONE)
    ns = int(start.timestamp()) * 1_000_000_000
    require(ns > 0 and ns % FIVE_NS == 0, 'UNALIGNED_TEHRAN_HISTORY_START')
    return start, ns


def inventory(raw, tag):
    namespace = raw.execute(
        "SELECT obj_description(n.oid,'pg_namespace') AS tag, "
        "n.nspowner = (SELECT oid FROM pg_roles WHERE rolname=current_user) AS owned "
        "FROM pg_namespace n WHERE n.nspname='anomaly_detection'"
    ).fetchone()
    require(namespace and namespace['owned'] and namespace['tag'] == tag,
            'OWNED_POSTGRES_SCHEMA_NAME_COLLISION')
    rows = raw.execute(
        "SELECT c.oid::bigint AS oid,c.relname AS name,c.relkind,"
        "c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user) AS owned,"
        "c.relpersistence,c.relrowsecurity,COALESCE(pg_total_relation_size(c.oid),0) AS bytes,"
        "GREATEST(0,c.reltuples)::bigint AS estimated_rows "
        "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname='anomaly_detection' AND c.relkind IN ('r','p','f','m','v') "
        "ORDER BY c.relname"
    ).fetchall()
    product = [r for r in rows if r['name'].startswith('adp_')]
    require({r['name'] for r in product} == set(TABLES), 'HISTORY_RESET_UNEXPECTED_PRODUCT_LAYOUT')
    require(all(r['owned'] and r['relkind'] == 'r' and r['relpersistence'] == 'p'
                and not r['relrowsecurity'] for r in product), 'HISTORY_RESET_UNSAFE_PRODUCT_TABLE')
    return product, [r for r in rows if r['name'] not in TABLES]


def check_links(raw, product):
    oids = [r['oid'] for r in product]
    row = raw.execute(
        "SELECT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid::bigint=ANY(%s)) AS triggers,"
        "EXISTS(SELECT 1 FROM pg_constraint WHERE contype='f' "
        "AND (conrelid::bigint=ANY(%s) OR confrelid::bigint=ANY(%s))) AS foreign_keys,"
        "EXISTS(SELECT 1 FROM pg_inherits WHERE inhrelid::bigint=ANY(%s) "
        "OR inhparent::bigint=ANY(%s)) AS inheritance,"
        "EXISTS(SELECT 1 FROM pg_rewrite WHERE ev_class::bigint=ANY(%s)) AS rules",
        (oids, oids, oids, oids, oids, oids),
    ).fetchone()
    require(not any(row.values()), 'HISTORY_RESET_UNEXPECTED_TABLE_DEPENDENCY')


def measured_free_space(raw, root, supplied_directory, local_server):
    project_free = shutil.disk_usage(root).free
    info = {'project_free_bytes': project_free, 'postgresql_min_free_bytes': None}
    if not local_server:
        return info
    server = raw.execute(
        "SELECT current_setting('server_version_num')::integer/10000 AS major,"
        "current_setting('port')::integer AS port,"
        "floor(extract(epoch FROM pg_postmaster_start_time()))::bigint AS started,"
        "(SELECT setting FROM pg_settings WHERE name='data_directory') AS data_directory"
    ).fetchone()
    candidates = [supplied_directory] if supplied_directory else [
        server['data_directory'], os.environ.get('PGDATA')
    ]
    if not supplied_directory and os.name == 'nt' and os.environ.get('ProgramFiles'):
        candidates.append(Path(os.environ['ProgramFiles']) / 'PostgreSQL' / str(server['major']) / 'data')
    directory = None
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate).resolve()
        try:
            pidfile = (path / 'postmaster.pid').read_text(encoding='utf-8').splitlines()
            version = (path / 'PG_VERSION').read_text(encoding='ascii').strip()
            if (version == str(server['major']) and int(pidfile[3]) == server['port']
                    and abs(int(pidfile[2]) - server['started']) <= 1):
                directory = path
                break
        except (OSError, UnicodeError, ValueError, IndexError):
            continue
    if directory is None:
        return info
    try:
        # Data, WAL and any external tablespaces used by this database are
        # checked separately. This is a preflight estimate, not reserved space.
        volumes = [directory, (directory / 'pg_wal').resolve()]
        volumes.extend(link.resolve() for link in (directory / 'pg_tblspc').iterdir())
        info['postgresql_min_free_bytes'] = min(shutil.disk_usage(v).free for v in volumes)
    except OSError:
        pass
    return info


def retention_counts(raw, cutoff):
    keep = {}
    for table in PRESERVE:
        length = 'octet_length(body)'
        if table == 'adp_facts':
            length += '+COALESCE(octet_length(details),0)'
        row = raw.execute(
            'SELECT COUNT(*) AS rows, COALESCE(SUM(length),0)::bigint AS body_bytes '
            f'FROM (SELECT {length} AS length FROM anomaly_detection.{table} '
            'WHERE at_ns >= %s LIMIT %s) retained',
            (cutoff, MAX_KEEP_ROWS + 1),
        ).fetchone()
        keep[table] = dict(row)
    return keep


def protect_current(raw, cutoff):
    return [table for table, predicate in PROTECT.items() if raw.execute(
        f'SELECT EXISTS(SELECT 1 FROM anomaly_detection.{table} WHERE {predicate}) AS present',
        (cutoff,),
    ).fetchone()['present']]


def reset_database(raw, root, tag, start, cutoff, *, apply, pg_data_dir=None, local_server=True):
    store = ProductStore(raw)
    with raw.transaction():
        if not apply:
            raw.execute('SET TRANSACTION READ ONLY')
        raw.execute("SET LOCAL statement_timeout = '30s'")
        raw.execute("SET LOCAL temp_tablespaces = ''")
        product, legacy = inventory(raw, tag)
        old_floor = load_floor(store)
        require(cutoff >= old_floor, 'HISTORY_BOUNDARY_CANNOT_MOVE_BACKWARD')
        total_before = sum(r['bytes'] for r in product)
        result = {
            'status': 'HISTORY_RESET_PLAN',
            'start_tehran': start.isoformat(), 'start_utc': start.astimezone(timezone.utc).isoformat(),
            'start_ns': cutoff, 'product_bytes_before': total_before,
            'legacy_ad_bytes': sum(r['bytes'] for r in legacy),
            'database_bytes': raw.execute('SELECT pg_database_size(current_database()) AS bytes').fetchone()['bytes'],
            'largest_product_tables': [
                {key: r[key] for key in ('name', 'bytes', 'estimated_rows')}
                for r in sorted(product, key=lambda row: row['bytes'], reverse=True)[:8]
            ],
        }
        if cutoff == old_floor:
            result['status'] = 'HISTORY_RESET_ALREADY_APPLIED'
            return result
        check_links(raw, product)
        if apply:
            for lease in (WRITER_LOCK, INPUT_LOCK):
                require(raw.execute('SELECT pg_try_advisory_xact_lock(%s) AS acquired',
                                    (lease,)).fetchone()['acquired'], 'AD_WRITER_ACTIVE')
            qualified = ', '.join('ONLY anomaly_detection.' + table for table in TABLES)
            raw.execute('LOCK TABLE ' + qualified + ' IN ACCESS EXCLUSIVE MODE NOWAIT')
            product, _ = inventory(raw, tag)
            check_links(raw, product)
            result['product_bytes_before'] = sum(r['bytes'] for r in product)
        keep = retention_counts(raw, cutoff)
        protected = protect_current(raw, cutoff)
        rows = sum(r['rows'] for r in keep.values())
        body_bytes = sum(r['body_bytes'] for r in keep.values())
        free = measured_free_space(raw, root, pg_data_dir, local_server)
        required = 128 * MIB + 4 * body_bytes + 4096 * rows
        result.update(retained=keep, protected_today=protected,
                      disk=free, preflight_free_bytes_required=required)
        if protected:
            result.update(status='HISTORY_RESET_BLOCKED', reason='PROTECTED_CURRENT_CASES_OR_FEEDBACK')
        elif rows > MAX_KEEP_ROWS or body_bytes > MAX_KEEP_BYTES:
            result.update(status='HISTORY_RESET_BLOCKED', reason='RETAINED_DATA_EXCEEDS_SMALL_COPY_BUDGET')
        elif free['postgresql_min_free_bytes'] is None:
            result.update(status='HISTORY_RESET_BLOCKED', reason='VERIFY_LOCAL_POSTGRESQL_DATA_DIRECTORY')
        elif min(free.values()) < required:
            result.update(status='HISTORY_RESET_BLOCKED', reason='INSUFFICIENT_FREE_DISK_FOR_TRANSACTION')
        if not apply or result['status'] == 'HISTORY_RESET_BLOCKED':
            return result
        # Temp copies contain current fact/profile projections only. All model,
        # coverage, audit and queue caches are rebuilt from the retained day.
        for table, columns in PRESERVE.items():
            if keep[table]['rows']:
                raw.execute(f'CREATE TEMP TABLE keep_{table} ON COMMIT DROP AS '
                            f'SELECT {columns} FROM anomaly_detection.{table} WHERE at_ns >= %s',
                            (cutoff,))
        saved = {name: store.state(name) for name in ('format', 'source_binding', 'source_watermark')}
        require(saved['format'].get('version') == 1, 'PRODUCT_SCHEMA_VERSION_MISMATCH')
        raw.execute('TRUNCATE TABLE ' + qualified + ' CONTINUE IDENTITY RESTRICT')
        for table, columns in PRESERVE.items():
            if keep[table]['rows']:
                raw.execute(f'INSERT INTO anomaly_detection.{table} ({columns}) '
                            f'SELECT {columns} FROM pg_temp.keep_{table}')
        for name, value in saved.items():
            if value:
                store.save_state(name, value)
        store.save_state(STATE_KEY, {'start_ns': cutoff, 'start_tehran': start.isoformat(),
                                     'retained_facts': keep['adp_facts']['rows'],
                                     'retained_profiles': keep['adp_profiles']['rows']})
        store.save_state('counters', {'registered_behaviors': keep['adp_facts']['rows']})
        store.save_state('previous_import', {'done': True, 'skipped': 'AD_HISTORY_BOUNDARY'})
        for name in ('fresh_cursor', 'learning_cursor', 'older_learning_cursor',
                     'service_sample_fresh_cursor', 'service_sample_old_cursor',
                     'scenario_traffic_cursor', 'scenario_old_traffic_cursor'):
            store.save_state(name, {'next_ns': cutoff})
    result['status'] = 'HISTORY_RESET_APPLIED'
    # Reclamation is measured after commit. A failed diagnostic must not make
    # a committed operation look like a failed transaction that needs retrying.
    try:
        after, _ = inventory(raw, tag)
        result['product_bytes_after'] = sum(r['bytes'] for r in after)
        result['product_relation_bytes_reclaimed'] = (
            result['product_bytes_before'] - result['product_bytes_after']
        )
    except Exception:
        result['product_bytes_after'] = None
    return result


def run(root, sha, day, *, apply=False, pg_data_dir=None):
    from .native_pg import database
    root = Path(root).resolve()
    start, cutoff = tehran_boundary(day)
    saved = read_json(root / 'data/pg_credentials.local.json', {})
    installation_id = saved.get('installation_id')
    require(isinstance(installation_id, str) and installation_id, 'POSTGRESQL_CREDENTIALS_NOT_PREPARED')
    connection = saved['connection']
    hosts = (connection.get('host'), connection.get('hostaddr'))
    local = all(host is None or host in ('', '127.0.0.1', '::1', 'localhost') or
                (isinstance(host, str) and host.startswith('/')) for host in hosts)
    with ExitStack() as stack:
        if apply:
            for resource in ('baseline', 'actor', 'web'):
                stack.enter_context(OwnedProcessLock(root, 'history_maintenance', sha, resource=resource))
        raw = stack.enter_context(database(root, readonly=not apply))
        return reset_database(raw, root, 'AnomalyDetection:' + installation_id, start, cutoff,
                              apply=apply, pg_data_dir=pg_data_dir, local_server=local)
