"""Read-only attachment to a schema already installed by the live core.

History never upgrades the live source schema. Even ADD COLUMN IF NOT EXISTS
can request an exclusive table lock and stall unrelated live readers/writers.
Missing columns or an incompatible stream fail closed; migrations belong to
controlled core installation, not background-worker startup or reconnect.
"""
from compact_behavior import CONTRACT, EXTRACTOR, FEATURES, FIVE

SOURCE_COLUMNS = {
    'streams': 'stream_id,contract,extractor,feature_version,start_ns,next_ns,change_epoch',
    'behaviors': 'behavior_id,stream_id,request_id,session_id,observed_at_ns,api,reported_duration,result_code,result_kind,kind,quality,features,content_hash,revision',
    'behavior_payloads': 'behavior_id,state',
    'request_context': 'behavior_id,context',
    'pending_requests': 'behavior_id,stream_id,state,content_hash,first_seen_ns,deadline_ns,updated_at_ns,status',
    'expired_fragments': 'behavior_id,stream_id,expired_at_ns',
    'dirty_windows': 'stream_id,session_id,start_ns,version,processed_version,updated_at_ns',
    'windows': 'stream_id,start_ns,end_ns,source_records,extracted_requests,content_hash,published_at_ns,first_published_ns,revision',
    'queue_counts': 'stream_id,active_pending,expired_pending,dirty_keys',
    'runtime_roles': 'role,token,backend_pid,backend_start,heartbeat_ns,info',
    'reference_cursor': 'stream_id,next_ns,target_ns,overlap_next_ns,overlap_target_ns,last_recheck_ns',
    'window_performance': 'stream_id,role,measured_ns,start_ns,mode,fresh,seconds,source_records,read_seconds,write_seconds,build',
}
HISTORY_COLUMNS = 'job_id,stream_id,from_ns,target_ns,next_ns,state,live_next_at_prepare_ns,published_windows,source_records,created_at_ns,updated_at_ns'


def validate_installed(store, stream, *, history_required=False):
    """Bounded read locks only; session timeouts and schema are left unchanged."""
    s = store.schema  # Store has validated this identifier.
    with store.conn.transaction():
        store.conn.execute('SET TRANSACTION READ ONLY')
        store.conn.execute("SET LOCAL statement_timeout='5s'")
        store.conn.execute("SET LOCAL lock_timeout='1s'")
        for table, columns in SOURCE_COLUMNS.items():
            store.conn.execute(f'SELECT {columns} FROM {s}.{table} LIMIT 0')
        if history_required:
            store.conn.execute(f'SELECT {HISTORY_COLUMNS} FROM {s}.history_jobs LIMIT 0')
        row = store.conn.execute(f'SELECT contract,extractor,feature_version FROM {s}.streams WHERE stream_id=%s', (stream,)).fetchone()
        if not row or tuple(row[k] for k in ('contract','extractor','feature_version')) != (CONTRACT, EXTRACTOR, FEATURES):
            raise ValueError('running_compatible_compact_stream_required')
        if not store.conn.execute(f'SELECT 1 FROM {s}.queue_counts WHERE stream_id=%s', (stream,)).fetchone():
            raise ValueError('installed_compact_queue_counts_required')
        if history_required and not store.conn.execute(f'SELECT 1 FROM {s}.history_jobs WHERE stream_id=%s LIMIT 1', (stream,)).fetchone():
            raise ValueError('existing_history_job_required')


def existing_job(store, stream, floor):
    """Resume exactly the requested range without DDL or cursor mutation."""
    if floor % FIVE:
        raise ValueError('history_start_must_align_to_five_minutes')
    if not store.conn.execute('SELECT to_regclass(%s) AS name', (store.schema+'.history_jobs',)).fetchone()['name']:
        return None
    return store.conn.execute(f'SELECT * FROM {store.schema}.history_jobs WHERE stream_id=%s AND from_ns=%s', (stream, floor)).fetchone()
