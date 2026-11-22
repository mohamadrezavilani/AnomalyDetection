"""Read-only pending admission diagnostic: counts/times only, no request payloads."""
import argparse
import json
from pathlib import Path
import sys
import time


def collect(db, schema, stream, now_ns):
    from compact_behavior import FIVE
    from compact_behavior.store import PENDING_WAIT_NS
    from compact_behavior.extract import Limits
    row = db.execute(f'SELECT start_ns,next_ns FROM {schema}.streams WHERE stream_id=%s', (stream,)).fetchone()
    if not row:
        raise ValueError('COMPACT_STREAM_NOT_FOUND')
    next_ns = row['next_ns']
    counts = db.execute(f'SELECT * FROM {schema}.queue_counts WHERE stream_id=%s', (stream,)).fetchone()
    # Indexed WAITING subset only; never scan stored expired bodies or raw logs.
    due = db.execute(f'''SELECT count(*) AS waiting,
        count(*) FILTER(WHERE deadline_ns<=%s) AS due_at_checkpoint,
        count(*) FILTER(WHERE deadline_ns<=%s) AS due_at_next_window_end,
        min(first_seen_ns) AS oldest_first_seen_ns,
        min(deadline_ns) AS earliest_deadline_ns,max(deadline_ns) AS latest_deadline_ns
        FROM {schema}.pending_requests WHERE stream_id=%s AND status='WAITING' ''',
        (next_ns,next_ns+FIVE,stream)).fetchone()
    buckets = db.execute(f'''SELECT (deadline_ns/%s)*%s AS deadline_bucket_ns,count(*) AS requests
        FROM {schema}.pending_requests WHERE stream_id=%s AND status='WAITING'
        GROUP BY 1 ORDER BY 1 LIMIT 24''',(FIVE,FIVE,stream)).fetchall()
    recent = db.execute(f'''SELECT start_ns,end_ns,source_records,extracted_requests,published_at_ns
        FROM {schema}.windows WHERE stream_id=%s ORDER BY start_ns DESC LIMIT 12''',(stream,)).fetchall()
    roles = db.execute(f'''SELECT role,heartbeat_ns,info->>'state' AS state,
        info->'failure' AS failure,info->'retry' AS retry FROM {schema}.runtime_roles''').fetchall()
    return dict(status='READ_ONLY_PENDING_REVIEW',recorded_at_ns=now_ns,
        database_modified=False,workers_restarted=False,stream=row,counters=counts,due=due,
        waiting_deadline_buckets=buckets,latest_windows=recent,roles=roles,
        pending_warning_threshold=Limits().pending_requests,
        pending_high_water_warning=due['waiting']>Limits().pending_requests,
        pending_wait_ns=PENDING_WAIT_NS,
        limitation='Failed uncommitted window is not stored; incoming pending count is unknown.')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project',type=Path,required=True)
    p.add_argument('--code-root',type=Path,required=True)
    a=p.parse_args();sys.path.insert(0,str(a.code_root.resolve()))
    from compact_product.config import load
    from compact_behavior.store import Store
    cfg,source,stream=load(a.project)
    store=Store(source['DATABASE'],schema=cfg.source_schema,application='pending-review')
    try:
        store.conn.execute('SET default_transaction_read_only=on')
        store.conn.execute('SET statement_timeout=8000')
        with store.conn.transaction():
            store.conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            report=collect(store.conn,cfg.source_schema,stream,time.time_ns())
    finally:
        store.close()
    output=a.project/'AnomalyDetection/reports'/('Compact_Pending_Review_'+time.strftime('%Y%m%d_%H%M%S')+'.json')
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2,default=str),encoding='utf-8')
    print(json.dumps(dict(status=report['status'],output=str(output),due=report['due'],database_modified=False)))


if __name__=='__main__':main()
