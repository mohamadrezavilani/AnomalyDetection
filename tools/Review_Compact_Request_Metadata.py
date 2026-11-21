"""Read-only bounded coverage; exports counts, never IP/User-Agent values."""
import argparse
import json
from pathlib import Path
import sys
import time


def sample(db,schema,stream,*,before=None):
    from compact_behavior import FIVE
    clause=''
    args=[stream]
    if before is not None:
        clause='AND b.observed_at_ns >= %s AND b.observed_at_ns < %s'
        args.extend([before-6*FIVE,before])
    rows=db.execute(f'''SELECT x.behavior_id,c.context FROM (
        SELECT b.behavior_id FROM {schema}.behaviors b WHERE b.stream_id=%s {clause}
        ORDER BY b.observed_at_ns DESC,b.behavior_id DESC LIMIT 1000) x
        LEFT JOIN {schema}.request_context c USING(behavior_id)''',args).fetchall()
    result=dict(sampled_behaviors=len(rows),with_context=0,with_ip=0,with_user_agent=0,with_conflicts=0,with_limits=0)
    for row in rows:
        context=row['context'] or {};values=context.get('values',{})
        result['with_context']+=bool(context)
        result['with_ip']+=bool(values.get('ip'))
        result['with_user_agent']+=bool(values.get('user_agent'))
        result['with_conflicts']+=any(len(v)>1 for v in values.values())
        result['with_limits']+=bool(context.get('limited'))
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--project',type=Path,required=True);a=p.parse_args()
    root=Path(__file__).resolve().parents[1];sys.path.insert(0,str(root))
    from compact_product.config import load
    from compact_behavior.store import Store
    cfg,source,stream=load(a.project);store=Store(source['DATABASE'],schema=cfg.source_schema,application='metadata-review')
    try:
        store.conn.execute('SET default_transaction_read_only=on');store.conn.execute('SET statement_timeout=5000')
        report=dict(status='READ_ONLY_METADATA_REVIEW',latest=sample(store.conn,cfg.source_schema,stream),database_modified=False,workers_restarted=False)
        job=store.conn.execute(f'SELECT next_ns FROM {cfg.source_schema}.history_jobs WHERE stream_id=%s ORDER BY created_at_ns DESC LIMIT 1',(stream,)).fetchone()
        if job:report['recent_history']=sample(store.conn,cfg.source_schema,stream,before=job['next_ns'])
    finally:store.close()
    output=a.project/'AnomalyDetection/reports'/('Compact_Request_Metadata_'+time.strftime('%Y%m%d_%H%M%S')+'.json')
    output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(dict(output=str(output),**report)))

if __name__=='__main__':main()
