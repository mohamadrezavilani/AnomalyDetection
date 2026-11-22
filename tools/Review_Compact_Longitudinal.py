"""Read-only aggregate readiness for multi-day AD. No raw profile or identity export."""
import argparse
import json
from pathlib import Path
import sys
import time


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project',type=Path,required=True)
    p.add_argument('--code-root',type=Path,required=True)
    args=p.parse_args()
    sys.path.insert(0,str(args.code_root.resolve()))
    from compact_product.config import load
    from compact_behavior.store import Store
    from compact_ad import long_store
    cfg,source,stream=load(args.project.resolve())
    db=Store(source['DATABASE'],schema=cfg.source_schema,application='longitudinal-read-only')
    try:
        with db.conn.transaction():
            db.conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
            db.conn.execute('SET LOCAL statement_timeout=5000')
            result=long_store.status(db.conn,cfg.source_schema,cfg.ad_schema,stream)
            if result['installed']:
                result['recent_periods']=db.conn.execute(f'''SELECT service,end_ns,span,state,details
                    FROM {cfg.ad_schema}.long_runs WHERE stream_id=%s ORDER BY end_ns DESC,service,span LIMIT 30''',(stream,)).fetchall()
                result['finding_counts']=db.conn.execute(f'''SELECT status,count(*) AS n FROM {cfg.ad_schema}.findings
                    WHERE stream_id=%s AND method='long_target_enumeration' GROUP BY status''',(stream,)).fetchall()
    finally:
        db.close()
    result.update(database_modified=False,workers_restarted=False,source_contacted=False)
    folder=args.project/'AnomalyDetection/reports';folder.mkdir(parents=True,exist_ok=True)
    output=folder/('Compact_Longitudinal_Review_'+time.strftime('%Y%m%d_%H%M%S')+'.json')
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(dict(status='READ_ONLY_LONGITUDINAL_REVIEW',output=str(output),database_modified=False)),flush=True)


if __name__=='__main__':main()
