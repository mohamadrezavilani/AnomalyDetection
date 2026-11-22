"""Inspect one request; optionally republish its complete window if its attempt feature is stale."""
import argparse
import json
from pathlib import Path
import sys
import time


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project',type=Path,required=True);p.add_argument('--code-root',type=Path,required=True)
    p.add_argument('--expected-source-sha',required=True);p.add_argument('--request-id',required=True)
    p.add_argument('--repair',action='store_true');a=p.parse_args()
    sys.path.insert(0,str(a.code_root.resolve()))
    from compact_product.version import verify
    from compact_product.config import load
    from compact_behavior.store import Store
    from compact_behavior import FIVE
    from compact_behavior.source import ElasticWindow
    from compact_behavior.__main__ import measure_window,save,notice
    from compact_product.attempt_review import inspect,AttemptWindowWriter,review_status
    output=a.project/'AnomalyDetection/reports'/('Compact_Attempt_Review_'+time.strftime('%Y%m%d_%H%M%S')+'.json')
    report=dict(status='COMPACT_ATTEMPT_REVIEW_STARTED',workers_restarted=False,data_reset=False,
                source_contacted=False,database_modified=False)
    db=None
    try:
        if verify(a.code_root)['source_sha256']!=a.expected_source_sha:raise ValueError('release_hash_mismatch')
        cfg,settings,stream=load(a.project)
        db=Store(settings['DATABASE'],schema=cfg.source_schema,application='attempt-review')
        with db.conn.transaction():
            db.conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
            report['before']=inspect(db,cfg.ad_schema,stream,a.request_id)
        if a.repair and report['before']['needs_feature_repair']:
            start=report['before']['start_ns'];report['source_contacted']=True
            save(output,report)
            source=ElasticWindow(settings['ELASTICSEARCH'],start,start+FIVE,
                page_size=settings['ELASTICSEARCH'].get('compact_page_size',500),budget=cfg.ingest_budget_seconds)
            report['repair']=measure_window(AttemptWindowWriter(db,cfg.ad_schema,a.request_id),stream,source,
                progress=lambda **kw:notice('COMPACT_ATTEMPT_WINDOW_READING',**kw))
            report['database_modified']=True
        with db.conn.transaction():
            db.conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
            report['after']=inspect(db,cfg.ad_schema,stream,a.request_id)
        after=report['after']
        report['status']=review_status(after)
    except Exception as exc:
        report['status']='COMPACT_ATTEMPT_REVIEW_INCOMPLETE'
        report['failure']=dict(type=type(exc).__name__,code=str(exc) if isinstance(exc,ValueError) else None,
                               sqlstate=getattr(exc,'sqlstate',None))
    finally:
        if db:db.close()
        save(output,report)
        notice(report['status'],output=str(output),database_modified=report['database_modified'],
               workers_restarted=False,data_reset=False)
    return 2 if report['status'].endswith('INCOMPLETE') else 0


if __name__=='__main__':raise SystemExit(main())
