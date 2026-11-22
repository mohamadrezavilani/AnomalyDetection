"""Export bounded timing, code and active-session statistics without writes or source calls."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import sys
import time
from zoneinfo import ZoneInfo


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project',type=Path,required=True);p.add_argument('--code-root',type=Path,required=True)
    p.add_argument('--service',required=True);p.add_argument('--at-tehran',required=True)
    a=p.parse_args();sys.path.insert(0,str(a.code_root.resolve()))
    from compact_product.config import load
    from compact_product.version import verify
    from compact_behavior import FIVE
    from compact_behavior.store import Store
    from compact_product.service_review import collect
    output=a.project/'AnomalyDetection/reports'/('Compact_Service_Review_'+time.strftime('%Y%m%d_%H%M%S')+'.json')
    report=dict(status='READ_ONLY_SERVICE_REVIEW',database_modified=False,workers_restarted=False,source_contacted=False)
    db=None
    try:
        report['package']=verify(a.code_root)
        at=datetime.fromisoformat(a.at_tehran)
        if at.tzinfo is None:at=at.replace(tzinfo=ZoneInfo('Asia/Tehran'))
        start=int(at.timestamp())*10**9//FIVE*FIVE
        cfg,settings,stream=load(a.project)
        db=Store(settings['DATABASE'],schema=cfg.source_schema,application='service-readonly-review')
        db.conn.execute('SET statement_timeout=8000')
        db.conn.execute('SET lock_timeout=1000')
        db.conn.execute('SET default_transaction_read_only=on')
        with db.conn.transaction():
            db.conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
            report.update(collect(db.conn,cfg.source_schema,cfg.ad_schema,stream,a.service,start))
        report['status']='READ_ONLY_SERVICE_REVIEW_COMPLETE'
    except Exception as exc:
        report['status']='READ_ONLY_SERVICE_REVIEW_INCOMPLETE'
        report['failure']=dict(type=type(exc).__name__,sqlstate=getattr(exc,'sqlstate',None))
    finally:
        if db:db.close()
        output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text(json.dumps(report,ensure_ascii=False,indent=2,default=str),encoding='utf-8')
        print(json.dumps(dict(status=report['status'],output=str(output),database_modified=False,workers_restarted=False)))
    return 2 if report['status'].endswith('INCOMPLETE') else 0


if __name__=='__main__':raise SystemExit(main())
