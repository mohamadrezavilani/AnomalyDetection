"""Qualify account identity in a separate database and collect four source windows."""
import argparse
from concurrent.futures import ThreadPoolExecutor,as_completed
from datetime import datetime,timezone
import json
from pathlib import Path
from uuid import uuid4

from account_behavior.storage import NEW_DATABASE, ORIGIN, prepare, scan, publish, connect
from compact_behavior import FIVE
from compact_behavior.extract import instant,iso
from compact_product.config import load
from .samples import AccountWindow,capture


def shadow(project, name, start, windows):
    _,settings,stream=load(project)
    begin=instant(start)
    if (not 1<=windows<=12 or begin%FIVE or begin<instant(ORIGIN) or
            begin+windows*FIVE>int(datetime.now(timezone.utc).timestamp())*10**9):
        raise ValueError('qualified_closed_window_range_required')
    # Verify ownership, source and contract before reading ES or opening a writer.
    prepared=prepare(settings['DATABASE'],stream,name)
    out=[]
    with connect(settings['DATABASE'],prepared['database']) as db:
        for n in range(windows):
            at=begin+n*FIVE
            source=AccountWindow(settings['ELASTICSEARCH'],at,at+FIVE)
            fragments,count,quality=scan(source,at)
            value=publish(db,stream,at,fragments,count)
            out.append(dict(start=iso(at),records=count,requests=len(fragments),identity_lines=quality,**value))
        states=db.execute('SELECT status,count(*) AS n FROM p24_account.requests GROUP BY status').fetchall()
        n=db.execute('SELECT count(DISTINCT user_id) AS n FROM p24_account.requests').fetchone()['n']
    return dict(status='ACCOUNT_IDENTITY_SHADOW_COMMITTED',database=name,windows=out,request_status=states,accounts=n,
                scope='IDENTITY_PROJECTION_ONLY',ad_models_executed=False)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=('prepare','sample','prepare-db','shadow'))
    p.add_argument('--project',required=True,type=Path)
    p.add_argument('--output',type=Path)
    p.add_argument('--start',default=ORIGIN)
    p.add_argument('--windows',default=4,type=int)
    p.add_argument('--new-database',default=NEW_DATABASE)
    args=p.parse_args(argv)
    project=args.project.resolve()
    output=(args.output or project/'AnomalyDetection'/'reports').resolve()
    job=output/('UserID_Transition_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%SZ')+'_'+uuid4().hex[:8])
    job.mkdir(parents=True,exist_ok=False)
    cfg,settings,stream=load(project)
    del cfg
    jobs={'sample':lambda:capture(project,job,args.start,args.windows),
          'prepare-db':lambda:prepare(settings['DATABASE'],stream,args.new_database),
          'shadow':lambda:shadow(project,args.new_database,args.start,args.windows)}
    selected=('sample','prepare-db') if args.action=='prepare' else (args.action,)
    receipt=dict(status='RUNNING',results={},errors={},scope='ACCOUNT_PREPARATION_ONLY',old_database_dropped=False)
    def save():
        temp=job/'transition.tmp'
        temp.write_text(json.dumps(receipt,indent=2,ensure_ascii=False,default=str),encoding='utf-8')
        temp.replace(job/'transition.json')
    save()
    with ThreadPoolExecutor(max_workers=len(selected)) as pool:
        futures={pool.submit(jobs[action]):action for action in selected}
        for f in as_completed(futures):
            action=futures[f]
            try:
                result=f.result();receipt['results'][action]=result
                print(json.dumps(result,ensure_ascii=True,default=str),flush=True)
            except Exception as exc:
                simple=str(exc) if isinstance(exc,ValueError) else ''
                # Only our short symbolic errors. Driver and URL errors may include credentials.
                code=simple if simple and len(simple)<140 and all(c.isalnum() or c in '_:.' for c in simple) else None
                failure=dict(type=type(exc).__name__,code=code,sqlstate=getattr(exc,'sqlstate',None))
                receipt['errors'][action]=failure
                print(json.dumps(dict(status='STEP_FAILED',step=action,**failure)),flush=True)
            save()
    receipt['status']='STEPS_COMPLETE' if not receipt['errors'] else 'PARTIAL'
    save()
    print(json.dumps(dict(status=receipt['status'],receipt=str(job/'transition.json'))),flush=True)
    return int(bool(receipt['errors']))


if __name__=='__main__':
    raise SystemExit(main())
