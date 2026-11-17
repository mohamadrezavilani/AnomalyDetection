"""Explicit scope switch and resumable reconstruction from retained evidence.

No cursor/date/key/feedback reset. Failed or cancelled reconstruction stays
RESTORING_FULL; ordinary publishers refuse that state. All three writer leases
remain held through the repair. Progress receipts contain no raw evidence.
"""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys
import threading
import time
import zlib

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))


@contextmanager
def repair_access(db):
    previous=getattr(db,'_financial_repair',False)
    db._financial_repair=True
    try:yield
    finally:db._financial_repair=previous


@contextmanager
def stopped_writer_leases(db):
    held=[]
    try:
        if not db.sqlite:
            # Do not leak AnomalyDetection/tests into multiprocessing's import
            # path. Spawned Viewer children must still import the Viewer tests.
            previous=sys.path[:]
            try:
                sys.path.insert(0,str(ROOT/'AnomalyDetection'))
                from anomaly_detection.history_scope import WRITER_LOCK
            finally:sys.path[:]=previous
            for keys,error in (((240026,1),'VIEWER_MUST_BE_STOPPED'),
                               ((240026,2),'VIEWER_MUST_BE_STOPPED'),
                               ((WRITER_LOCK,),'AD_MUST_BE_STOPPED')):
                if not db.one('SELECT pg_try_advisory_lock('+','.join('?' for _ in keys)+') AS held',keys)['held']:
                    raise ValueError(error)
                held.append(keys)
        yield
    finally:
        if held:
            db.conn.rollback()
            for keys in reversed(held):
                db.one('SELECT pg_advisory_unlock('+','.join('?' for _ in keys)+') AS released',keys)
            db.conn.commit()


def change(db,action,*,progress=lambda value:None,cancelled=lambda:False,max_seconds=43200):
    from p24_foundation.viewer_product_scope import set_scope,read,capabilities,BEHAVIOR,FULL
    if action=='status':return capabilities(read(db,refresh=True))
    if action not in ('enable','restore-full'):raise ValueError('INVALID_SCOPE_ACTION')
    if max_seconds<=0:raise ValueError('POSITIVE_REPAIR_BUDGET_REQUIRED')
    deadline=time.monotonic()+max_seconds
    monitor_failures=[]
    @contextmanager
    def cancellation_monitor():
        done=threading.Event();failure=monitor_failures
        def monitor():
            from viewer_performance.financial_screen.resources import process_usage,available_memory
            while not done.wait(.2):
                usage=process_usage(os.getpid());free=available_memory()
                if usage.get('rss_bytes',0)>2*1024**3 or free is not None and free<4*1024**3:
                    failure.append(ValueError('SCOPE_REPAIR_MEMORY_BUDGET_EXHAUSTED'))
                if cancelled() or time.monotonic()>=deadline:
                    failure.append(ValueError('SCOPE_REPAIR_CANCELLED') if cancelled() else TimeoutError('SCOPE_REPAIR_BUDGET_EXHAUSTED'))
                if failure:
                    if not db.sqlite:
                        try:db.conn.cancel()
                        except Exception:pass
                    return
        thread=threading.Thread(target=monitor,daemon=True);thread.start()
        try:
            yield
            if failure:raise failure[0]
        finally:done.set();thread.join(10)
    def checkpoint(stage,**values):
        if monitor_failures:raise monitor_failures[0]
        if cancelled():raise ValueError('SCOPE_REPAIR_CANCELLED')
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('SCOPE_REPAIR_BUDGET_EXHAUSTED')
        if not db.sqlite:
            db.sql("SELECT set_config('statement_timeout',?,false)",(str(max(1,int(remaining*1000))),))
        progress(dict(stage=stage,at_ns=time.time_ns(),**values))
    with stopped_writer_leases(db),repair_access(db),cancellation_monitor():
        try:
            previous=read(db,refresh=True)
            if action=='enable':
                if previous['contract']==BEHAVIOR and previous['state']=='READY':return capabilities(previous)
                generation=None
                if previous['state']=='RESTORING_FULL':
                    live=db.one('SELECT generation FROM viewer_live_state WHERE id=1')
                    generation=max(live['generation'],db.semantic_checkpoint()['generation'])+1
                    db.sql('UPDATE viewer_live_state SET generation=? WHERE id=1',(generation,))
                    db.sql('UPDATE viewer_semantic_checkpoint SET generation=? WHERE id=1',(generation,))
                result=set_scope(db,BEHAVIOR)
                if generation is not None:db.sql('INSERT INTO viewer_publication_contracts VALUES(?,?,?)',(generation,BEHAVIOR,result['scope_epoch']))
                db.conn.commit();return result
            if previous['contract']==FULL and previous['state']=='READY':return capabilities(previous)
            # The committed generation fences the resumable scan. If behavior
            # publication resumed after an interrupted repair, scan raw again.
            live=db.one('SELECT generation FROM viewer_live_state WHERE id=1')
            generation=live['generation']
            if previous['state']!='RESTORING_FULL':
                set_scope(db,BEHAVIOR,state='RESTORING_FULL')
            db.sql('''CREATE TABLE IF NOT EXISTS viewer_financial_repair(
                id INTEGER PRIMARY KEY,generation BIGINT NOT NULL,origin_key TEXT NOT NULL,
                version_key TEXT NOT NULL,scanned BIGINT NOT NULL,phase TEXT NOT NULL DEFAULT 'LINKS',projection_after TEXT NOT NULL DEFAULT '')''')
            columns={c[0] for c in db.sql('SELECT * FROM viewer_financial_repair LIMIT 0').description}
            for column,definition in (('phase',"TEXT NOT NULL DEFAULT 'LINKS'"),('projection_after',"TEXT NOT NULL DEFAULT ''")):
                if column not in columns:db.sql('ALTER TABLE viewer_financial_repair ADD COLUMN '+column+' '+definition)
            repair=db.one('SELECT * FROM viewer_financial_repair WHERE id=1')
            if not repair or repair['generation']!=generation:
                db.sql("INSERT INTO viewer_financial_repair(id,generation,origin_key,version_key,scanned,phase,projection_after) VALUES(1,?,'','',0,'LINKS','') ON CONFLICT(id) DO UPDATE SET generation=excluded.generation,origin_key='',version_key='',scanned=0,phase='LINKS',projection_after=''",(generation,))
                repair=dict(origin_key='',version_key='',scanned=0,phase='LINKS',projection_after='')
            db.conn.commit()
            from p24_foundation.viewer_data import sql_links,token
            from p24_foundation.viewer_storage_keys import conflict_clause
            after=(repair['origin_key'],repair['version_key']);scanned=repair['scanned']
            while repair['phase']=='LINKS':
                checkpoint('RESTORING_LINKS',scanned=scanned)
                rows=db.all('''SELECT e.origin_key,e.version_key,e.request_key,b.payload FROM viewer_events e
                    LEFT JOIN viewer_raw_events b ON b.origin_key=e.origin_key AND b.version_key=e.version_key
                    WHERE e.kind='sql' AND (e.origin_key,e.version_key)>(?,?)
                    ORDER BY e.origin_key,e.version_key LIMIT 64''',after)
                if not rows:
                    db.sql("UPDATE viewer_financial_repair SET phase='PROJECTIONS' WHERE id=1");db.conn.commit();break
                values=[]
                for row in rows:
                    if row['payload'] is None:raise ValueError('FINANCIAL_REPAIR_RAW_EVIDENCE_MISSING')
                    raw=json.loads(zlib.decompress(bytes(row['payload'])).decode('utf-8'))
                    for domain,value in sql_links(raw.get('message','')).items():
                        values.append((row['origin_key'],row['version_key'],row['request_key'],domain,token(db.keys,domain,value)))
                db.many('INSERT INTO viewer_links(origin_key,version_key,request_key,link_domain,link_key) VALUES(?,?,?,?,?)'+conflict_clause(db,'viewer_links'),values)
                after=(rows[-1]['origin_key'],rows[-1]['version_key']);scanned+=len(rows)
                db.sql('UPDATE viewer_financial_repair SET origin_key=?,version_key=?,scanned=? WHERE id=1',(*after,scanned))
                db.conn.commit()
            # Rebuild one exact financial dependency closure at a time. The
            # source is fenced and AD refuses RESTORING_FULL, so completed
            # batches can commit without advertising partial finance as ready.
            # The durable cursor commits with its projections, not before them.
            from p24_foundation.viewer_online import affected_closure
            after_request=repair['projection_after']
            while True:
                checkpoint('SELECTING_REPAIR_REQUESTS',scanned=scanned,after_request=after_request)
                page=db.all('SELECT DISTINCT request_key FROM viewer_events WHERE request_key>? ORDER BY request_key LIMIT 500',(after_request,))
                if not page:break
                keys=affected_closure(db,[r['request_key'] for r in page])
                checkpoint('REBUILDING_REQUESTS',batch_requests=len(keys));db.rebuild(request_keys=keys,commit=False)
                checkpoint('REBUILDING_FINANCIAL_CONTRACT',batch_requests=len(keys));db.rebuild_payment_contract(request_keys=keys,commit=False)
                checkpoint('REBUILDING_SEMANTICS',batch_requests=len(keys));db.reconcile_semantic_requests(keys,commit=False)
                after_request=page[-1]['request_key']
                db.sql('UPDATE viewer_financial_repair SET projection_after=? WHERE id=1',(after_request,));db.conn.commit()
            # Only this final transaction advertises restored full capability.
            checkpoint('PUBLISHING_RESTORED_SCOPE',scanned=scanned)
            semantic=db.semantic_checkpoint();generation=max(generation,semantic['generation'])+1
            db.sql('UPDATE viewer_live_state SET generation=? WHERE id=1',(generation,))
            db.sql('UPDATE viewer_semantic_checkpoint SET generation=? WHERE id=1',(generation,))
            result=set_scope(db,FULL)
            db.sql('INSERT INTO viewer_publication_contracts VALUES(?,?,?)',(generation,FULL,result['scope_epoch']))
            db.conn.commit();progress(dict(stage='FULL_SCOPE_READY',scanned=scanned,**result));return result
        except BaseException:
            db.conn.rollback();db._product_scope=None;raise


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('status','enable','restore-full'))
    parser.add_argument('--project',type=Path,default=ROOT)
    parser.add_argument('--progress',type=Path)
    parser.add_argument('--cancel-file',type=Path)
    parser.add_argument('--max-seconds',type=int,default=43200)
    parser.add_argument('--command-token',default='')
    args=parser.parse_args(argv)
    from p24_foundation.viewer_runtime import atomic_json
    from viewer_performance.financial_screen.resources import process_usage
    identity=process_usage(os.getpid(),cpu_only=True)
    last=dict(command_token=args.command_token,process_pid=os.getpid(),
              process_created_epoch_seconds=identity.get('created_epoch_seconds'))
    def progress(value):
        last.update(value)
        if args.progress:atomic_json(args.progress,last)
    progress(dict(stage='INITIALIZING_SCOPE_CONTROLLER'))
    from viewer_performance.Run_Viewer_Web import existing_options
    from viewer_performance.fast_writer import FastWriterDB
    try:
        with FastWriterDB(**existing_options(args.project.resolve())) as db:
            db.writer_identity.enabled=False
            result=change(db,args.action,progress=progress,
                          cancelled=lambda:bool(args.cancel_file and args.cancel_file.exists()),max_seconds=args.max_seconds)
        progress(dict(stage='SCOPE_READY',**result))
        print(json.dumps(dict(status='BEHAVIOR_SCOPE_UPDATED' if args.action!='status' else 'SCOPE_READ',**result)),flush=True)
        return 0
    except Exception as exc:
        result=dict(status='SCOPE_CONTROL_BLOCKED',error_type=type(exc).__name__,code=str(exc) if isinstance(exc,(ValueError,TimeoutError)) else None)
        progress(result);print(json.dumps(result),flush=True);return 2


if __name__=='__main__':raise SystemExit(main())
