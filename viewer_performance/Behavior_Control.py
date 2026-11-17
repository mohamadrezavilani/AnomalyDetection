"""Explicit scope switch / data-preserving financial reconstruction rollback.

Requires stopped Viewer and AD writers. No date, key, checkpoint or feedback
reset. A rollback rebuild can be long; incomplete repairs stay behavior-only.
"""
import argparse
import json
from pathlib import Path
import sys
import zlib

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))


def change(db,action):
    from p24_foundation.viewer_product_scope import set_scope,read,capabilities,BEHAVIOR,FULL
    if action=='status':return capabilities(read(db,refresh=True))
    if not db.sqlite:
        for key in ((240026,1),(240026,2)):
            if not db.one('SELECT pg_try_advisory_lock(?,?) AS held',key)['held']:
                raise ValueError('VIEWER_MUST_BE_STOPPED')
        # AD writer lock is independent. Avoid changing its active input scope.
        sys.path.insert(0,str(ROOT/'AnomalyDetection'))
        from anomaly_detection.history_scope import WRITER_LOCK
        if not db.one('SELECT pg_try_advisory_lock(?) AS held',(WRITER_LOCK,))['held']:
            raise ValueError('AD_MUST_BE_STOPPED')
    if action=='enable':
        previous=read(db,refresh=True)
        if previous['contract']==BEHAVIOR and previous['state']=='READY':return capabilities(previous)
        db._financial_repair=True
        result=set_scope(db,BEHAVIOR);db.conn.commit();return result
    if action!='restore-full':raise ValueError('INVALID_SCOPE_ACTION')
    # Old financial rows have intentionally stopped receiving new evidence.
    # Reconstruct them from retained raw versions before declaring full scope.
    db._financial_repair=True
    set_scope(db,BEHAVIOR,state='RESTORING_FULL');db.conn.commit()
    from p24_foundation.viewer_data import sql_links,token,opaque
    from p24_foundation.viewer_storage_keys import conflict_clause
    after=('', '')
    while True:
        rows=db.all('''SELECT e.origin_key,e.version_key,e.request_key,b.payload FROM viewer_events e
          JOIN viewer_raw_events b ON b.origin_key=e.origin_key AND b.version_key=e.version_key
          WHERE e.kind='sql' AND (e.origin_key,e.version_key)>(?,?)
          ORDER BY e.origin_key,e.version_key LIMIT 500''',after)
        if not rows:break
        values=[]
        for row in rows:
            raw=json.loads(zlib.decompress(bytes(row['payload'])).decode('utf-8'))
            for domain,value in sql_links(raw.get('message','')).items():
                values.append((row['origin_key'],row['version_key'],row['request_key'],domain,token(db.keys,domain,value)))
        db.many('INSERT INTO viewer_links(origin_key,version_key,request_key,link_domain,link_key) VALUES(?,?,?,?,?)'+conflict_clause(db,'viewer_links'),values)
        after=(rows[-1]['origin_key'],rows[-1]['version_key']);db.conn.commit()
    # Ordinary canonical algorithms; a failure rolls back the final projection
    # transaction and leaves RESTORING_FULL (never a falsely complete finance).
    try:
        db.rebuild(commit=False);db.rebuild_payment_contract(commit=False);db.build_semantic_index(commit=False)
        live=db.one('SELECT generation FROM viewer_live_state WHERE id=1')
        semantic=db.semantic_checkpoint()
        generation=max(live['generation'],semantic['generation'])+1
        db.sql('UPDATE viewer_live_state SET generation=? WHERE id=1',(generation,))
        db.sql('UPDATE viewer_semantic_checkpoint SET generation=? WHERE id=1',(generation,))
        result=set_scope(db,FULL);db.conn.commit();return result
    except BaseException:
        db.conn.rollback();raise


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('status','enable','restore-full'))
    parser.add_argument('--project',type=Path,default=ROOT)
    args=parser.parse_args(argv)
    from viewer_performance.Run_Viewer_Web import existing_options
    from viewer_performance.fast_writer import FastWriterDB
    try:
        with FastWriterDB(**existing_options(args.project.resolve())) as db:
            db.writer_identity.enabled=False
            result=change(db,args.action)
        print(json.dumps(dict(status='BEHAVIOR_SCOPE_UPDATED' if args.action!='status' else 'SCOPE_READ',**result)))
        return 0
    except Exception as exc:
        print(json.dumps(dict(status='SCOPE_CONTROL_BLOCKED',error_type=type(exc).__name__,code=str(exc) if isinstance(exc,ValueError) else None)))
        return 2


if __name__=='__main__':raise SystemExit(main())
