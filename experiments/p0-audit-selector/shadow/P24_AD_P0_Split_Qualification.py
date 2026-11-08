"""Safely qualify two-stage AD audit selection (live DB READ ONLY).

Nothing is installed, persisted, or changed. Only exact source-matched SQL
is split; the second stage reuses audit_scope.due_requests as-is.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import sys
import time

BUILD = 'AD-20261108-WINSTART'
SOURCE_SHA = '56c64aaf2e9a35e237feb2e29f7f253958adfd0987426ef4f6c0e8809235ad4b'
EXPECTED = {'a369501609ee4d70','a399578b9c00d188'}
FACT_MARK = 'AND EXISTS(SELECT 1 FROM anomaly_detection.adp_facts f WHERE f.session_key=s.job_session '
ROTATION_MARK = 'AND (s.target_ns,s.job_session)<(%s,%s) '
ORDER = 'ORDER BY s.target_ns DESC,s.job_session DESC LIMIT 1'
VERSION = 'P24_AD_P0_TWO_STAGE_READONLY_20261108_V1'


def source_sql(ad,rotation=None,now=None):
    """Obtain statements using fake executor; never use a hardcoded imitation."""
    sys.path.insert(0,str(ad))
    from anomaly_detection import audit_scope
    class Answer:
        def fetchone(self):return None
        def fetchall(self):return []
    class Raw:
        def __init__(self):self.sql=[]
        def execute(self,statement,args=()):
            if not isinstance(statement,str) or not statement.startswith('SELECT '):
                raise ValueError('SOURCE_STATEMENT_NOT_SELECT')
            self.sql.append((statement,args));return Answer()
    class Store:
        def __init__(self):self.raw=Raw()
        def state(self,unused):
            return {'session_key':(rotation or {}).get('session_key','FICTITIOUS_AUDIT_SCOPE'),
                    'target_ns':(rotation or {}).get('target_ns',1794030000000000000),
                    'visit_until_ns':0}
        def save_state(self,*args):pass
    store=Store()
    audit_scope.keys(store,now=now or time.time_ns(),limit=1)
    out=[]
    for sql,args in store.raw.sql:
        uid=hashlib.sha256(sql.encode()).hexdigest()[:16]
        if uid in EXPECTED:out.append((uid,sql,args))
    if len(out)!=2 or {s[0] for s in out}!=EXPECTED:
        raise ValueError('SOURCE_SQL_FINGERPRINT_CHANGED')
    return out


def split_statement(sql,args):
    """Remove only expensive correlated FACT EXISTS from the exact live SQL.

    Semantics are recovered by calling unchanged audit_scope.due_requests()
    for *each* candidate scope, in original descending order.
    """
    if sql.count(FACT_MARK)!=1 or not sql.endswith(ORDER):
        raise ValueError('UNEXPECTED_SOURCE_SQL_SHAPE')
    before=sql.split(FACT_MARK,1)[0]
    if 'adp_source_windows sw' not in before or 's.source_kind=' not in before:
        raise ValueError('MISSING_SOURCE_GUARD')
    has_cursor=ROTATION_MARK in sql
    if len(args)!=(4 if has_cursor else 2) or sql.count(ROTATION_MARK)!=(1 if has_cursor else 0):
        raise ValueError('UNEXPECTED_SOURCE_PARAMETERS')
    # Before contains all source-kind, active, review and completed-window
    # clauses, so the only dropped condition is the fact-existence predicate.
    statement=before.replace('SELECT s.job_session,s.target_ns FROM ', 'SELECT DISTINCT s.job_session,s.target_ns FROM ',1)+(ROTATION_MARK if has_cursor else '')+\
        'ORDER BY s.target_ns DESC,s.job_session DESC LIMIT %s'
    return statement, (tuple(args[-2:]) if has_cursor else ())


def pg_config(ad):
    config=json.loads((ad/'data/pg_credentials.local.json').read_text(encoding='utf-8'))['connection']
    if config.get('dbname')!='p24_design_viewer' or config.get('user')!='p24_anomaly_detection':
        raise ValueError('REQUIRES_OWNED_AD_ROLE')
    params={k:v for k,v in config.items() if k not in
            ('options','row_factory','autocommit','application_name','service','passfile')}
    params.update(connect_timeout=4,autocommit=True,application_name='P24_AD_P0_TwoStage_RO',
        options='-c default_transaction_read_only=on -c statement_timeout=1800 '
                '-c lock_timeout=150 -c jit=off -c search_path=anomaly_detection,pg_catalog')
    return params


def safe_failure(exc):
    return {'status':'TIMEOUT' if getattr(exc,'sqlstate',None)=='57014' else 'ERROR',
            'sqlstate':getattr(exc,'sqlstate',None),'error_type':type(exc).__name__}


def current_state(conn):
    try:
        row=conn.execute("SELECT body FROM anomaly_detection.adp_state WHERE name='candidate_audit_scope_v4'").fetchone()
        value=json.loads(row['body']) if row else {}
        if isinstance(value.get('session_key'),str) and type(value.get('target_ns')) is int:
            return {'session_key':value['session_key'],'target_ns':value['target_ns']}
    except Exception:pass
    return None


def run(project,max_scopes=16,deadline_seconds=16,*,reference_db_oid):
    if not 0<reference_db_oid<2**32:raise ValueError('INVALID_REFERENCE_DATABASE_OID')
    import psycopg
    from psycopg.rows import dict_row
    project=Path(project).resolve();ad=project/'AnomalyDetection'
    installed=json.loads((ad/'RELEASE_MANIFEST.json').read_text(encoding='utf-8'))
    if installed.get('build_id')!=BUILD or installed.get('source_sha256')!=SOURCE_SHA:
        raise ValueError('INSTALLED_AD_VERSION_CHANGED')
    report={'tool':VERSION,'status':'STARTED','started_utc':datetime.now(timezone.utc).isoformat(),
        'installed_build':BUILD,'source_identity_verified':True,'production_database_changed':False,
        'services_stopped':False,'source_modified':False,'identifiers_exported':False,
        'full_equivalence_proven':False,'branches':[],
        'limitations':['No installed Worker code changed',
        'A short scope sample does not establish output equality or sustained capacity',
        'Original SELECT timed out in previous read-only A/B; not repeated here',
        'Read-only SQL shares the live database resources',
        'An alternative needs full matched PostgreSQL replay and rollback proof before installation']}
    with psycopg.connect(**pg_config(ad),row_factory=dict_row) as conn:
        identity=conn.execute("SELECT current_database() AS name,current_user AS role,"
            "current_setting('transaction_read_only') AS ro,"
            "(SELECT oid FROM pg_database WHERE datname=current_database()) AS oid").fetchone()
        if identity['name']!='p24_design_viewer' or identity['role']!='p24_anomaly_detection' \
                or identity['ro']!='on' or identity['oid']!=reference_db_oid:
            raise ValueError('LIVE_DATABASE_IDENTITY_GUARD')
        report['database_guard_passed']=True
        begun=time.monotonic()
        with conn.transaction():
            conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
            rotation=current_state(conn)
            snapshot_now=time.time_ns()
            queries=source_sql(ad,rotation,now=snapshot_now)
            report['rotation_loaded']=rotation is not None
            from anomaly_detection import audit_scope
            class Store:
                def __init__(self,connection):self.raw=connection
            for uid,original,args in queries:
                sql,cursor=split_statement(original,args)
                branch={'source_sql_id':uid,'scope_query_status':'NOT_RUN','scopes_seen':0,
                        'due_requests_checked':0,'first_due_found':False,'individual_query_times_ms':[],
                        'scope_query_ms':None,'status':'STARTED'}
                report['branches'].append(branch)
                if time.monotonic()-begun>deadline_seconds:
                    branch['status']='BUDGET_EXPIRED';continue
                started=time.monotonic()
                try:
                    with conn.transaction():
                        scopes=conn.execute(sql,(*cursor,max_scopes)).fetchall()
                    branch['scope_query_ms']=round((time.monotonic()-started)*1000,2)
                    branch['scope_query_status']='OK'
                except Exception as exc:
                    branch['scope_query_status']=safe_failure(exc)
                    branch['status']='SCOPE_QUERY_FAILED';continue
                branch['scopes_seen']=len(scopes)
                for s in scopes:
                    if time.monotonic()-begun>deadline_seconds:
                        branch['status']='BUDGET_EXPIRED';break
                    t=time.monotonic()
                    try:
                        with conn.transaction():
                            found=audit_scope.due_requests(Store(conn),
                                {'session_key':s['job_session'],'target_ns':s['target_ns']},
                                snapshot_now,1)
                        branch['due_requests_checked']+=1
                        branch['individual_query_times_ms'].append(round((time.monotonic()-t)*1000,2))
                        if found:
                            branch['first_due_found']=True;branch['status']='DUE_FOUND';break
                    except Exception as exc:
                        branch['due_check_failure']=safe_failure(exc)
                        branch['status']='DUE_QUERY_FAILED';break
                if branch['status']=='STARTED':
                    branch['status']='NO_DUE_IN_SAMPLED_SCOPES' if scopes else 'NO_SIGNAL_SCOPE'
                # No sample output IDs are retained. Just count and timing.
        report['elapsed_seconds']=round(time.monotonic()-begun,3)
    report['qualification_status']='PRELIMINARY_ONLY_NO_PRODUCTION_CHANGE'
    report['status']='COMPLETE_READ_ONLY'
    report['finished_utc']=datetime.now(timezone.utc).isoformat()
    return report


def main(argv=None):
    parser=argparse.ArgumentParser()
    parser.add_argument('--project',type=Path,required=True)
    parser.add_argument('--reference-db-oid',required=True,type=int)
    parser.add_argument('--max-scopes',type=int,default=16)
    args=parser.parse_args(argv)
    out=args.project.resolve()/'AnomalyDetection'/'reports';out.mkdir(parents=True,exist_ok=True)
    try:
        report=run(args.project,max_scopes=min(16,max(1,args.max_scopes)),reference_db_oid=args.reference_db_oid)
    except Exception as exc:
        report={'tool':VERSION,'status':'STOPPED_NO_CHANGE','error_type':type(exc).__name__,
                'error_code':str(exc) if isinstance(exc,ValueError) else 'RUNTIME_ERROR',
                'production_database_changed':False,'services_stopped':False,'source_modified':False}
    target=out/('P24_AD_P0_Split_Qualification_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')+'.json')
    target.write_text(json.dumps(report,ensure_ascii=False,indent=2,default=str),encoding='utf-8')
    print(json.dumps({'status':report['status'],'report':str(target)},ensure_ascii=False))
    return 0 if report['status']=='COMPLETE_READ_ONLY' else 2

if __name__=='__main__':raise SystemExit(main())
