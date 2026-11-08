"""Non-installing, read-only shadow of bounded P0 candidate audit selector.

No operational checkpoint/state mutation. Uses the installed AD role's existing
credentials under a strictly read-only PostgreSQL transaction. Never exports
customer, session, request identifiers or SQL parameters.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import importlib.util
import json
from pathlib import Path
import sys
import time

VERSION='P24_AD_P0_SHADOW_CANDIDATE_RO_20261108_V1'
REQUIRED_BUILD='AD-20261108-WINSTART'
REQUIRED_SHA='56c64aaf2e9a35e237feb2e29f7f253958adfd0987426ef4f6c0e8809235ad4b'
MAX_DURATION=25
MAX_TURNS=26


def stamp():return datetime.now(timezone.utc).isoformat()

class ReadOnlyRaw:
    def __init__(self,conn):
        self.conn=conn
        self.scope_queries=0
        self.due_queries=0
        self.elapsed_scope_ms=0.
        self.elapsed_due_ms=0.
    def execute(self,sql,args=()):
        if not sql.startswith('SELECT '):raise ValueError('SHADOW_NON_SELECT_BLOCKED')
        if sql.startswith('SELECT DISTINCT s.job_session,s.target_ns'):
            kind='scope'
        elif sql.startswith('SELECT f.request_key'):
            kind='due'
        else:raise ValueError('SHADOW_UNEXPECTED_SELECT')
        t=time.monotonic()
        try:return self.conn.execute(sql,args)
        finally:
            elapsed=(time.monotonic()-t)*1000
            if kind=='scope':self.scope_queries+=1;self.elapsed_scope_ms+=elapsed
            else:self.due_queries+=1;self.elapsed_due_ms+=elapsed

class ShadowStore:
    def __init__(self,conn,primary):
        self.raw=ReadOnlyRaw(conn)
        self.memory={'candidate_audit_scope_v4':primary or {}}
        self.state_saves=0
    def state(self,name):return self.memory.get(name,{})
    def save_state(self,name,value):
        # Deliberately never calls the PostgreSQL connection.
        self.memory[name]=dict(value)
        self.state_saves+=1


def load_shadow(ad):
    # Import exact installed source only after path is explicitly registered.
    sys.path.insert(0,str(ad))
    from anomaly_detection import audit_scope as installed
    path=Path(__file__).with_name('audit_scope_candidate.py')
    spec=importlib.util.spec_from_file_location('anomaly_detection.audit_scope_p0_shadow',path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return installed,module


def run(project,max_duration=MAX_DURATION,*,reference_db_oid):
    if not 0<reference_db_oid<2**32:raise ValueError('INVALID_REFERENCE_DATABASE_OID')
    import psycopg
    from psycopg.rows import dict_row
    project=Path(project).resolve();ad=project/'AnomalyDetection'
    release=json.loads((ad/'RELEASE_MANIFEST.json').read_text(encoding='utf-8'))
    if (release.get('build_id'),release.get('source_sha256'))!=(REQUIRED_BUILD,REQUIRED_SHA):
        raise ValueError('INSTALLED_AD_SOURCE_CHANGED')
    installed,candidate=load_shadow(ad)
    # Use original live source query extraction as an independent SQL identity guard.
    from P24_AD_P0_Split_Qualification import source_sql,split_statement,pg_config
    query_pairs=source_sql(ad,{'session_key':'shadow_cursor','target_ns':1794045600000000000},now=1794120000000000000)
    expected=[]
    for uid,sql,args in query_pairs:
        shape,params=split_statement(sql,args)
        if params:expected.append((uid,candidate.SCOPE_SELECT.replace(candidate.SCOPE_ORDER,
                'AND (s.target_ns,s.job_session)<(%s,%s) '+candidate.SCOPE_ORDER)==shape))
        else:expected.append((uid,candidate.SCOPE_SELECT==shape))
    if len(expected)!=2 or not all(equal for _,equal in expected):raise ValueError('CANDIDATE_SQL_PREDICATES_DIFFER')
    report={'tool':VERSION,'status':'STARTED','started_utc':stamp(),
        'installed_build':REQUIRED_BUILD,'installed_source_verified':True,
        'candidate_scope_sql_source_aligned':True,'database_changed':False,
        'source_modified':False,'services_stopped':False,'identifiers_exported':False,
        'comparison_to_original_full_query':'NOT_PROVEN',
        'limits':{'max_duration_seconds':max_duration,'max_turns':MAX_TURNS,
                  'max_scopes_per_turn':candidate.WALK_PAGE_SIZE},
        'warnings':['This shadow does not install code or commit PostgreSQL writes',
            'No original slow SQL is executed',
            'No native PostgreSQL fixture replay or production regression is proven',
            'A short sample does not demonstrate sustained throughput']}
    params=pg_config(ad)
    begin=time.monotonic();deadline=begin+max_duration
    with psycopg.connect(**params,row_factory=dict_row) as conn:
        identity=conn.execute("SELECT current_database() AS name,current_user AS role,"
            "current_setting('transaction_read_only') AS ro,"
            "(SELECT oid FROM pg_database WHERE datname=current_database()) AS oid").fetchone()
        if (identity['name'],identity['role'],identity['ro'],identity['oid'])!=('p24_design_viewer','p24_anomaly_detection','on',reference_db_oid):
            raise ValueError('DATABASE_ROLE_OR_READ_ONLY_GUARD_FAILED')
        report['database_identity_verified']=True
        with conn.transaction():
            conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
            row=conn.execute("SELECT body FROM anomaly_detection.adp_state WHERE name='candidate_audit_scope_v4'").fetchone()
            rotation={}
            if row:
                try:rotation=json.loads(row['body'])
                except (ValueError,TypeError):rotation={}
            if not isinstance(rotation,dict):rotation={}
            report['rotation_cursor_present']=isinstance(rotation.get('session_key'),str) and type(rotation.get('target_ns')) is int
            s=ShadowStore(conn,rotation)
            snapshot_ns=time.time_ns()
            chosen=False
            rounds=0
            while rounds<MAX_TURNS and time.monotonic()<deadline:
                rounds+=1
                with conn.transaction():
                    due=candidate.keys(s,snapshot_ns,limit=1)
                if due:
                    chosen=True;report['selection']='DUE_FOUND';break
                if not s.state(candidate.WALK_STATE):
                    report['selection']='NO_DUE_AFTER_COMPLETE_WALK';break
            else:report['selection']='PARTIAL_TIME_OR_TURN_LIMIT'
            report['turns']=rounds
            report['memory_only_state_saves']=s.state_saves
            report['scope_queries']=s.raw.scope_queries
            report['due_queries']=s.raw.due_queries
            report['scope_query_ms_total']=round(s.raw.elapsed_scope_ms,2)
            report['due_query_ms_total']=round(s.raw.elapsed_due_ms,2)
            report['candidate_selected_due']=chosen
            report['completed_rotation_walk']=report['selection']!='PARTIAL_TIME_OR_TURN_LIMIT'
            report['elapsed_seconds']=round(time.monotonic()-begin,3)
    report['status']='COMPLETE_READ_ONLY'
    report['qualification']='SHADOW_PRELIMINARY' if report['completed_rotation_walk'] else 'SHADOW_INCOMPLETE'
    report['finished_utc']=stamp()
    return report


def main():
    a=argparse.ArgumentParser()
    a.add_argument('--project',required=True,type=Path)
    a.add_argument('--reference-db-oid',required=True,type=int)
    args=a.parse_args()
    dest=args.project.resolve()/'AnomalyDetection'/'reports';dest.mkdir(parents=True,exist_ok=True)
    try:rep=run(args.project,reference_db_oid=args.reference_db_oid)
    except Exception as e:
        rep={'tool':VERSION,'status':'STOPPED_NO_CHANGE','error_type':type(e).__name__,
             'error_code':str(e) if isinstance(e,ValueError) else 'RUNTIME_ERROR',
             'sqlstate':getattr(e,'sqlstate',None),
             'database_changed':False,'services_stopped':False,'source_modified':False}
    path=dest/('P24_AD_P0_Shadow_Qualification_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')+'.json')
    path.write_text(json.dumps(rep,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'status':rep['status'],'report':str(path)},ensure_ascii=False))
    return 0 if rep['status']=='COMPLETE_READ_ONLY' else 2
if __name__=='__main__':raise SystemExit(main())
