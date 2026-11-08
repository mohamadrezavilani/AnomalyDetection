"""P24 AD P0 qualification against native PostgreSQL, isolated synthetic DB ONLY.

Never connects with a write transaction to the production p24_design_viewer DB.
Creates a fresh unique template0 database (no production data), executes the
EXACT installed original selector and the candidate using the same indexed
synthetic fixtures, tests transactional rollback and late evidence, then drops
only that same temporary DB. No service is modified.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import random
import sys
import time
import uuid

TOOL='P24_AD_P0_NATIVE_PG_EQUIVALENCE_20261108_V1'
BUILD='AD-20261108-WINSTART'
SOURCE_SHA='56c64aaf2e9a35e237feb2e29f7f253958adfd0987426ef4f6c0e8809235ad4b'
DB_NAME='p24_design_viewer'
FIVE_NS=300_000_000_000
NOW=4_000_000_000_000_000
EXPECTED_CANDIDATE_SHA='ceb22fc3553d257cb5d9a5a704cb184d630efb7adeef84aaf87382af5b9e70ea'


def when():return datetime.now(timezone.utc).isoformat()


def require_release(root:Path):
    mf=root/'AnomalyDetection'/'RELEASE_MANIFEST.json'
    meta=json.loads(mf.read_text(encoding='utf-8'))
    if (meta.get('build_id'),meta.get('source_sha256'))!=(BUILD,SOURCE_SHA):
        raise ValueError('INSTALLED_BUILD_OR_SHA_MISMATCH')
    path=Path(__file__).with_name('audit_scope_candidate.py')
    if hashlib.sha256(path.read_bytes()).hexdigest()!=EXPECTED_CANDIDATE_SHA:
        raise ValueError('CANDIDATE_HASH_MISMATCH')
    sys.path.insert(0,str(root/'AnomalyDetection'))
    from anomaly_detection import audit_scope as original
    sp=importlib.util.spec_from_file_location('anomaly_detection.audit_scope_native_candidate',path)
    candidate=importlib.util.module_from_spec(sp);sp.loader.exec_module(candidate)
    if original.STATE!=candidate.STATE or original.needed()!=candidate.needed():
        raise ValueError('SELECTOR_CONTRACT_MISMATCH')
    if original.due_requests.__code__.co_code!=candidate.due_requests.__code__.co_code:
        # Bytecode matches when selection predicates / args stay identical;
        # variant source compiled using the same python release on target.
        raise ValueError('DUE_SELECT_CODE_MISMATCH')
    return original,candidate


def read_config(root:Path):
    path=root/'viewer_config.local.py'
    if not path.is_file():raise ValueError('VIEWER_LOCAL_CONFIG_NOT_FOUND')
    sp=importlib.util.spec_from_file_location('private_viewer_config_native_qual',path)
    module=importlib.util.module_from_spec(sp);sp.loader.exec_module(module)
    settings=dict(module.DATABASE)
    if settings.get('dbname')!=DB_NAME:raise ValueError('PRODUCTION_DB_NAME_GUARD_FAILED')
    if str(settings.get('host') or 'localhost').lower() not in ('localhost','127.0.0.1','::1'):
        raise ValueError('REMOTE_DB_FORBIDDEN')
    return settings


def conn_config(base,db):
    config=dict(base,dbname=db,connect_timeout=5,application_name='p24-ad-p0-nativepg-qualification')
    return config


@contextmanager
def disposable_database(base,report):
    import psycopg
    from psycopg import sql
    from psycopg.rows import dict_row
    target='p24_ad_p0_'+uuid.uuid4().hex[:16]+'_qualification'
    admin=psycopg.connect(**conn_config(base,'postgres'),autocommit=True,row_factory=dict_row)
    created=False
    try:
        auth=admin.execute('SELECT rolcreatedb,rolsuper FROM pg_roles WHERE rolname=current_user').fetchone()
        if not auth or not (auth['rolcreatedb'] or auth['rolsuper']):
            raise ValueError('NEED_CREATEDB_RIGHTS_FOR_ISOLATION')
        configs={r['name']:r['setting'] for r in admin.execute(
            "SELECT name,setting FROM pg_settings WHERE name IN ('fsync','full_page_writes','synchronous_commit')")}
        if any(configs.get(k)!='on' for k in ('fsync','full_page_writes','synchronous_commit')):
            raise ValueError('POSTGRES_DURABILITY_GUARD_FAILED')
        report['durability']=configs
        if admin.execute('SELECT 1 FROM pg_database WHERE datname=%s',(target,)).fetchone():
            raise ValueError('RANDOM_DATABASE_NAME_COLLISION')
        report['qualification_database']=target
        admin.execute(sql.SQL('CREATE DATABASE {} TEMPLATE template0').format(sql.Identifier(target)))
        created=True;report['qualification_created']=True
        yield conn_config(base,target)
    finally:
        if created:
            try:
                # Connections are closed by the context handler's user.
                admin.execute(sql.SQL('DROP DATABASE {}').format(sql.Identifier(target)))
                report['qualification_dropped']=True
            except Exception as err:
                report['qualification_dropped']=False
                report['cleanup_error_type']=type(err).__name__
                report['status']='BLOCKED_CLEANUP'
        admin.close()


SCHEMA=(
    'CREATE SCHEMA anomaly_detection',
    'CREATE TABLE anomaly_detection.adp_state(name TEXT PRIMARY KEY,body TEXT NOT NULL)',
    'CREATE TABLE anomaly_detection.adp_source_windows(start_ns BIGINT PRIMARY KEY,complete BOOLEAN NOT NULL)',
    'CREATE INDEX adp_complete_window_time ON anomaly_detection.adp_source_windows(start_ns DESC) WHERE complete=TRUE',
    'CREATE TABLE anomaly_detection.adp_jobs(session_key TEXT NOT NULL,target_ns BIGINT NOT NULL,primary_version BIGINT NOT NULL,PRIMARY KEY(session_key,target_ns))',
    """CREATE TABLE anomaly_detection.adp_case_signals(signal_key TEXT PRIMARY KEY,job_session TEXT,target_ns BIGINT NOT NULL,
    source_kind TEXT NOT NULL,state TEXT NOT NULL,review_eligible BOOLEAN NOT NULL,family TEXT NOT NULL,
    body TEXT NOT NULL,primary_version BIGINT)""",
    'CREATE INDEX adp_signal_audit_scope ON anomaly_detection.adp_case_signals(target_ns DESC,job_session) WHERE state=\'ACTIVE\' AND review_eligible=TRUE AND source_kind=\'actor\'',
    'CREATE INDEX adp_signal_actor ON anomaly_detection.adp_case_signals(job_session,target_ns)',
    """CREATE TABLE anomaly_detection.adp_facts(request_key TEXT PRIMARY KEY,session_key TEXT,at_ns BIGINT NOT NULL,
    eligible BOOLEAN NOT NULL,source_present BOOLEAN NOT NULL,state TEXT NOT NULL,next_audit_ns BIGINT NOT NULL,
    details TEXT,revision BIGINT NOT NULL,anchor_key TEXT NOT NULL,service_path TEXT)""",
    'CREATE INDEX adp_fact_session ON anomaly_detection.adp_facts(session_key,at_ns,request_key)',
    'CREATE INDEX adp_fact_audit ON anomaly_detection.adp_facts(next_audit_ns,request_key)',
)


class Store:
    def __init__(self,conn):self.raw=conn
    def state(self,name):
        row=self.raw.execute('SELECT body FROM anomaly_detection.adp_state WHERE name=%s',(name,)).fetchone()
        return json.loads(row['body']) if row else {}
    def save_state(self,name,value):
        self.raw.execute('INSERT INTO anomaly_detection.adp_state(name,body) VALUES(%s,%s) '
                         'ON CONFLICT(name) DO UPDATE SET body=excluded.body',
                         (name,json.dumps(value,separators=(',',':'),sort_keys=True)))


def clear_fixture(conn):
    conn.execute('TRUNCATE anomaly_detection.adp_case_signals,anomaly_detection.adp_jobs,anomaly_detection.adp_facts,anomaly_detection.adp_source_windows,anomaly_detection.adp_state')


def fixture(conn,n=120,*,due_at=(),cursor_at=None,visiting=False,incomplete=(),extra_signals=(),invalid_due=()):
    """Deterministic two-part timestamp/session ordering and fixed synthetic inputs."""
    rows=[]
    # Group 3 sessions per source window to exercise same-time tie ordering.
    for i in range(n):
        t=(n-(i//3))*FIVE_NS
        session='fixture_session_'+chr(122-i%3)+f'_{i//3:04d}'
        rows.append((t,session))
    assert rows==sorted(rows,reverse=True)
    for t in sorted({key[0] for key in rows}):
        conn.execute('INSERT INTO anomaly_detection.adp_source_windows(start_ns,complete) VALUES(%s,%s)',
                     (t,t not in {rows[i][0] for i in incomplete}))
    for i,(t,session) in enumerate(rows):
        conn.execute('INSERT INTO anomaly_detection.adp_case_signals VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                     (f'signal_{i}',session,t,'actor','ACTIVE',True,'rate_5m','{}',1))
        conn.execute('INSERT INTO anomaly_detection.adp_jobs VALUES(%s,%s,%s)',(session,t,1))
        if i in extra_signals:
            conn.execute('INSERT INTO anomaly_detection.adp_case_signals VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                         (f'extra_{i}',session,t,'actor','ACTIVE',True,'rate_5m','{}',1))
        if i in due_at or i in invalid_due:
            details=None if i not in invalid_due else json.dumps({'source_present':'true','quality':{'evidence_available':'true','conflicted':'false'},'semantic':{'state':'active','revision':'1','anchor_key':'fixture_anchor'},'input_subject':{'version':'verified-inquiry-input-1','status':'VERIFIED'}})
            conn.execute('INSERT INTO anomaly_detection.adp_facts VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                         (f'fixture_request_{i}',session,t+1,True,True,'active',0,details,1,'fixture_anchor','Services.v1/WaterBills'))
    anchor=rows[cursor_at] if cursor_at is not None else None
    return rows,({'session_key':anchor[1],'target_ns':anchor[0],
                   'visit_until_ns':NOW+1_000_000_000 if visiting else 0} if anchor else {})


def selector(conn,method,initial,*,max_turns=60):
    s=Store(conn)
    conn.execute('TRUNCATE anomaly_detection.adp_state')
    if initial:s.save_state(method.STATE,initial)
    times=[];found=[]
    for turn in range(max_turns):
        start=time.monotonic()
        with conn.transaction():
            found=method.keys(s,NOW,limit=1)
        times.append(round((time.monotonic()-start)*1000,3))
        if found or method is ORIG or not s.state(getattr(method,'WALK_STATE','unused')):
            break
    else:raise RuntimeError('QUALIFICATION_MAX_TURNS_REACHED')
    state=s.state(method.STATE)
    return dict(result=found,selected=[state.get('target_ns'),state.get('session_key')] if found else None,
                turns=len(times),total_ms=round(sum(times),3),max_turn_ms=round(max(times),3))

ORIG=None


def compare_case(conn,original,candidate,title,**kw):
    global ORIG
    ORIG=original
    n=kw.pop('n',120)
    with conn.transaction():
        clear_fixture(conn)
        rows,initial=fixture(conn,n,**kw)
    baseline=selector(conn,original,initial)
    alternative=selector(conn,candidate,initial)
    if (baseline['result'],baseline['selected'])!=(alternative['result'],alternative['selected']):
        raise AssertionError('EQUIVALENCE_FAILURE_'+title)
    return dict(case=title,status='PASS',original=baseline,candidate=alternative,
                fixture_scopes=n,input_due_count=len(kw.get('due_at',())))


def late_evidence_case(conn,candidate):
    """Late due after cursor visit may be seen in next lap, never permanently lost."""
    with conn.transaction():
        clear_fixture(conn)
        rows,initial=fixture(conn,90,due_at=())
    s=Store(conn)
    for _ in range(2):
        with conn.transaction():
            assert candidate.keys(s,NOW,limit=1)==[]
    assert s.state(candidate.WALK_STATE),'expected partial rotation before late evidence'
    t,session=rows[5]
    with conn.transaction():
        conn.execute('INSERT INTO anomaly_detection.adp_facts VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                     ('fixture_late_request',session,t+1,True,True,'active',0,None,1,'fixture_anchor','Services.v1/WaterBills'))
    turns=0;found=[]
    while turns<12:
        with conn.transaction():found=candidate.keys(s,NOW,limit=1)
        turns+=1
        if found:break
    if found!=['fixture_late_request']:raise AssertionError('LATE_EVIDENCE_NOT_REVISITED')
    return {'case':'late_evidence_next_lap','status':'PASS','turns':turns}


def rollback_case(conn,candidate):
    with conn.transaction():
        clear_fixture(conn);fixture(conn,70,due_at=())
    s=Store(conn)
    try:
        with conn.transaction():
            candidate.keys(s,NOW,limit=1)
            if not s.state(candidate.WALK_STATE):raise AssertionError('EXPECTED_CONTINUATION')
            raise RuntimeError('inject_rollback')
    except RuntimeError as e:
        if str(e)!='inject_rollback':raise
    if s.state(candidate.WALK_STATE):raise AssertionError('CONTINUATION_PERSISTED_AFTER_ROLLBACK')
    return {'case':'transactional_state_rollback','status':'PASS'}


def run(root:Path,*,reference_db_oid):
    if not 0<reference_db_oid<2**32:raise ValueError('INVALID_REFERENCE_DATABASE_OID')
    import psycopg
    from psycopg.rows import dict_row
    root=root.resolve()
    report={'tool':TOOL,'started_utc':when(),'status':'STARTED',
            'production_modified':False,'viewer_or_ad_stopped':False,
            'synthetic_only':True,'qualification_created':False,'qualification_dropped':False,
            'installed_build':BUILD,'cases':[]}
    original,candidate=require_release(root)
    settings=read_config(root)
    # Verify production identity only by reading pg_database; never enter a
    # modifying transaction on the production database.
    with psycopg.connect(**conn_config(settings,DB_NAME),row_factory=dict_row) as verify:
        row=verify.execute('SELECT (SELECT oid FROM pg_database WHERE datname=current_database()) AS oid,current_database() AS db').fetchone()
        if row['oid']!=reference_db_oid or row['db']!=DB_NAME:raise ValueError('PRODUCTION_IDENTITY_CHANGED')
    with disposable_database(settings,report) as qualification_settings:
        with psycopg.connect(**qualification_settings,row_factory=dict_row,autocommit=True) as conn:
            conn.execute("SET statement_timeout = '12000ms'")
            with conn.transaction():
                for q in SCHEMA:conn.execute(q)
            series=[
                ('deep_after_cursor',dict(n=120,due_at=(99,),cursor_at=20)),
                ('wrap_to_older',dict(n=120,due_at=(9,),cursor_at=50)),
                ('tie_and_duplicate',dict(n=120,due_at=(11,12,95),extra_signals=(11,12,55))),
                ('no_due',dict(n=120,due_at=(),cursor_at=25)),
                ('current_visit_priority',dict(n=120,due_at=(35,3),cursor_at=35,visiting=True)),
                ('incomplete_source_window',dict(n=120,due_at=(9,45),incomplete=(9,))),
                ('nonqualifying_evidence',dict(n=120,due_at=(49,),invalid_due=(2,))),
                ('zero_cursor',dict(n=120,due_at=(105,))),
            ]
            for title,kws in series:report['cases'].append(compare_case(conn,original,candidate,title,**kws))
            report['cases'].append(late_evidence_case(conn,candidate))
            report['cases'].append(rollback_case(conn,candidate))
    if report['qualification_created'] and not report['qualification_dropped']:
        report['status']='BLOCKED_CLEANUP'
    else:
        report['status']='PASS_SYNTHETIC_NATIVE_PG_PRELIMINARY'
    report['limitations']=[
        'This is schema-faithful synthetic fixture SQL, not live production data or full Viewer/AD replay.',
        'Bounded selector may defer later-arriving evidence until a subsequent complete lap.',
        'Qualification database shares the same PostgreSQL cluster I/O and WAL.',
        'Full operational rollout needs concurrency/crash/restart and real-data validation.',
    ]
    report['finished_utc']=when()
    return report


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--project',required=True,type=Path)
    ap.add_argument('--reference-db-oid',required=True,type=int)
    args=ap.parse_args()
    root=args.project.resolve();out=root/'AnomalyDetection'/'reports';out.mkdir(parents=True,exist_ok=True)
    path=out/('P24_AD_P0_NativePG_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')+'.json')
    try:r=run(root,reference_db_oid=args.reference_db_oid)
    except Exception as e:
        r={'tool':TOOL,'status':'BLOCKED_OR_FAILED','error_type':type(e).__name__,
           'error_code':str(e) if isinstance(e,(AssertionError,ValueError,RuntimeError)) else 'RUNTIME_ERROR',
           'sqlstate':getattr(e,'sqlstate',None),
           'production_modified':False,'viewer_or_ad_stopped':False,
           'qualification_cleanup':'SEE_LOG_IF_DATABASE_LEFT'}
    path.write_text(json.dumps(r,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'status':r['status'],'report':str(path)},ensure_ascii=False))
    return 0 if r['status']=='PASS_SYNTHETIC_NATIVE_PG_PRELIMINARY' else 2
if __name__=='__main__':raise SystemExit(main())
