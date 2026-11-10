"""Opt-in native PostgreSQL qualification on an EMPTY isolated test database.

No database/role/server creation, installation, resets or service changes.
Refuses p24_design_viewer, remote/default endpoints and an existing AD schema.
All fixture DDL/data live inside one transaction that is rolled back. No real
Viewer is opened. Never run this against a production database or config.
"""
from pathlib import Path
from unittest.mock import patch
import argparse,hashlib,importlib.util,json,sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))


def config_guard(value):
    c=value.get('connection',{})
    if value.get('isolated_audit_database') is not True:raise ValueError('ISOLATED_DATABASE_MARKER_REQUIRED')
    if set(c)-{'host','port','dbname','user','password','connect_timeout','sslmode'}:raise ValueError('CONNECTION_OVERRIDE_NOT_ALLOWED')
    if c.get('host') not in ('127.0.0.1','::1'):raise ValueError('ONLY_EXPLICIT_LOOPBACK_TEST_DATABASE_ALLOWED')
    if type(c.get('port')) is not int or c['port']==5432 or not 1024<=c['port']<=65535:raise ValueError('EXPLICIT_NONDEFAULT_TEST_PORT_REQUIRED')
    if not str(c.get('dbname','')).startswith('p24_audit_'):raise ValueError('ONLY_P24_AUDIT_DATABASE_ALLOWED')
    return dict(c,connect_timeout=3)


def write_profiles(raw,points,target,service):
    from anomaly_detection.snapshot import canonical,digest
    for p in points:
        raw.execute('INSERT INTO anomaly_detection.adp_profiles VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(request_key) DO UPDATE SET body=excluded.body,content_digest=excluded.content_digest',
            (p['request_key'],p['session_key'],p['service_path'],p['at_ns'],canonical(p),digest(p),target))
        raw.execute('INSERT INTO anomaly_detection.adp_facts(request_key,anchor_key,session_key,at_ns,service_path,kind,state,revision,eligible,source_present,body,content_digest,last_seen_ns) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,TRUE,TRUE,%s,%s,%s) ON CONFLICT(request_key) DO NOTHING',
            (p['request_key'],p['anchor_key'],p['session_key'],p['at_ns'],service,'service_execution','active',1,'{}',digest({}),target))


def seed_frames(raw,fixture,service):
    from anomaly_detection import FIVE_NS
    from anomaly_detection.snapshot import canonical
    for frame in fixture.frames:
        raw.execute('INSERT INTO anomaly_detection.adp_service_profile_samples VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING',
            (service,frame['start_ns'],frame['request_keys'],True))
        raw.execute('INSERT INTO anomaly_detection.adp_source_windows(start_ns,stamp,source,complete) VALUES(%s,%s,%s,TRUE) ON CONFLICT DO NOTHING',
            (frame['start_ns'],'native-fixture',canonical({'peer_population_valid':True})))
    for p in fixture.current+fixture.past:
        raw.execute('INSERT INTO anomaly_detection.adp_window_members(start_ns,request_key,body) VALUES(%s,%s,%s) ON CONFLICT DO NOTHING',
            (p['at_ns']//FIVE_NS*FIVE_NS,p['request_key'],'{}'))


def qualify(config):
    import psycopg
    from psycopg.rows import dict_row
    from anomaly_detection import BUILD_ID,FIVE_NS
    from anomaly_detection.product_store import ProductStore
    from anomaly_detection.scenario_store import enqueue,process_one,save_profile,scope_key
    from anomaly_detection.case_summary import case_status
    from anomaly_detection.cases import identity
    from anomaly_detection.snapshot import canonical,digest
    from anomaly_detection.request_profiles import VERSION
    from anomaly_detection.longitudinal import context as long_context,reference as long_reference
    from anomaly_detection.scenario_worker import step
    from audit.request_sample_fixture import Store as Fixture,FAMILIES,T,S
    checks=[]
    def check(name,expected,actual):checks.append(dict(test=name,expected=expected,actual=actual,status='PASS' if expected==actual else 'FAIL'))
    phase='connect_isolated_database'
    raw=psycopg.connect(**config_guard(config),autocommit=False,row_factory=dict_row)
    try:
        phase='verify_empty_database'
        db=raw.execute('SELECT current_database() AS db').fetchone()['db']
        if not db.startswith('p24_audit_'):raise ValueError('SERVER_DATABASE_IDENTITY_MISMATCH')
        if raw.execute("SELECT to_regnamespace('anomaly_detection') AS n").fetchone()['n'] is not None:raise ValueError('ISOLATED_DATABASE_MUST_HAVE_NO_AD_SCHEMA')
        existing=raw.execute("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%%' AND c.relkind IN ('r','p','m')) AS present").fetchone()['present']
        if existing:raise ValueError('ISOLATED_DATABASE_MUST_BE_EMPTY')
        phase='initialize_owned_fixture_schema'
        raw.execute('CREATE SCHEMA anomaly_detection')
        store=ProductStore(raw);store.initialize()
        fixture=Fixture('response_content_change');all_profiles=fixture.current+fixture.past
        phase='seed_declared_fixture';write_profiles(raw,all_profiles,T,S);seed_frames(raw,fixture,S)
        def evaluate(family,mode='valid'):
            data=Fixture(family,mode);write_profiles(raw,data.current,T,S)
            keys=[p['request_key'] for p in data.current]
            raw.execute('UPDATE anomaly_detection.adp_facts SET revision=%s WHERE request_key=ANY(%s)',(2 if mode=='stale_revision' else 1,keys))
            raw.execute('DELETE FROM anomaly_detection.adp_profile_tasks WHERE request_key=ANY(%s)',(keys,))
            if mode=='refresh_pending':
                for key in keys:raw.execute('INSERT INTO anomaly_detection.adp_profile_tasks(request_key) VALUES(%s)',(key,))
            kind='request_workflow' if family=='service_workflow_change' else 'request_response'
            enqueue(store,kind,S,S,T);result=process_one(store,T+100)
            return next(d for d in result['decisions'] if d['family']==family),data
        for family in FAMILIES:
            phase='evaluate_'+family
            positive,data=evaluate(family);check(family+'_positive','CANDIDATE',positive['status'])
            key=identity('service',S,{'service_workflow_change':'workflow','response_schema_change':'response_schema','response_content_change':'response_content','service_health':'service_health','multi_session_target':'service_coordination'}[family],S)
            check(family+'_case_current',True,case_status(store,key)['fresh'])
            for mode in ('stale_revision','refresh_pending'):
                phase='evaluate_'+family+'_'+mode
                unknown,_=evaluate(family,mode);check(family+'_'+mode,'INSUFFICIENT_DATA',unknown['status'])
        # SQL projection and aggregate qualification for pending multi-day inputs.
        phase='longitudinal_pending_profiles'
        _,data=evaluate('response_content_change');target_profile=data.current[0]
        raw.execute('INSERT INTO anomaly_detection.adp_profile_tasks(request_key) VALUES(%s)',(target_profile['request_key'],))
        rows,covered,bounded,receipt,metrics=long_context(store,dict(target_ns=T,service_path=S,entity_key=target_profile['session_key']))
        check('long_current_pending_qualified',False,next(r['qualified'] for r in rows if r['request_key']==target_profile['request_key']))
        prior=fixture.past[-1]
        raw.execute('INSERT INTO anomaly_detection.adp_profile_tasks(request_key) VALUES(%s) ON CONFLICT DO NOTHING',(prior['request_key'],))
        metrics,missing=long_reference(store,S,T,T-12*FIVE_NS,[prior['session_key']],[12*FIVE_NS])
        check('long_reference_pending_excluded',False,metrics[12*FIVE_NS][0]['qualified'])
        # Real scenario Worker lane with native owned SQL and a declared source fixture.
        raw.execute('DELETE FROM anomaly_detection.adp_profile_tasks WHERE request_key<>%s',(target_profile['request_key'],))
        source_meta=dict(namespace='native-audit-fixture',stream_key='native-audit-fixture',keys_fingerprint='fixture',generation=1,semantic_generation=1)
        class Source:
            def profile(self,key):return dict(request_key=key,profile=target_profile,source=source_meta)
        phase='real_scenario_worker_lane'
        state={};step(store,Source(),state,0)
        check('real_scenario_worker_lane_read',1,state.get('content_reads',0))
        check('real_scenario_worker_lane_failures',{},state.get('scenario_lane_failures',{}))
        check('real_scenario_worker_lane_evaluated',True,state.get('scenario_evaluations',0)>0)
        phase='rollback_and_verify_cleanup';raw.rollback()
        check('test_schema_rolled_back',None,raw.execute("SELECT to_regnamespace('anomaly_detection') AS n").fetchone()['n'])
        return dict(build_id=BUILD_ID,checks=checks,native_postgresql='EXECUTED_SYNTHETIC_ISOLATED',
            source='DECLARED_FIXTURE_NOT_LIVE_VIEWER',production_access=False,
            native_auth_concurrency_capacity_and_browser='NOT_QUALIFIED',status='PASS_BOUNDED_NATIVE_CHECKS' if all(c['status']=='PASS' for c in checks) else 'FAIL')
    except Exception as exc:
        exc.audit_phase=phase;exc.audit_checks=checks;raise
    finally:
        raw.rollback();raw.close()


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--config',type=Path);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    try:
        if args.config is None:result={'status':'NOT_RUN','reason':'ISOLATED_NATIVE_CONFIG_REQUIRED','native_postgresql':'NOT_RUN'}
        else:
            value=json.loads(args.config.read_text(encoding='utf-8-sig'));config_guard(value)
            if importlib.util.find_spec('psycopg') is None:result={'status':'NOT_RUN','reason':'EXISTING_PSYCOPG3_REQUIRED','native_postgresql':'NOT_RUN'}
            else:result=qualify(value)
    except Exception as e:
        # Exception SQL/DSN text can expose secrets; only its type is exported.
        reason=str(e) if isinstance(e,ValueError) and str(e).replace('_','').isalnum() and str(e).upper()==str(e) else None
        result={'status':'FAIL','error_type':type(e).__name__,'sqlstate':getattr(e,'sqlstate',None),
            'phase':getattr(e,'audit_phase','preflight_or_connection'),'checks':getattr(e,'audit_checks',[]),
            'reason':reason,'native_postgresql':'NOT_COMPLETED'}
    args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps(result))
    raise SystemExit(0 if result['status']=='PASS_BOUNDED_NATIVE_CHECKS' else 2 if result['status']=='NOT_RUN' else 1)
