"""Unified cases, reference equivalence and independent worker lanes on SQL.

Disposable PostgreSQL/WASM only. Worker source packets are synthetic; SQLSTATE
57014 is raised by the database. No native owner connection or capacity claim.
"""
from contextlib import contextmanager,ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import hashlib,json
from transport import Engine
from anomaly_detection import BUILD_ID,FIVE_NS
from anomaly_detection.product_store import ProductStore
from anomaly_detection.product_pipeline import apply_window
from anomaly_detection.process_control import read_json,write_json
from anomaly_detection.product_worker import run
from anomaly_detection.service_reference import model,reference,HORIZON
from anomaly_detection.scenario_store import publish_scope,save_profile,process_one,scope_key
from anomaly_detection.service_sampling import read as read_sample,apply as apply_sample
from anomaly_detection.product_web import render
from anomaly_detection.cases import identity
from anomaly_detection.request_profiles import VERSION as PROFILE_VERSION
from anomaly_detection.snapshot import canonical,digest
from tests.test_scenarios import point,refs,S
from check_revision10 import TARGET as T,SESSION as ACTOR,packet,metadata
from check_revision19 import insert_many

ROOT=Path(__file__).resolve().parents[2]
OLD_QUERY=('SELECT p.session_key,p.start_ns,p.value FROM anomaly_detection.adp_service_reference_points p '
    'WHERE p.service_path=%s AND p.kind=%s AND p.qualified=TRUE AND p.start_ns<%s AND p.start_ns>=%s '
    'AND NOT EXISTS(SELECT 1 FROM anomaly_detection.adp_service_reference_points bad WHERE bad.service_path=p.service_path '
    'AND bad.kind=p.kind AND bad.session_key=p.session_key AND bad.qualified=FALSE AND bad.start_ns<%s AND bad.start_ns>=%s) '
    'ORDER BY p.start_ns DESC,p.session_key LIMIT 20001')


def setup():
    e=Engine();raw=e.connect();raw.execute('CREATE SCHEMA anomaly_detection');store=ProductStore(raw);store.initialize()
    return e,raw,store


def references_and_ui(checks):
    engine,raw,store=setup()
    try:
        values=[]
        for i in range(120):
            for at,n in ((T-(i+1)*3*FIVE_NS,1+i%3),(T-(i+1)*3*FIVE_NS-1,2+i%2),(T-1,0)):
                values.append({'service_path':S,'kind':'service_execution','session_key':f'{i+1000:064x}','start_ns':at,'value':n,'qualified':True})
        for actor,at,n,valid in ((ACTOR,T-FIVE_NS,100,True),('bad',T-FIVE_NS,500,True),('bad',T-2*FIVE_NS,0,False),
                ('outside',T-HORIZON-1,999,True),('future',T,999,True),('negative',T-1,-1,True)):
            values.append({'service_path':S,'kind':'service_execution','session_key':actor,'start_ns':at,'value':n,'qualified':valid})
        columns=[('service_path','TEXT'),('kind','TEXT'),('session_key','TEXT'),('start_ns','BIGINT'),('value','INTEGER'),('qualified','BOOLEAN')]
        insert_many(raw,'adp_service_reference_points',columns,values)
        old=[dict(r) for r in raw.execute(OLD_QUERY,(S,'service_execution',T,T-HORIZON,T,T-HORIZON)).fetchall()]
        expected=reference(old,ACTOR,T,S,unit='canonical_service_executions',reference_id='owned-complete-windows')
        expected['selection_policy']='canonical_first_qualified_http_bootstrap_fallback'
        got,_=model(store,S,ACTOR,T,'service_execution')
        assert got==expected,(got,expected)
        assert got['status']=='READY_BASELINE' and got['other_session_epochs']==120 and got['active_session_windows']==240
        checks['one_range_aggregate_preserves_model_id_maxima_span_point_count_invalid_actor_exclusion_and_past_cutoff']='PASS_EXACT_EQUALITY_TO_RELEASE20_SQL'
        oversized=[{'service_path':'Fixture/Cap','kind':'service_execution','session_key':f'{i//20+1000:064x}','start_ns':T-i-1,'value':1,'qualified':True} for i in range(20001)]
        insert_many(raw,'adp_service_reference_points',columns,oversized)
        capped,_=model(store,'Fixture/Cap',ACTOR,T,'service_execution')
        assert capped['status']=='INSUFFICIENT_DATA' and capped['other_session_epochs']==0
        checks['aggregate_does_not_bypass_20000_raw_point_limit']='PASS_20001_QUALIFIED_POINTS'
        # A real content case, then a separate real rate case, in one table.
        profiles=[];scopes=[]
        for rows in refs():
            for p in rows:profiles.append({'request_key':p['request_key'],'session_key':p['session_key'],'service_path':S,'at_ns':p['at_ns'],'body':canonical(p),'content_digest':digest(p),'observed_ns':T-FIVE_NS})
            scopes.append({'session_key':rows[0]['session_key'],'service_path':S,'start_ns':rows[0]['at_ns']//FIVE_NS*FIVE_NS,'request_keys':canonical([p['request_key'] for p in rows]),'independent':True,'available':True,'authority':'canonical'})
        # refs() has its own fixed timestamp; align the current target with it.
        from tests.test_scenarios import T as content_target
        insert_many(raw,'adp_profiles',[('request_key','TEXT'),('session_key','TEXT'),('service_path','TEXT'),('at_ns','BIGINT'),('body','TEXT'),('content_digest','TEXT'),('observed_ns','BIGINT')],profiles)
        insert_many(raw,'adp_profile_scopes',[('session_key','TEXT'),('service_path','TEXT'),('start_ns','BIGINT'),('request_keys','TEXT'),('independent','BOOLEAN'),('available','BOOLEAN'),('authority','TEXT')],scopes)
        apply_window(store,packet(content_target,{S:20},offset=50000))
        facts=raw.execute('SELECT request_key,at_ns,revision,anchor_key FROM anomaly_detection.adp_facts WHERE session_key=%s',(ACTOR,)).fetchall()
        publish_scope(store,ACTOR,S,content_target,[r['request_key'] for r in facts])
        for r in facts:
            p=point(int(r['request_key'],16),ACTOR,r['at_ns'],topic='one-bill',subject='one-bill')
            p.update(semantic_active=True,semantic_revision=r['revision'],anchor_key=r['anchor_key'])
            save_profile(store,{'source':metadata(content_target),'request_key':r['request_key'],'profile':p},content_target+FIVE_NS)
        assert process_one(store,content_target+FIVE_NS)['status']=='APPLIED'
        content_key=identity('actor',ACTOR,'repeat_target',S)
        assert raw.execute('SELECT 1 FROM anomaly_detection.adp_cases WHERE case_key=%s',(content_key,)).fetchone()
        # The existing primary comparison creates a rate case through its
        # actual engine, rather than manually inserting a presentation row.
        from anomaly_detection.primary_pipeline import context
        from anomaly_detection.product_engine import evaluate_job
        rate_at=T;apply_window(store,packet(rate_at,{S:20},offset=70000))
        raw.execute("UPDATE anomaly_detection.adp_facts SET details=jsonb_build_object('source_present',true,'semantic',body::jsonb,'quality',jsonb_build_object('evidence_available',true,'conflicted',false))::text WHERE at_ns>=%s",(rate_at,))
        j=dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(ACTOR,rate_at)).fetchone())
        c=store.save_context(j,context(store,j));j['version']=c['job_version']
        assert evaluate_job(store,j,c,T+FIVE_NS,mode='primary')['status']=='APPLIED'
        before=raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_case_versions').fetchone()['n']
        with raw.transaction():
            raw.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            args={'view':['cases'],'bucket':['ALL']}
            unified=render(store,{},'/incidents',args,'token')
            alias=render(store,{},'/scenarios',args,'token')
            assert unified==alias and 'تکرار همان موضوع استعلام' in unified and 'نرخ نامعمول استفاده از خدمت' in unified
            nav=unified.split('<nav>')[1].split('</nav>')[0]
            assert 'همهٔ آنومالی‌ها' in nav and 'href="/scenarios' not in nav and nav.count('href="/incidents"')==1
            assert 'dir="rtl"' in unified and '/case/'+content_key in unified
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_case_versions').fetchone()['n']==before
        checks['actual_rate_and_content_cases_render_together_legacy_scenario_url_is_same_view_and_get_cannot_write']='PASS_READ_ONLY_SQL_AND_RTL_HTML'
        original=engine.query
        def cancel(role,sql,args):
            if 'AS pending,COUNT(*) FILTER(WHERE NOT dirty' in sql:
                return original(role,"DO $$ BEGIN RAISE EXCEPTION 'progress fixture' USING ERRCODE='57014'; END $$",())
            return original(role,sql,args)
        from anomaly_detection.unified_review import progress
        engine.query=cancel
        assert 'مقدار نامعلوم صفر نیست' in progress(store)
        engine.query=original
        assert raw.execute('SELECT 1 AS n').fetchone()['n']==1
        checks['unified_progress_timeout_is_unknown_not_zero_and_preserves_connection']='PASS_REAL_SQL57014_SAVEPOINT'
    finally:engine.close()


def finite_sampling(checks):
    engine,raw,store=setup()
    try:
        raw.execute('CREATE TABLE public.viewer_live_windows(start_ns BIGINT PRIMARY KEY,end_ns BIGINT)')
        raw.execute('CREATE TABLE public.viewer_requests(request_key TEXT PRIMARY KEY,root_call TEXT,root_ns BIGINT,started_ns BIGINT,root_count INTEGER,conflicted INTEGER)')
        raw.execute('CREATE INDEX fixture_request_time ON public.viewer_requests((COALESCE(root_ns,started_ns)),request_key)')
        raw.execute('CREATE TABLE public.viewer_semantic_occurrences(request_key TEXT PRIMARY KEY,root_call TEXT,state TEXT)')
        raw.execute('INSERT INTO public.viewer_live_windows VALUES(%s,%s)',(T,T+FIVE_NS))
        raw.execute("INSERT INTO public.viewer_requests SELECT lpad(to_hex(i),64,'0'),'Public.v1/ExchangeCurrency',%s::bigint+i,%s::bigint+i,1,0 FROM generate_series(1,40) i",(T,T))
        raw.execute("INSERT INTO public.viewer_semantic_occurrences SELECT request_key,%s,'active' FROM public.viewer_requests WHERE request_key=%s",(S,f'{1:064x}'))
        # Conflicted and out-of-window roots cannot enter the sample.
        raw.execute('UPDATE public.viewer_requests SET conflicted=1 WHERE request_key=%s',(f'{2:064x}',))
        raw.execute('UPDATE public.viewer_requests SET root_ns=%s WHERE request_key=%s',(T+FIVE_NS,f'{3:064x}',))
        class Source:
            snapshots=0
            @contextmanager
            def snapshot(self):
                self.snapshots+=1
                with raw.transaction():
                    raw.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
                    yield self.query
            def metadata(self,q):return metadata(T)
            def query(self,sql,args=(),*,cap):
                rows=raw.execute(sql,args).fetchall();assert len(rows)<=cap
                return [dict(r) for r in rows]
        source=Source();sample=read_sample(source,{})
        assert source.snapshots==1 and sample['status']=='SAMPLED' and len(sample['rows'])==32
        keys=[r['request_key'] for r in sample['rows']]
        assert keys==sorted(keys) and f'{2:064x}' not in keys and f'{3:064x}' not in keys
        assert apply_sample(store,sample,'sample_fixture')=='SAMPLED'
        assert store.state('sample_fixture')['next_ns']==T+FIVE_NS
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_profile_tasks').fetchone()['n']==32
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_profile_scopes').fetchone()['n']==0
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_traffic_counts').fetchone()['n']==0
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_facts').fetchone()['n']==0
        assert {r['kind'] for r in raw.execute('SELECT DISTINCT kind FROM anomaly_detection.adp_scenario_jobs').fetchall()}=={'request_workflow','request_response'}
        checks['single_snapshot_request_sample_queues_response_and_workflow_without_census_fake_zero_or_actor_inference']='PASS_32_REAL_SQL_ROWS'
        complete={'complete':True,'requests':40}
        raw.execute('INSERT INTO anomaly_detection.adp_traffic_counts VALUES(%s,%s,%s)',(S,T,canonical(complete)))
        version=raw.execute('SELECT version FROM anomaly_detection.adp_scenario_jobs WHERE scope_key=%s',(scope_key('request_response',S,S,T),)).fetchone()['version']
        apply_sample(store,sample,'sample_fixture')
        assert raw.execute('SELECT version FROM anomaly_detection.adp_scenario_jobs WHERE scope_key=%s',(scope_key('request_response',S,S,T),)).fetchone()['version']==version
        assert json.loads(raw.execute('SELECT body FROM anomaly_detection.adp_traffic_counts WHERE service_path=%s',(S,)).fetchone()['body'])==complete
        checks['finite_sample_does_not_replace_complete_census_or_reinvalidate_existing_complete_response_job']='PASS'
        raw.execute('UPDATE anomaly_detection.adp_scenario_jobs SET dirty=FALSE,processed_version=version')
        apply_sample(store,{'status':'UNAVAILABLE','source':metadata(T),'target_ns':T},'sample_fixture')
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_service_profile_samples WHERE available=TRUE').fetchone()['n']==0
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_scenario_jobs WHERE dirty=TRUE').fetchone()['n']>0
        checks['unavailable_window_retracts_sample_qualification_and_requeues_affected_decisions']='PASS_NO_STALE_CURRENT_SAMPLE'
    finally:engine.close()


def worker_lanes(checks):
    for mode in ('source','primary','audit_selection','maintenance'):
        engine,raw,store=setup()
        try:
            apply_window(store,packet(T,{S:2}))
            facts=raw.execute('SELECT request_key,at_ns,revision,anchor_key FROM anomaly_detection.adp_facts').fetchall()
            publish_scope(store,ACTOR,S,T,[r['request_key'] for r in facts])
            class Clock:
                elapsed=0.
                def monotonic(self):return 100+self.elapsed
                def time_ns(self):return T+10*FIVE_NS+int(self.elapsed*1e9)
                def wait(self,n):self.elapsed+=max(10,n)
            class Source:
                page_size=128
                def __init__(self,project):self.project=Path(project);self.last_source=metadata(T);self.last_metrics=[]
                def page(self,after=None):return {'rows':[],'source':self.last_source,'after':None,'has_more':False}
                def profile(self,key):
                    row=next(r for r in facts if r['request_key']==key)
                    p=point(int(key,16),ACTOR,row['at_ns'],topic='one-bill',subject='one-bill')
                    p.update(version=PROFILE_VERSION,input_complete=True,actor_qualified=True,service_path=S,semantic_active=True,semantic_revision=row['revision'],anchor_key=row['anchor_key'])
                    return {'source':self.last_source,'request_key':key,'profile':p}
            cancellations=[];opened=[]
            def timeout(*args,**kwargs):
                cancellations.append(True)
                raw.execute("DO $$ BEGIN RAISE EXCEPTION 'worker isolation fixture' USING ERRCODE='57014'; END $$")
            def prepare(_):opened.append(True);return raw
            clock=Clock()
            with TemporaryDirectory(dir=ROOT/'validation') as temp, ExitStack() as stack:
                root=Path(temp)/'AnomalyDetection';root.mkdir()
                write_json(root/'RELEASE_MANIFEST.json',{'build_id':BUILD_ID,'source_sha256':'lane-fixture21'})
                stack.enter_context(patch('anomaly_detection.product_pipeline.read_window_burst',return_value=[{'status':'CAUGHT_UP'}]))
                stack.enter_context(patch('anomaly_detection.scenario_traffic.read_page',return_value={'status':'CAUGHT_UP','source':metadata(T)}))
                stack.enter_context(patch('anomaly_detection.service_sampling.read',return_value={'status':'CAUGHT_UP','source':metadata(T)}))
                stack.enter_context(patch.object(ProductStore,'audit_keys',return_value=[]))
                stack.enter_context(patch('anomaly_detection.audit_scope.keys',return_value=[]))
                target={'source':'anomaly_detection.product_pipeline.read_window_burst','primary':'anomaly_detection.product_worker.evaluate_job',
                        'audit_selection':'anomaly_detection.audit_scope.keys','maintenance':'anomaly_detection.job_scope.warm'}[mode]
                stack.enter_context(patch(target,side_effect=timeout))
                run(root,'lane-fixture21',source_factory=Source,prepare_pg=prepare,clock=clock,wait=clock.wait,max_cycles=8,web=False)
                state=read_json(root/'reports/product_status.json')
            assert cancellations and len(opened)==1,(mode,len(cancellations),state)
            assert state.get('content_reads')==2 and state.get('scenario_evaluations',0)>0,(mode,state)
            assert state.get('last_scenario_failure') is None,(mode,state)
            verify=engine.connect()
            assert verify.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_profiles').fetchone()['n']==2
            assert verify.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_scenario_jobs WHERE processed_version>0').fetchone()['n']>0
            checks[mode+'_timeout_does_not_starve_profiles_and_scenario_evaluation_or_reconnect']='PASS_REAL_SQL57014_SYNTHETIC_SOURCE_ONE_WRITER'
        finally:engine.close()


def main():
    checks={};references_and_ui(checks);finite_sampling(checks);worker_lanes(checks)
    report={'build_id':BUILD_ID,'status':'PASS_UNIFIED_CASES_AND_RESERVED_LANES_SQL','checks':checks,
        'owner_connections':0,'source_writes':0,'native_windows_postgresql21':'NOT_RUN','native_latency_capacity_precision_recall':'NOT_MEASURED',
        'financial_acceptance':'BLOCKED_EXTERNAL_DEPENDENCY','browser_visual_test':'NOT_RUN'}
    (ROOT/'validation/PRODUCT_revision21.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))


if __name__=='__main__':main()
