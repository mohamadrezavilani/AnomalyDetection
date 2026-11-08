"""Same readiness policy, bounded optional counts and actual GET failure paths.

An optional owner export supplies case/signal/member shapes. Missing job rows
are synthetic lookups constrained by exported current_method_input, never
labelled a complete native replay or a production precision/capacity test.
"""
import argparse,io,json,time,zipfile,hashlib,threading,http.client
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from http.server import ThreadingHTTPServer
from urllib.request import urlopen,Request
from transport import Engine
from review_sql22_reference import cte as previous
from anomaly_detection import BUILD_ID,FIVE_NS
from anomaly_detection.product_store import ProductStore
from anomaly_detection.case_summary import cte,signals,render,filters,groups
from anomaly_detection.product_web import serve
from anomaly_detection.process_control import write_json,read_json
from anomaly_detection.cases import replace_scope
from anomaly_detection.snapshot import canonical
from check_revision17 import load
from check_revision19 import insert_many

ROOT=Path(__file__).resolve().parents[2]


def restore(raw,path):
    with zipfile.ZipFile(path) as outer:
        with zipfile.ZipFile(io.BytesIO(outer.read('case_review.zip'))) as z:
            read=lambda n:[json.loads(l) for l in z.read(n+'.jsonl').splitlines()]
            cases=read('cases');items=read('case_signals');members=read('case_members')
            load(raw,'adp_cases',cases);load(raw,'adp_case_signals',items);load(raw,'adp_case_requests',members)
    actors={};pop={}
    for s in items:
        if s['source_kind']=='actor':actors.setdefault((s['job_session'],s['target_ns']),[]).append(s)
        elif s['source_kind']=='population':pop.setdefault(s['target_ns'],[]).append(s)
    jobs=[]
    for (actor,at),rows in actors.items():
        normal=[s for s in rows if s['current_method_input'] and not(s['family']=='peer_service_rate_5m' and s.get('primary_version') is not None)]
        peers=[s for s in rows if s['family']=='peer_service_rate_5m' and s.get('primary_version') is not None]
        current_peers=[s for s in peers if s['current_method_input']]
        jobs.append({'session_key':actor,'target_ns':at,'version':normal[0]['job_version'] if normal else max(s['job_version'] for s in rows)+1,
            'primary_version':current_peers[0]['primary_version'] if current_peers else max([s['primary_version'] for s in peers]+[0])+1,
            'dirty':not bool(normal),'evaluation':canonical({'pending_families':[]})})
    insert_many(raw,'adp_jobs',[('session_key','TEXT'),('target_ns','BIGINT'),('version','BIGINT'),('primary_version','BIGINT'),('dirty','BOOLEAN'),('evaluation','TEXT')],jobs)
    insert_many(raw,'adp_population_jobs',[('start_ns','BIGINT'),('dirty','BOOLEAN'),('version','BIGINT')],[{'start_ns':at,'dirty':not any(s['current_method_input'] for s in rows),'version':next((s['job_version'] for s in rows if s['current_method_input']),max(s['job_version'] for s in rows)+1)} for at,rows in pop.items()])
    actual={r['signal_key']:r['current_input'] for r in raw.execute(signals()+'unused AS (SELECT 1) SELECT signal_key,current_input FROM signal_inputs').fetchall()}
    assert all(actual[s['signal_key']]==s['current_method_input'] for s in items)
    return {'cases':len(cases),'signals':len(items),'members':len(members),'synthetic_job_lookups':len(jobs),'pending_families_in_missing_jobs':'UNAVAILABLE_ASSUMED_EMPTY_FOR_SHAPE_TEST_ONLY','native_complete_replay':False}


def main(path=None):
    engine=Engine();checks={};corpus={}
    try:
        raw=engine.connect();raw.execute('CREATE SCHEMA anomaly_detection');store=ProductStore(raw);store.initialize()
        if path:corpus=restore(raw,path)
        # Add feature and ordinary actor controls, including pending methods,
        # missing dependencies and explicit operator feedback.
        at=1_800_000_000_000_000_000//FIVE_NS*FIVE_NS
        for i in range(8):
            actor=f'{900000+i:064x}'
            raw.execute('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns,version,dirty,evaluation) VALUES(%s,%s,1,%s,%s)',(actor,at,i==2,canonical({'pending_families':['peer_service_rate_5m'] if i==3 else []})))
            d={'signal_key':'ui23:'+str(i),'family':'peer_service_rate_5m','service_path':'Fixture/Review','status':'CANDIDATE','observed':20 if i!=1 else 2,'upper':3,'expected':1,'score':2.,'evidence_verified':i!=4,'single_signal_review_eligible':True,'begin_ns':at,'end_ns':at+FIVE_NS}
            with store.transaction():replace_scope(store,'fixture23:'+str(i),[d],at,job={'session_key':actor,'target_ns':at,'version':1})
        key=raw.execute("SELECT case_key,revision FROM anomaly_detection.adp_cases WHERE service_path='Fixture/Review' ORDER BY case_key LIMIT 1").fetchone()
        raw.execute("INSERT INTO anomaly_detection.adp_case_feedback(case_key,label,note,created_ns,case_revision) VALUES(%s,'needs_evidence','operator fixture',%s,%s)",(key['case_key'],at,key['revision']))
        columns='SELECT case_key,bucket,fresh,needs_recheck,stale_signals,can_review,evidence_pending,review_label,body FROM effective ORDER BY case_key'
        begin=time.monotonic();old=raw.execute(previous()+columns).fetchall();old_seconds=time.monotonic()-begin
        begin=time.monotonic();new=raw.execute(cte()+columns).fetchall();new_seconds=time.monotonic()-begin
        assert old==new
        checks['every_case_readiness_currentness_selected_signal_and_feedback_match_release22']='PASS_EXACT_SQL_ROW_EQUALITY'
        _,_,_,condition,params=filters({});rows,metrics,leads=groups(store,'services',condition,params,0)
        assert rows and leads and all(metrics[r['group_key']]['executions'] is not None for r in rows[:25])
        checks['group_lead_and_current_case_selection_are_read_in_one_query']='PASS_SQL'
        original=engine.query;fail_metrics=True;fail_page=False
        def cancel(role,sql,args):
            if (fail_metrics and 'counts AS (SELECT' in sql) or (fail_page and 'SELECT g.*,l.body AS lead_body' in sql):
                return original(role,"DO $$ BEGIN RAISE EXCEPTION 'page timeout private fixture' USING ERRCODE='57014'; END $$",())
            return original(role,sql,args)
        engine.query=cancel
        with raw.transaction():
            raw.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            html=render(store,{})
            assert '<table' in html and '—' in html and 'شمار شواهد' in html
        assert raw.execute('SELECT 1 AS n').fetchone()['n']==1
        checks['optional_evidence_count_timeout_keeps_current_issues_visible_and_unknown_counts_are_not_zero']='PASS_REAL_SQL57014_READ_ONLY_SAVEPOINT'
        fail_metrics=False
        with TemporaryDirectory(dir=ROOT/'validation') as temp:
            root=Path(temp)/'AnomalyDetection';root.mkdir();sha='web-fixture23'
            write_json(root/'RELEASE_MANIFEST.json',{'build_id':BUILD_ID,'source_sha256':sha})
            write_json(root/'reports/product_status.json',{'build_id':BUILD_ID,'source_sha256':sha})
            @contextmanager
            def database(_root,*,readonly=False):assert readonly;yield raw
            ready=threading.Event();ports=[];errors=[]
            class Server(ThreadingHTTPServer):
                def __init__(self,address,handler):super().__init__((address[0],0),handler);ports.append(self.server_port);ready.set()
            def web():
                try:serve(root,sha,server_class=Server)
                except BaseException as e:errors.append(repr(e))
            with patch('anomaly_detection.product_web.database',side_effect=database):
                thread=threading.Thread(target=web,daemon=True);thread.start();assert ready.wait(5)
                def get(path):
                    c=http.client.HTTPConnection('127.0.0.1',ports[0],timeout=20)
                    c.request('GET',path,headers={'Host':'127.0.0.1:5022'});r=c.getresponse();value=(r.status,r.read().decode());c.close();return value
                try:
                    fail_page=True;code,body=get('/incidents')
                    assert code==503 and 'از زمان مجاز گذشت' in body and 'دسترسی به مخزن PostgreSQL آماده نیست' not in body
                    trace=read_json(root/'reports/web_diagnostics.json')
                    assert trace['events'][-1]['failure']['sqlstate']=='57014'
                    assert any(q['sqlstate']=='57014' for q in trace['events'][-1]['queries'])
                    fail_page=False
                    with patch('anomaly_detection.product_web.render',side_effect=RuntimeError('private payload must not be exported')):
                        code,body=get('/incidents');assert code==500 and 'خطا در نمایش' in body
                    assert 'private payload' not in json.dumps(read_json(root/'reports/web_diagnostics.json'))
                    from anomaly_detection.web_diagnostics import probe
                    def opener(req,timeout):return urlopen(Request(req.full_url.replace(':5022',':'+str(ports[0])),headers={'Host':'127.0.0.1:5022'}),timeout=timeout)
                    proof=probe(opener=opener);assert proof['status']=='PASS_LOCAL_GETS',proof
                    checks['incidents_service_user_and_case_views_and_status_succeed_as_actual_http_gets']='PASS_HTTP_NOT_BROWSER'
                    checks['sql_timeout_and_python_render_error_have_distinct_status_messages_and_safe_trace']='PASS_503_VS_500_EXACT_HANDLER_PATH'
                finally:
                    from anomaly_detection.process_control import process_owner
                    owner=process_owner(root,'web')['owner'];write_json(root/'data/web_stop_request.json',{'instance_token':owner['instance_token']})
                    thread.join(5);assert not thread.is_alive() and not errors,errors
        report={'build_id':BUILD_ID,'status':'PASS_REVIEW_QUERY_EQUIVALENCE_AND_HTTP_FAILURE_ISOLATION','checks':checks,'corpus':corpus,
            'comparison_rows':len(new),'isolated_sql_seconds':{'release22':round(old_seconds,6),'release23':round(new_seconds,6)},
            'owner_connections':0,'production_source_writes':0,'native_windows_postgresql23':'NOT_RUN','production_precision_recall_capacity':'NOT_MEASURED','browser_visual':'NOT_RUN'}
        (ROOT/'validation/PRODUCT_revision23.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
    finally:engine.close()


if __name__=='__main__':
    args=argparse.ArgumentParser();args.add_argument('--snapshot',type=Path);main(args.parse_args().snapshot)
