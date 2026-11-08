"""Native product SQL + historical-correction/UI checks in isolated PostgreSQL WASM."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import time
import threading
import http.client
import re
from http.server import ThreadingHTTPServer
from urllib.parse import urlencode
from unittest.mock import patch

from transport import Engine
from anomaly_detection import BUILD_ID,FIVE_NS,CATALOG_SHA,SOURCE_SHA
from anomaly_detection.native_pg import prepare
from anomaly_detection.product_store import ProductStore
from anomaly_detection.product_source import ProductSource
from anomaly_detection.product_web import render
from anomaly_detection.product_web import serve
from anomaly_detection.product_worker import run
from anomaly_detection.product_engine import evaluate_job
from anomaly_detection.process_control import OwnedProcessLock,process_owner,read_json,write_json
from anomaly_detection.product_models import evaluate
from anomaly_detection.snapshot import ContractError,digest
from tests.fixture_factory import initial,START,key,anchor,SESSION_A
from tests.test_product_models import example,SERVICE


def main():
    engine=Engine();report={'build_id':BUILD_ID,'environment':'PGLITE_POSTGRESQL_WASM_PIPE',
        'native_windows_postgresql':'NOT_RUN','wire_pipeline_copy_concurrency_and_durability':'NOT_EVALUATED',
        'live_source_connections':0,'product_storage':'POSTGRESQL_ONLY'}
    try:
        # Synthetic source tables match the accepted names/types, never a live Viewer.
        schema=json.loads((Path(__file__).resolve().parents[2]/'reference/handoff_20261031/reference/viewer_schema_reference.json').read_text())['tables']
        for name,spec in schema.items():
            columns=[]
            for column in spec['columns']:
                kind={'INTEGER':'BIGINT','BLOB':'BYTEA','REAL':'DOUBLE PRECISION'}.get(column['declared_type'],column['declared_type'])
                columns.append('"'+column['name']+'" '+kind)
            engine.query('postgres','CREATE TABLE public."'+name+'"('+','.join(columns)+')',())
        fixture=initial()
        def insert(table,row):
            allowed={column['name'] for column in schema[table]['columns']}
            value={key:value for key,value in row.items() if key in allowed}
            cols=list(value)
            return engine.query('postgres','INSERT INTO public."'+table+'"('+','.join('"'+name+'"' for name in cols)+') VALUES ('+
                ','.join('$'+str(i+1) for i in range(len(cols)))+')',[value[name] for name in cols])
        for table,rows in fixture['tables'].items():
            for row in rows:insert(table,row)
        for row in fixture['tables']['viewer_events']:
            insert('viewer_raw_events',{'origin_key':row['origin_key'],'version_key':row['version_key']})
        insert('viewer_live_state',{'id':1,'stream_key':'synthetic-stream','keys_fingerprint':'synthetic-key-namespace',
            'generation':11,'next_ns':START+2*FIVE_NS,'lag_seconds':60,'last_error':None,'worker_status':'capturing'})
        insert('viewer_semantic_checkpoint',{'id':1,'generation':11,'state':'ready'})
        insert('viewer_service_catalog_state',{'id':1,'fingerprint':CATALOG_SHA})
        for at,end in fixture['scope']['complete_intervals_ns']:insert('viewer_live_windows',{'start_ns':at,'end_ns':end})
        before=engine.query('postgres','SELECT * FROM public.viewer_semantic_occurrences ORDER BY request_key',())['rows']
        with tempfile.TemporaryDirectory(prefix='AD product pg ',dir=Path(__file__).resolve().parents[1]) as temporary:
            project=Path(temporary);root=project/'AnomalyDetection';root.mkdir()
            (project/'viewer_config.local.py').write_text("DATABASE={'dbname':'p24_design_viewer','user':'postgres','password':'test-only'}")
            with patch('psycopg.connect',side_effect=engine.connect), \
                 patch('anomaly_detection.product_source.installed_source_identity',return_value={'runtime_sha256':SOURCE_SHA}):
                raw=prepare(root);store=ProductStore(raw);store.initialize();reader=ProductSource(project)
                packet=reader.page();result=store.apply_rows(packet['rows'],packet['source'],cursor_state=('semantic_cursor',{'after':packet['after']}))
                assert result['new']==6 and result['rows']==6,result
                assert store.apply_rows(packet['rows'],packet['source'])['changed']==0
                try:store.apply_rows(packet['rows'],dict(packet['source'],generation=10,semantic_generation=10))
                except ContractError as exc:assert str(exc)=='PRODUCT_SOURCE_GENERATION_REGRESSED'
                else:raise AssertionError('regressed source accepted')
                assert store.report()['registered_behaviors']==6
                context=reader.context({'session_key':SESSION_A,'target_ns':START+FIVE_NS})
                assert next(row for row in context['windows'] if row['start_ns']==START+FIVE_NS)['counts'][SERVICE]==1,context
                assert len([row for row in packet['rows'] if row['request_key']==key(1)])==1
                report['anchor_identity_cross_window_no_duplicate_and_replay']='PASS'
                keys=store.audit_keys(time.time_ns())
                snapshot=reader.audit(keys);audited=store.apply_audit(snapshot)
                assert audited['audited']==6,audited
                assert store.apply_audit(reader.audit(keys))['evidence_changes']==0
                report['all_kinds_including_null_service_audit_and_idempotence']='PASS'
                after=engine.query('postgres','SELECT * FROM public.viewer_semantic_occurrences ORDER BY request_key',())['rows']
                assert before==after
                try:engine.query('p24_anomaly_detection','UPDATE public.viewer_requests SET conflicted=1',())
                except RuntimeError as exc:assert exc.sqlstate=='42501',exc
                else:raise AssertionError('source write was not denied')
                report['source_read_only_and_role_write_denied']='PASS'
                # A semantic change must not partially advance a page/cursor.
                bad=deepcopy(packet['rows'][:2]);bad[0]['revision']=2;bad[0]['root_code']='changed'
                bad[1]['revision']=0
                old_cursor=store.state('semantic_cursor');old_count=store.report()['semantic_changes']
                try:store.apply_rows(bad,packet['source'],cursor_state=('semantic_cursor',{'after':'bad'}))
                except ContractError:pass
                else:raise AssertionError('invalid page accepted')
                assert store.state('semantic_cursor')==old_cursor and store.report()['semantic_changes']==old_count
                report['page_rollback_preserves_cursor_and_counts']='PASS'
                # The real worker loop runs against the isolated engine/source,
                # including a backlog. No current-time freshness gate is allowed.
                sha='test-product-build'
                write_json(root/'RELEASE_MANIFEST.json',{'build_id':BUILD_ID,'source_sha256':sha})
                class Clock:
                    elapsed=0
                    def monotonic(self):return 100+self.elapsed
                    def time_ns(self):return START+4*FIVE_NS+int((60+self.elapsed)*1e9)
                    def wait(self,seconds):self.elapsed+=max(1,seconds)
                clock=Clock()
                with OwnedProcessLock(root,'baseline_worker',sha):
                    try:run(root,sha,max_cycles=1,web=False)
                    except ContractError as exc:assert str(exc)=='BASELINE_PROCESS_ALREADY_RUNNING'
                    else:raise AssertionError('second worker admitted')
                raw.execute('UPDATE anomaly_detection.adp_facts SET next_audit_ns=0')
                apply_audit=ProductStore.apply_audit;audit_sizes=[]
                def constrained_audit(s,snapshot):
                    audit_sizes.append(len(snapshot.keys))
                    if len(snapshot.keys)>1:
                        with s.transaction():
                            s.raw.execute("DO $$ BEGIN RAISE EXCEPTION 'synthetic audit apply cancellation' USING ERRCODE='57014'; END $$")
                    return apply_audit(s,snapshot)
                with patch.object(ProductStore,'apply_audit',constrained_audit):
                    run(root,sha,clock=clock,wait=clock.wait,max_cycles=160,web=False)
                worker=read_json(root/'reports/product_status.json')
                assert worker['source_pages']>0 and worker['evaluated_jobs']>0 and worker['audited_requests']>0 and worker['cohort_windows']>0,worker
                assert any(n>1 for n in audit_sizes) and 1 in audit_sizes and store.state('regular_audit_size')['n']==1,audit_sizes
                assert worker['owned_apply_failures_total']>=2 and worker.get('source_failures_total',0)==0,worker
                report['audit_apply_cancellation_reduces_regular_batch_below_eight_to_one_and_other_lanes_progress']='PASS_REAL_SQL57014'
                assert worker['source_status']['backlog_seconds']>0 and worker['stop_reason']=='OFFLINE_TEST_CYCLE_BOUND',worker
                assert not process_owner(root)['locked']
                assert store.report()['semantic_changes']==6,store.report()
                # Test transport uses one PG session: explicitly release its
                # virtual connection's session lease before simulating restart.
                engine.query('postgres','SELECT pg_advisory_unlock_all()',())
                clock.elapsed+=1200
                run(root,sha,clock=clock,wait=clock.wait,max_cycles=40,web=False)
                engine.query('postgres','SELECT pg_advisory_unlock_all()',())
                restarted=read_json(root/'reports/product_status.json')
                assert restarted['evaluated_jobs']==0 and not restarted.get('last_storage_failure'),restarted
                # A restart/time jump does not manufacture changed inputs.
                # Genuine queued work must nevertheless resume on restart.
                store.invalidate(SESSION_A,START+FIVE_NS)
                run(root,sha,clock=clock,wait=clock.wait,max_cycles=40,web=False)
                engine.query('postgres','SELECT pg_advisory_unlock_all()',())
                assert read_json(root/'reports/product_status.json')['evaluated_jobs']>0
                report['unchanged_restart_is_idle_changed_input_restart_resumes']='PASS'
                report['worker_backlog_progress_all_lanes_single_writer_and_restart']='PASS_OFFLINE'
                # A late outcome with unchanged semantic revision dirties its
                # historic target and all already-evaluated dependent jobs.
                old_target=START+FIVE_NS;session='b'*64
                with raw.transaction():
                    raw.execute('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns,dirty,training_begin_ns,processed_version) VALUES(%s,%s,FALSE,%s,1)',
                        (session,old_target+FIVE_NS,old_target))
                    raw.execute('UPDATE anomaly_detection.adp_jobs SET dirty=FALSE,processed_version=version,training_begin_ns=%s WHERE session_key=%s AND target_ns=%s',
                        (old_target,session,old_target))
                insert('viewer_events',{'origin_key':key(19991),'version_key':key(29991),'request_key':key(8),'at_ns':old_target+10,'callpath':'DBPath.ud_prc_inquiryInvoiceResult2'})
                insert('viewer_raw_events',{'origin_key':key(19991),'version_key':key(29991)})
                insert('viewer_contract_observations',{'origin_key':key(19991),'version_key':key(29991),'request_key':key(8),
                    'at_ns':old_target+10,'callpath':'DBPath.ud_prc_inquiryInvoiceResult2','axis':'service_dispatch.inquiry_result',
                    'value':'GD2076','field_path':'statusCode','authority':'reported'})
                changed=store.apply_audit(reader.audit([key(8)]));assert changed['evidence_changes']==1
                jobs=raw.execute('SELECT target_ns,dirty FROM anomaly_detection.adp_jobs WHERE session_key=%s ORDER BY target_ns',(session,)).fetchall()
                assert all(row['dirty'] for row in jobs),jobs
                report['late_outcome_same_revision_invalidates_historic_target_and_future_models']='PASS'
                # No historical age cutoff: a 100-day-old input is registered.
                ancient=deepcopy(packet['rows'][0]);ancient.update(request_key=key(900001),anchor_key=anchor(900001),anchor_ns=START-100*288*FIVE_NS,revision=1)
                store.apply_rows([ancient],packet['source'])
                assert raw.execute('SELECT 1 FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',
                    (ancient['session_key'],ancient['anchor_ns']//FIVE_NS*FIVE_NS)).fetchone()
                report['historical_recheck_without_age_expiry']='PASS'
                # An uncached ancient job cannot block a newer ready context.
                store.invalidate(SESSION_A,old_target)
                ready_job=dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(SESSION_A,old_target)).fetchone())
                store.save_context(ready_job,reader.context(ready_job))
                next_ready=store.next_job(time.time_ns(),cached=True,recent=True)
                assert next_ready and next_ready['target_ns']==old_target and next_ready['session_key']==SESSION_A,next_ready
                assert store.next_job(time.time_ns())['target_ns']<old_target
                report['ready_context_not_starved_by_uncached_old_target']='PASS'
                # Native PG finding/incident lifecycle, input CAS and feedback.
                target=START+FIVE_NS;job=dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(SESSION_A,target)).fetchone())
                context=store.save_context(job,reader.context(job));job['version']=context['job_version'];context['evidence_verified']=True
                base={'session_key':SESSION_A,'target_ns':target,'status':'CANDIDATE','reason':'SYNTHETIC_TEST','score':9,
                    'service_path':SERVICE,'explanation_fa':'شرح آزمایشی','operator_alert':False,'witness_request_key':key(2)}
                decisions=[base|{'finding_key':'pf1:'+digest('rate'),'family':'rate_5m','dimension':'activity'},
                    base|{'finding_key':'pf1:'+digest('mix'),'family':'service_mix','dimension':'activity'},
                    base|{'finding_key':'pf1:'+digest('outcome'),'family':'business_result_change','dimension':'context'}]
                result=store.complete(job,context,decisions,time.time_ns());assert result['status']=='APPLIED'
                case=raw.execute('SELECT * FROM anomaly_detection.adp_incidents WHERE session_key=%s AND target_ns=%s',(SESSION_A,target)).fetchone()
                assert case['state']=='HOLD',case
                report['correlated_count_and_context_signals_do_not_create_independent_votes']='PASS'
                store.feedback(case['incident_key'],'reviewed_benign','<script>kept & escaped</script>',time.time_ns())
                job=dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(SESSION_A,target)).fetchone())
                store.complete(job,context,decisions,time.time_ns())
                case=raw.execute('SELECT * FROM anomaly_detection.adp_incidents WHERE incident_key=%s',(case['incident_key'],)).fetchone()
                assert case['state']=='HOLD' and case['revision']==1,case
                # New journey evidence can raise review priority, without any
                # automatic accusation or external notification.
                store.invalidate(SESSION_A,target);job=dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(SESSION_A,target)).fetchone())
                decisions.append(base|{'finding_key':'pf1:'+digest('journey'),'family':'service_sequence','dimension':'journey'})
                store.complete(job,context,decisions,time.time_ns())
                case=raw.execute('SELECT * FROM anomaly_detection.adp_incidents WHERE incident_key=%s',(case['incident_key'],)).fetchone()
                assert case['state']=='NEEDS_REVIEW' and not json.loads(case['body'])['operator_alert']
                page=render(store,{'state':'RUNNING','statistics':store.report()},'/incident/'+case['incident_key'],{},'test-csrf')
                assert 'dir="rtl"' in page and '&lt;script&gt;kept &amp; escaped&lt;/script&gt;' in page and '<script>kept' not in page
                assert 'http://127.0.0.1:5021/request/'+key(2) in page and 'name="csrf"' in page
                report['persian_ui_viewer_links_and_escaped_feedback']='PASS_RENDERED_HTML'
                # Incomplete replacement defers, rather than erasing a case.
                store.invalidate(SESSION_A,target);job=dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(SESSION_A,target)).fetchone())
                incomplete=dict(context,target_complete=False)
                store.complete(job,incomplete,[],time.time_ns())
                assert raw.execute("SELECT COUNT(*) AS n FROM anomaly_detection.adp_findings WHERE state='DEFERRED'").fetchone()['n']==4
                assert raw.execute('SELECT state FROM anomaly_detection.adp_incidents WHERE incident_key=%s',(case['incident_key'],)).fetchone()['state']=='HOLD'
                # Complete zero revises existing findings; review notes survive.
                store.invalidate(SESSION_A,target);new_job=dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(SESSION_A,target)).fetchone())
                assert store.complete(job,context,decisions,time.time_ns())['status']=='INPUT_CHANGED_RETRY'
                store.complete(new_job,context,[decision|{'status':'NO_DEVIATION_OBSERVED'} for decision in decisions],time.time_ns())
                assert raw.execute('SELECT state FROM anomaly_detection.adp_incidents WHERE incident_key=%s',(case['incident_key'],)).fetchone()['state']=='WITHDRAWN'
                assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_feedback').fetchone()['n']==1
                report['defer_withdraw_input_version_cas_and_feedback_survival']='PASS'
                # Fault after all writes must roll back finding versions and job
                # checkpoint together, so a restart can retry exactly once.
                store.invalidate(SESSION_A,target)
                retry=dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(SESSION_A,target)).fetchone())
                previous_versions=raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_finding_versions').fetchone()['n']
                def fail():raise RuntimeError('injected-at-commit-boundary')
                try:store.complete(retry,context,decisions,time.time_ns(),fault=fail)
                except RuntimeError:pass
                else:raise AssertionError('commit fault not raised')
                assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_finding_versions').fetchone()['n']==previous_versions
                assert raw.execute('SELECT dirty FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(SESSION_A,target)).fetchone()['dirty']
                store.complete(retry,context,decisions,time.time_ns())
                store.feedback(case['incident_key'],'confirmed_suspicious','exclude from training',time.time_ns())
                future=dict(retry,target_ns=target+FIVE_NS)
                assert target in store.excluded_windows(future)
                # Fresh source summaries must not reintroduce excluded data.
                inspected={}
                def inspect_context(ctx,hist,details,**_):inspected.update(context=ctx,history=hist,details=details);return []
                future_context=dict(context,target_ns=target+FIVE_NS,windows=context['windows']+[dict(context['windows'][0],start_ns=target+FIVE_NS)])
                with patch('anomaly_detection.product_engine.evaluate',side_effect=inspect_context):evaluate_job(store,future,future_context,time.time_ns())
                assert target not in [row['start_ns'] for row in inspected['history']]
                assert not [row for row in inspected['context']['events'] if row['anchor_ns']//FIVE_NS*FIVE_NS==target]
                store.feedback(case['incident_key'],'reviewed_benign','latest decision restores eligibility',time.time_ns())
                assert target not in store.excluded_windows(future)
                report['atomic_result_commit_and_latest_feedback_training_exclusion']='PASS'
                # Real local HTTP routing, tokens, cross-origin rejection,
                # feedback persistence and safe rendering (no browser claimed).
                ready=threading.Event();port=[]
                class Server(ThreadingHTTPServer):
                    def __init__(self,address,handler):
                        super().__init__((address[0],0),handler);port.append(self.server_port);ready.set()
                errors=[]
                def web():
                    try:serve(root,sha,server_class=Server)
                    except BaseException as exc:errors.append(repr(exc))
                thread=threading.Thread(target=web,daemon=True);thread.start();assert ready.wait(5)
                def request(method,path,body=None,headers=None):
                    connection=http.client.HTTPConnection('127.0.0.1',port[0],timeout=5)
                    connection.request(method,path,body,headers={'Host':'127.0.0.1:5022',**(headers or {})})
                    response=connection.getresponse();result=(response.status,dict(response.getheaders()),response.read().decode());connection.close();return result
                try:
                    code,headers,page=request('GET','/incident/'+case['incident_key']);assert code==200,(code,page)
                    cookie=headers['Set-Cookie'].split(';')[0];token=re.search('name="csrf" value="([0-9a-f]+)"',page).group(1)
                    payload=urlencode({'csrf':token,'incident':case['incident_key'],'label':'needs_evidence','note':'<script>HTTP & feedback</script>'})
                    assert request('GET','/',headers={'Host':'foreign.example'})[0]==403
                    assert request('POST','/feedback',payload,{'Cookie':cookie,'Origin':'https://foreign.example','Content-Type':'application/x-www-form-urlencoded'})[0]==403
                    assert request('POST','/feedback',payload.replace(token,'bad'),{'Cookie':cookie,'Content-Type':'application/x-www-form-urlencoded'})[0]==403
                    assert request('POST','/feedback',payload,{'Cookie':cookie,'Origin':'http://127.0.0.1:5022','Content-Type':'application/x-www-form-urlencoded'})[0]==303
                    code,headers,page=request('GET','/incident/'+case['incident_key'],headers={'Cookie':cookie})
                    assert code==200 and '&lt;script&gt;HTTP &amp; feedback&lt;/script&gt;' in page
                    stable=raw.execute('SELECT case_key FROM anomaly_detection.adp_cases ORDER BY case_key LIMIT 1').fetchone()['case_key']
                    code,headers,page=request('GET','/case/'+stable,headers={'Cookie':cookie})
                    assert code==200 and 'dir="rtl"' in page and 'تاریخچه' not in stable
                    revision=re.search('name="case_revision" value="([0-9]+)"',page).group(1)
                    receipt=re.search('name="review_input_token" value="([0-9a-f]{64})"',page).group(1)
                    payload=urlencode({'csrf':token,'incident':stable,'case_revision':revision,'review_input_token':receipt,'label':'needs_evidence','note':'<img src=x> stable HTTP'})
                    assert request('POST','/feedback',payload,{'Cookie':cookie,'Origin':'https://foreign.example','Content-Type':'application/x-www-form-urlencoded'})[0]==403
                    code,headers,_=request('POST','/feedback',payload,{'Cookie':cookie,'Origin':'http://127.0.0.1:5022','Content-Type':'application/x-www-form-urlencoded'})
                    assert code==303 and headers['Location']=='/case/'+stable
                    assert request('POST','/feedback',payload,{'Cookie':cookie,'Origin':'http://127.0.0.1:5022','Content-Type':'application/x-www-form-urlencoded'})[0]==409
                    code,_,page=request('GET','/case/'+stable,headers={'Cookie':cookie})
                    assert code==200 and '&lt;img src=x&gt; stable HTTP' in page and '<img src=x>' not in page
                    report['stable_case_http_summary_detail_csrf_feedback_redirect_and_escape']='PASS_HTTP_NOT_BROWSER'
                    for path in ('/','/coverage','/scenarios','/incidents?state=ALL','/evaluation/'+SESSION_A+'/'+str(START)+'/proof','/request/'+key(2),'/api/status','/legacy'):
                        code,_,page=request('GET',path);assert code==200,(path,code,page)
                    assert request('GET','/missing')[0]==404
                    assert request('GET','/incidents?state=bad')[0]==400
                finally:
                    owner=process_owner(root,'web')['owner'];write_json(root/'data/web_stop_request.json',{'instance_token':owner['instance_token']})
                    thread.join(5)
                assert not thread.is_alive() and not errors,errors
                report['local_http_rtl_review_csrf_escape_and_routes']='PASS_HTTP_NOT_BROWSER'
                # Reuse an already-migrated PG summary only with the same
                # stream/key binding. This is not a file-database migration.
                with raw.transaction():
                    raw.execute('CREATE TABLE anomaly_detection.ah_state(id BIGINT PRIMARY KEY,body TEXT NOT NULL)')
                    raw.execute('CREATE TABLE anomaly_detection.ah_windows(session_key TEXT,start_ns BIGINT,body TEXT,last_valid TEXT,PRIMARY KEY(session_key,start_ns))')
                    raw.execute('INSERT INTO anomaly_detection.ah_state VALUES(1,%s)',(json.dumps({'binding':store.state('source_binding')}),))
                    past={'start_ns':START-FIVE_NS,'coverage_complete':True,'population_complete':True,'counts':{SERVICE:2}}
                    raw.execute('INSERT INTO anomaly_detection.ah_windows VALUES(%s,%s,%s,%s)',(SESSION_A,past['start_ns'],json.dumps(past),json.dumps(past)))
                    store.save_state('previous_import',{})
                imported=store.import_previous();assert imported['done'] and imported['rows']==1,imported
                assert store.import_previous()==imported
                assert raw.execute('SELECT 1 FROM anomaly_detection.adp_windows WHERE session_key=%s AND start_ns=%s',(SESSION_A,past['start_ns'])).fetchone()
                report['existing_postgresql_history_binding_checked_import_idempotent']='PASS'
                # Reopening the same PG state is idempotent and creates no file DB.
                raw.close();raw=prepare(root);store=ProductStore(raw);store.initialize()
                assert store.report()['registered_behaviors']==7
                assert not list(root.rglob('*.sqlite*'))
                raw.close()
                report['postgres_only_restart_no_file_database']='PASS'
                report['status']='PASS_PRODUCT_SQL_AND_HISTORICAL_CORRECTION_CONTRACT_NOT_NATIVE_CAPACITY'
    finally:engine.close()
    path=Path(__file__).resolve().parents[1]/'PRODUCT_engine_contract.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(report,ensure_ascii=False))


if __name__=='__main__':main()
