"""Owned evidence index, early real-target scheduling and timeout recovery.

Disposable synthetic PostgreSQL/WASM; no owner connection. The bad read plan
is reproduced by dropping only the new index inside this disposable database.
"""
from pathlib import Path
from unittest.mock import patch
from tempfile import TemporaryDirectory
import json

from transport import Engine
from anomaly_detection import BUILD_ID,FIVE_NS
from anomaly_detection.product_store import ProductStore,DDL
from anomaly_detection.product_pipeline import apply_window,owned_context
from anomaly_detection.product_dependencies import service_details
from anomaly_detection.job_scope import warm,promote_observed
from anomaly_detection.product_worker import run
from anomaly_detection.process_control import read_json,write_json
from check_revision10 import packet,TARGET,SESSION,SERVICES,metadata

ROOT=Path(__file__).resolve().parents[2]


def nodes(plan):
    yield plan
    for child in plan.get('Plans',[]):yield from nodes(child)


def main():
    engine=Engine();checks={}
    try:
        raw=engine.connect();raw.execute('CREATE SCHEMA anomaly_detection');store=ProductStore(raw);store.initialize()
        apply_window(store,packet(TARGET,{SERVICES[0]:3}),cursor_name='fixture')
        raw.execute("INSERT INTO anomaly_detection.adp_facts(request_key,anchor_key,session_key,at_ns,service_path,kind,state,revision,eligible,body,content_digest,last_seen_ns) "
            "SELECT lpad(to_hex(g),64,'0'),'ba1:'||lpad(to_hex(g+1000000),64,'0'),repeat('b',64),%s::bigint+g,%s,'service_execution','active',1,TRUE,'{}','fixture',%s "
            'FROM generate_series(500000,550000) g',(TARGET,SERVICES[0],TARGET))
        raw.execute("INSERT INTO anomaly_detection.adp_window_members SELECT %s,request_key,'{}' FROM anomaly_detection.adp_facts ON CONFLICT DO NOTHING",(TARGET,))
        raw.execute('ANALYZE anomaly_detection.adp_facts');raw.execute('ANALYZE anomaly_detection.adp_window_members')
        original=engine.query;plans=[]
        def traced(role,sql,args):
            if sql.startswith('SELECT f.request_key') and 'LIMIT 2048' in sql:
                plans.append(original(role,'EXPLAIN (ANALYZE,FORMAT JSON) '+sql,args)['rows'][0]['QUERY PLAN'][0]['Plan'])
            return original(role,sql,args)
        engine.query=traced
        raw.execute('DROP INDEX anomaly_detection.adp_fact_service_audited')
        job={'session_key':SESSION,'target_ns':TARGET+FIVE_NS}
        old,_=service_details(store,job,[SERVICES[0]])
        old_facts=[n for n in nodes(plans[-1]) if n.get('Relation Name')=='adp_facts']
        assert not old and sum(n.get('Rows Removed by Filter',0) for n in old_facts)>50000,old_facts
        raw.execute(next(q for q in DDL if 'CREATE INDEX IF NOT EXISTS adp_fact_service_audited ' in q))
        store.model_cache.clear();new,_=service_details(store,job,[SERVICES[0]])
        fact_plans=[n for n in nodes(plans[-1]) if n.get('Relation Name')=='adp_facts']
        assert new==old and fact_plans and all(n.get('Index Name')=='adp_fact_service_audited' for n in fact_plans),fact_plans
        assert all(n.get('Rows Removed by Filter',0)==0 and n['Actual Rows']==0 for n in fact_plans),fact_plans
        checks['empty_evidence_query_before_fix_scans_50004_facts_after_fix_zero']='PASS_EXPLAIN_ANALYZE'
        # Same eligibility and revision checks: the new index cannot turn stale
        # evidence into a training observation or alter a model's result.
        facts=raw.execute('SELECT request_key,body FROM anomaly_detection.adp_facts WHERE session_key=%s',(SESSION,)).fetchall()
        for i,row in enumerate(facts):
            body=json.loads(row['body']);body['revision']+=int(i==2)
            detail={'request_key':row['request_key'],'source_present':True,'semantic':body,'quality':{'evidence_available':True}}
            raw.execute('UPDATE anomaly_detection.adp_facts SET details=%s WHERE request_key=%s',(json.dumps(detail),row['request_key']))
        store.model_cache.clear();new,_=service_details(store,job,[SERVICES[0]])
        assert len(new)==2
        raw.execute('DROP INDEX anomaly_detection.adp_fact_service_audited')
        store.model_cache.clear();old,_=service_details(store,job,[SERVICES[0]])
        assert old==new
        raw.execute(next(q for q in DDL if 'CREATE INDEX IF NOT EXISTS adp_fact_service_audited ' in q))
        checks['indexed_and_previous_queries_return_identical_evidence_and_reject_stale_revision']='PASS'
        engine.query=original
        # The global cursor is far before this actor; assessed/positive targets
        # become reachable without waiting for every synthetic coverage row.
        values=[(f'{i+1000:064x}',TARGET) for i in range(600)]
        with raw.cursor() as cursor:
            cursor.executemany('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns,target_scope) VALUES(%s,%s,NULL)',values)
        normal=packet(TARGET+2*FIVE_NS,{SERVICES[1]:1},session='e'*64,offset=800000)
        busy=packet(TARGET+3*FIVE_NS,{SERVICES[0]:2},session='d'*64,offset=900000)
        apply_window(store,normal,cursor_name='normal');apply_window(store,busy,cursor_name='busy')
        raw.execute('UPDATE anomaly_detection.adp_jobs SET dirty=FALSE')
        raw.execute('UPDATE anomaly_detection.adp_jobs SET target_scope=NULL,dirty=TRUE,last_evaluated_ns=%s WHERE session_key=%s',(TARGET,'e'*64))
        raw.execute('UPDATE anomaly_detection.adp_jobs SET target_scope=NULL,dirty=TRUE WHERE session_key=%s',('d'*64,))
        before=[dict(r) for r in raw.execute('SELECT session_key,target_ns,version,processed_version,dirty,last_evaluated_ns,evaluation FROM anomaly_detection.adp_jobs WHERE session_key=ANY(%s) ORDER BY session_key',(['d'*64,'e'*64],)).fetchall()]
        cursor=warm(store,limit=64);assert cursor['after'][0]<'d'*64 and not cursor['done']
        promoted=promote_observed(store,limit=1);assert promoted=={'assessed':1,'positive':1},promoted
        after=[dict(r) for r in raw.execute('SELECT session_key,target_ns,version,processed_version,dirty,last_evaluated_ns,evaluation FROM anomaly_detection.adp_jobs WHERE session_key=ANY(%s) ORDER BY session_key',(['d'*64,'e'*64],)).fetchall()]
        assert before==after and store.state('job_scope_backfill_v1')==cursor
        assert store.next_job(TARGET+10*FIVE_NS)['session_key']=='e'*64
        checks['assessed_and_positive_targets_are_schedulable_before_the_global_scope_cursor_reaches_them']='PASS'
        checks['early_promotion_preserves_versions_decisions_dirty_flags_and_global_cursor']='PASS'
        prior=dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s',('e'*64,)).fetchone())
        context=owned_context(store,prior)
        def cancel_commit():
            raw.execute("DO $$ BEGIN RAISE EXCEPTION 'synthetic commit cancellation' USING ERRCODE='57014'; END $$")
        try:store.complete(prior,context,[],TARGET+10*FIVE_NS,fault=cancel_commit)
        except Exception as exc:assert getattr(exc,'sqlstate',None)=='57014'
        else:raise AssertionError('commit cancellation not reached')
        assert dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s',('e'*64,)).fetchone())==prior
        checks['real_sql_cancellation_after_result_writes_rolls_back_the_whole_owned_commit']='PASS'
        # Inject a genuine SQL statement cancellation during evaluation, then
        # prove another target completes on the SAME prepared connection/lease.
        raw.execute('UPDATE anomaly_detection.adp_jobs SET dirty=FALSE')
        raw.execute('UPDATE anomaly_detection.adp_jobs SET dirty=TRUE WHERE session_key=ANY(%s)',(['d'*64,'e'*64],))
        class Clock:
            elapsed=0.
            def monotonic(self):return 100+self.elapsed
            def time_ns(self):return TARGET+10*FIVE_NS+int(self.elapsed*1e9)
            def wait(self,n):self.elapsed+=max(.1,n)
        clock=Clock();calls={'prepare':0,'cancelled':False,'committed':0}
        def prepare(_):calls['prepare']+=1;return raw
        def evaluate(s,j,context,now,*,progress,mode='full'):
            if not calls['cancelled']:
                progress('service_evidence');calls['cancelled']=True
                s.raw.execute("DO $$ BEGIN RAISE EXCEPTION 'synthetic timeout, no input data' USING ERRCODE='57014'; END $$")
            progress('commit_result')
            result=s.complete(j,context,[],now)
            calls['committed']+=int(result['status']=='APPLIED');return result
        class Source:
            def __init__(self,_):raise RuntimeError('no owner source in this test')
        with TemporaryDirectory(dir=ROOT/'validation') as folder:
            root=Path(folder)/'AnomalyDetection';root.mkdir()
            write_json(root/'RELEASE_MANIFEST.json',{'build_id':BUILD_ID,'source_sha256':'isolated15'})
            with patch('anomaly_detection.product_worker.evaluate_job',side_effect=evaluate):
                run(root,'isolated15',source_factory=Source,prepare_pg=prepare,clock=clock,wait=clock.wait,max_cycles=5,web=False)
            state=read_json(root/'reports/product_status.json')
        assert calls['prepare']==1 and calls['cancelled'] and calls['committed']>0,calls
        assert state['evaluation_timeouts_total']==1 and state.get('source_failures_total',0)==0,state
        event=state['last_evaluation_failure_event'];assert event['phase']=='evaluate_service_evidence'
        assert event['queries'][-1]['sqlstate']=='57014'
        assert set(event['queries'][-1])=={'statement_id','operation','elapsed_seconds','sqlstate'}
        verify=engine.connect()
        assert verify.execute("SELECT COUNT(*) AS n FROM anomaly_detection.adp_jobs WHERE evaluation::jsonb->>'reason'='OWNED_EVALUATION_QUERY_TIMEOUT_RETRY'").fetchone()['n']==1
        checks['evaluation_sql_timeout_defers_only_that_target_and_other_work_commits_without_reconnect']='PASS'
        checks['failure_stage_and_bounded_statement_fingerprints_are_saved_without_sql_or_parameters']='PASS'
        report={'build_id':BUILD_ID,'status':'PASS_ISOLATED_POSTGRESQL_WASM','checks':checks,
            'owner_connections':0,'native_windows_postgresql':'NOT_RUN','native_timeout_statement_identity':'NOT_PRESENT_IN_RELEASE14_REPORT',
            'legacy_models_and_thresholds':'LEGACY_SCHEMA_CONTRACT_PRESERVED_REVIEW_AND_HOUR_QUALIFICATION_UPDATED_IN_RELEASE17','new_index_scope':'anomaly_detection.adp_facts_ONLY'}
        (ROOT/'validation/PRODUCT_revision15.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
    finally:engine.close()


if __name__=='__main__':main()
