"""Worker-loop recovery, complete model graphs and restartable scope migration."""
from contextlib import contextmanager,redirect_stdout
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch,MagicMock

from anomaly_detection import BUILD_ID,EVALUATOR_VERSION,FIVE_NS
from anomaly_detection.behavior_scope import BEHAVIOR,FULL,FEATURES,MIGRATION,advance_migration


def source(contract=BEHAVIOR,epoch=1):
    return dict(namespace='viewer:fixture',stream_key='fixture',keys_fingerprint='fixture',generation=1,
        semantic_generation=1,input_contract=contract,scope_epoch=epoch,behavioral_features=FEATURES,
        financial_relations='OUT_OF_SCOPE' if contract==BEHAVIOR else 'COMPLETE',captured_at_ns=100*FIVE_NS)


class ConsoleTests(unittest.TestCase):
    def test_worker_status_preserves_persian_json_through_a_non_unicode_windows_pipe(self):
        from anomaly_detection import product_cli
        payload=dict(health='RUNNING',explanation='سلام؛ شاهد و نتیجه محفوظ است')
        buffer=io.BytesIO();console=io.TextIOWrapper(buffer,encoding='cp1252',errors='strict')
        with patch('sys.argv',['run_anomaly.py','worker-status']),patch.object(product_cli,'status',return_value=payload),redirect_stdout(console):
            code=product_cli.main('fixture')
        console.flush()
        self.assertEqual(code,0);self.assertEqual(json.loads(buffer.getvalue()),payload)

    def test_unavailable_source_contract_defers_reads_but_runs_owned_scenario_models(self):
        from anomaly_detection.scenario_worker import step
        src=MagicMock();store=MagicMock();state={};clock=MagicMock();clock.time_ns.return_value=1
        with patch('anomaly_detection.scenario_store.process_one',return_value={'status':'APPLIED','scope_key':'fixture'}) as model, \
             patch('anomaly_detection.scenario_store.next_profile') as profiles:
            step(store,src,clock,0,state,source_ready=False)
        model.assert_called_once();profiles.assert_not_called();src.profile.assert_not_called()
        self.assertEqual(state['scenario_evaluations'],1);self.assertTrue(state['scenario_source_reads_deferred'])


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'disposable native PostgreSQL required')
class NativeBehaviorRecoveryTests(unittest.TestCase):
    from tests.test_runtime_bounds_pg import RuntimeBoundsTests as Fixture
    setUpClass=classmethod(Fixture.setUpClass.__func__)
    tearDownClass=classmethod(Fixture.tearDownClass.__func__)
    setUp=Fixture.setUp

    def run_worker_fixture(self,*,contract_timeout=True,contract_rejection=False,owned_timeout=False,admissions=None):
        from anomaly_detection import product_worker
        from psycopg.errors import QueryCanceled
        from psycopg.rows import dict_row
        class Clock:
            now=100.
            def monotonic(self):return self.now
            def time_ns(self):return int(self.now*1_000_000_000)
            def wait(self,value):self.now+=max(5,value)
        class Source:
            last_source={};last_metrics=[];calls=0
            @contextmanager
            def snapshot(self):yield object()
            def metadata(self,q):
                self.calls+=1
                if contract_timeout and self.calls==1:raise QueryCanceled('fixture source metadata timeout')
                if contract_rejection and self.calls==1:return source(FULL,0)
                return source()
            def profile(self,key):raise AssertionError('no source profile reads in this fixture')
        src=Source();clock=Clock();prepared=[];reserved=[];failures=[]
        if contract_rejection:
            with self.store.transaction():self.store.bind(source())
        def prepare(root):
            conn=self.psycopg.connect(**self.params,dbname=self.name,autocommit=True,row_factory=dict_row)
            prepared.append(conn);return conn
        def scenario(store,src,clock,cycle,state,*,source_ready):
            self.assertFalse(store.raw.closed)
            self.assertEqual(store.raw.execute('SELECT 1 AS value').fetchone()['value'],1)
            reserved.append(source_ready)
            if state.get('last_source_failure') or state.get('last_storage_failure'):failures.append(deepcopy(state))
        from anomaly_detection.product_store import ProductStore
        original_bind=ProductStore.bind;bound=[False]
        def bind(store,metadata):
            if owned_timeout and not bound[0]:
                bound[0]=True
                store.raw.execute("SET LOCAL statement_timeout='1ms'")
                store.raw.execute('SELECT pg_sleep(0.02)')
            return original_bind(store,metadata)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'RELEASE_MANIFEST.json').write_text(json.dumps(dict(build_id=BUILD_ID,source_sha256='f'*64)))
            with patch('anomaly_detection.runtime_lanes.maintenance'), \
                 patch('anomaly_detection.product_scheduling.EvaluationScheduler.choose',return_value=(None,'history')), \
                 patch('anomaly_detection.product_pipeline.read_window_burst',return_value=[dict(status='CAUGHT_UP')]), \
                 patch('anomaly_detection.audit_scope.keys',return_value=[]), \
                 patch.object(ProductStore,'bind',bind), \
                 patch('anomaly_detection.scenario_worker.step',side_effect=scenario), \
                 patch('anomaly_detection.viewer_priority.ViewerPriority.admit',side_effect=admissions or
                       [dict(admitted=True,mode='VIEWER_IDLE',writer_busy=False)]*3):
                result=product_worker.run(root,'f'*64,source_factory=lambda _:src,prepare_pg=prepare,
                    clock=clock,wait=clock.wait,max_cycles=3,web=False)
            end=json.loads((root/'reports/product_status.json').read_text())
        self.assertEqual(result,0);self.assertEqual(len(prepared),1)
        return src,reserved,failures,end

    def test_real_worker_loop_source_contract_timeout_keeps_owned_connection_and_reserved_work_then_recovers(self):
        src,reserved,failures,end=self.run_worker_fixture()
        self.assertGreaterEqual(src.calls,2);self.assertIn(False,reserved);self.assertIn(True,reserved)
        self.assertTrue(any(s['state']=='DEGRADED_SOURCE' for s in failures))
        self.assertTrue(all(s['last_storage_failure'] is None for s in failures))
        self.assertEqual(failures[0]['last_source_failure_event']['phase'],'read_input_contract')
        self.assertEqual(end['input_contract_check']['status'],'CURRENT')
        self.assertEqual(end['input_contract']['input_contract'],BEHAVIOR)
        self.assertIsNone(end['last_source_failure'])

    def test_real_worker_loop_does_not_bypass_viewer_admission_in_the_reserved_finally_lane(self):
        denied=dict(admitted=False,mode='WAITING_FOR_VIEWER_PUBLICATION',writer_busy=True)
        allowed=dict(admitted=True,mode='BOUNDED_FAIRNESS_CYCLE',writer_busy=True)
        src,reserved,failures,end=self.run_worker_fixture(contract_timeout=False,admissions=[denied,denied,allowed])
        self.assertEqual(src.calls,1)
        self.assertEqual(reserved,[True]);self.assertEqual(failures,[])

    def test_real_worker_loop_rejects_regressed_source_contract_without_closing_owned_storage(self):
        src,reserved,failures,end=self.run_worker_fixture(contract_timeout=False,contract_rejection=True)
        self.assertEqual(failures[0]['last_source_failure']['code'],'PRODUCT_INPUT_CONTRACT_EPOCH_REGRESSED')
        self.assertEqual(failures[0]['last_source_failure_event']['phase'],'apply_input_contract')
        self.assertTrue(all(s['last_storage_failure'] is None for s in failures))
        self.assertEqual(end['input_contract_check']['status'],'CURRENT');self.assertIsNone(end['last_source_failure'])

    def test_real_worker_loop_retries_rolled_back_owned_contract_write_without_mislabeling_the_source(self):
        src,reserved,failures,end=self.run_worker_fixture(contract_timeout=False,owned_timeout=True)
        self.assertTrue(all(s['last_source_failure'] is None for s in failures))
        self.assertEqual(failures[0]['state'],'DEGRADED_OWNED_APPLY')
        self.assertEqual(failures[0]['last_owned_apply_failure_event']['phase'],'apply_input_contract')
        self.assertEqual(end['input_contract_check']['status'],'CURRENT')
        self.assertFalse(end['contract_apply_blocked']);self.assertIsNone(end['last_storage_failure'])

    def test_evaluate_job_persists_resolvable_model_graph_and_does_not_mutate_provider_cache(self):
        from anomaly_detection.product_engine import evaluate_job
        from anomaly_detection.snapshot import digest
        values=[]
        for name,family in [('parent','peer_service_rate_5m'),('child','input_subject_burst')]:
            model=dict(model_id='fixture:'+name)
            decision=dict(finding_key='pf1:'+digest(name),family=family,dimension='activity',status='CANDIDATE',score=1,
                          service_path='Services.v1/WaterBills',model=model,model_id=model['model_id'])
            if name=='child':model['reference_model_id']='fixture:parent';decision['reference_model_id']='fixture:parent'
            values.append(decision)
        values.append(dict(values[0],family='service_mix',finding_key='pf1:'+digest('alias')))
        original=deepcopy(values)
        for i,contract in enumerate((FULL,BEHAVIOR)):
            src=source(contract,0 if contract==FULL else 1);actor=str(i+1)*64;target=100*FIVE_NS
            emitted=deepcopy(values)
            for decision in emitted:decision['finding_key']='pf1:'+digest([actor,decision['family']])
            expected_emitted=deepcopy(emitted)
            with self.store.transaction():
                self.store.bind(src)
                self.raw.execute('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns) VALUES(%s,%s)',(actor,target))
            job=dict(self.raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s',(actor,)).fetchone())
            context=dict(source=src,session_key=actor,target_ns=target,windows=[],events=[],target_complete=False)
            with patch('anomaly_detection.product_engine.evaluate',return_value=emitted), \
                 patch('anomaly_detection.context_models.evaluate',return_value=[]), \
                 patch('anomaly_detection.service_reference.decisions',return_value=([],{})), \
                 patch('anomaly_detection.input_subjects.decisions',return_value=[]):
                first=evaluate_job(self.store,job,context,target)
                self.assertEqual(first['status'],'APPLIED')
                evaluate_job(self.store,job,context,target+1)
            self.assertEqual(values,original)
            self.assertEqual(emitted,expected_emitted)
            models=[json.loads(r['body']) for r in self.raw.execute('SELECT body FROM anomaly_detection.adp_models').fetchall()]
            ids={m['model_id'] for m in models}
            self.assertTrue(all(m.get('reference_model_id') in ids for m in models if m.get('reference_model_id')))
            stored=json.loads(self.raw.execute('SELECT evaluation FROM anomaly_detection.adp_jobs WHERE session_key=%s',(actor,)).fetchone()['evaluation'])
            self.assertTrue(all(d['model_id'] in ids and (not d.get('reference_model_id') or d['reference_model_id'] in ids) for d in stored['decisions']))
        self.assertEqual(len(models),4)

    def test_scope_migration_is_bounded_resumes_after_rollback_and_keeps_history_feedback_and_models(self):
        from anomaly_detection.snapshot import canonical
        self.store.bind(source(FULL,0))
        # Interleave unrelated parents; a sparse WHERE family filter must not
        # turn a small page into an unbounded whole-table selection.
        self.raw.execute("INSERT INTO anomaly_detection.adp_findings SELECT 'f-'||lpad(i::text,6,'0'),'actor',%s,"
            "CASE WHEN i%%3=0 THEN 'payment_result_change' ELSE 'rate_5m' END,'context','ACTIVE',1,1,'old',"
            "json_build_object('family',CASE WHEN i%%3=0 THEN 'payment_result_change' ELSE 'rate_5m' END,'status','CANDIDATE')::text,1 FROM generate_series(1,513) i",(FIVE_NS,))
        self.raw.execute('INSERT INTO anomaly_detection.adp_finding_versions SELECT finding_key,revision,body,updated_ns FROM anomaly_detection.adp_findings')
        self.raw.execute("INSERT INTO anomaly_detection.adp_case_signals(signal_key,case_key,scope_key,target_ns,job_version,source_kind,family,state,qualified,review_eligible,begin_ns,end_ns,score,body,content_digest,updated_ns) "
            "SELECT 's-'||lpad(i::text,6,'0'),'c-'||lpad(i::text,6,'0'),'scope',%s,1,'actor',CASE WHEN i%%3=0 THEN 'payment_result_change' ELSE 'rate_5m' END,'ACTIVE',TRUE,TRUE,%s,%s,1,'{}','old',1 FROM generate_series(1,513) i",(FIVE_NS,FIVE_NS,2*FIVE_NS))
        self.raw.execute("INSERT INTO anomaly_detection.adp_cases(case_key,entity_type,entity_key,issue_kind,service_path,state,revision,body,content_digest,first_ns,last_ns,updated_ns) "
            "SELECT 'c-'||lpad(i::text,6,'0'),'actor','actor',CASE WHEN i%%3=0 THEN 'payment_profile' ELSE 'activity' END,'service','HOLD',1,"
            "json_build_object('state','HOLD','strongest',json_build_object('family',CASE WHEN i%%3=0 THEN 'payment_result_change' ELSE 'rate_5m' END,'status','CANDIDATE'))::text,'old',%s,%s,1 FROM generate_series(1,513) i",(FIVE_NS,2*FIVE_NS))
        self.raw.execute('INSERT INTO anomaly_detection.adp_case_versions SELECT case_key,revision,body,updated_ns FROM anomaly_detection.adp_cases')
        self.raw.execute("INSERT INTO anomaly_detection.adp_case_feedback(case_key,label,note,created_ns,case_revision) VALUES('c-000003','confirmed_suspicious','keep review',1,1)")
        self.raw.execute("INSERT INTO anomaly_detection.adp_models VALUES('old-model','payment_result_change','{}',1)")
        self.store.save_state('fresh_cursor',{'next_ns':7*FIVE_NS})
        with self.store.transaction():self.store.bind(source())
        self.assertFalse(self.store.state(MIGRATION)['complete'])
        with self.assertRaisesRegex(RuntimeError,'crash'):
            with self.store.transaction():advance_migration(self.store,limit=7);raise RuntimeError('crash')
        self.assertEqual(self.store.state(MIGRATION)['pages'],0)
        self.assertEqual(self.raw.execute("SELECT COUNT(*) AS n FROM anomaly_detection.adp_findings WHERE state='OUT_OF_SCOPE'").fetchone()['n'],0)
        self.assertEqual(self.raw.execute("SELECT COUNT(*) AS n FROM anomaly_detection.adp_case_signals WHERE state='OUT_OF_SCOPE'").fetchone()['n'],0)
        maximum=0;turns=0
        from anomaly_detection.product_store import ProductStore
        while not self.store.state(MIGRATION)['complete']:
            before=self.store.state(MIGRATION).get('scanned',0)
            value=advance_migration(self.store,limit=7);maximum=max(maximum,value['scanned']-before);turns+=1
            self.store=ProductStore(self.raw);self.store._history_floor_ns=0
            self.assertLess(turns,300)
        self.assertLessEqual(maximum,7);self.assertGreater(turns,200)
        self.assertEqual(self.raw.execute("SELECT COUNT(*) AS n FROM anomaly_detection.adp_findings WHERE state='OUT_OF_SCOPE'").fetchone()['n'],171)
        self.assertEqual(self.raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_finding_versions').fetchone()['n'],684)
        self.assertEqual(self.raw.execute("SELECT COUNT(*) AS n FROM anomaly_detection.adp_case_signals WHERE state='OUT_OF_SCOPE'").fetchone()['n'],171)
        self.assertEqual(self.raw.execute("SELECT COUNT(*) AS n FROM anomaly_detection.adp_cases WHERE state='OUT_OF_SCOPE'").fetchone()['n'],171)
        self.assertEqual(self.raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_case_versions').fetchone()['n'],684)
        self.assertEqual(self.raw.execute('SELECT note FROM anomaly_detection.adp_case_feedback').fetchone()['note'],'keep review')
        self.assertEqual(self.raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_findings').fetchone()['n'],513)
        self.assertEqual(self.store.state('fresh_cursor'),{'next_ns':7*FIVE_NS})
        self.assertEqual(self.raw.execute('SELECT model_id FROM anomaly_detection.adp_models').fetchone()['model_id'],'old-model')
        previous=self.store.state(MIGRATION);advance_migration(self.store,7);self.assertEqual(self.store.state(MIGRATION),previous)

    def test_pending_scope_migration_survives_reversals_and_nonfinancial_epoch_changes(self):
        with self.store.transaction():self.store.bind(source())
        advance_migration(self.store,limit=1)
        self.assertFalse(self.store.state(MIGRATION)['complete'])
        with self.store.transaction():self.store.bind(source(FULL,2))
        advance_migration(self.store,limit=1)
        with self.store.transaction():self.store.bind(source(FULL,3))
        for _ in range(5):
            if advance_migration(self.store,limit=1)['complete']:break
        self.assertTrue(self.store.state(MIGRATION)['complete'])
        self.assertEqual(self.store.state(MIGRATION)['scope_epoch'],3)
        self.assertTrue(self.store.state(MIGRATION+':1'))
        self.assertTrue(self.store.state(MIGRATION+':2'))

    def test_old_model_results_are_requeued_by_bounded_page_without_resetting_jobs_or_history(self):
        from anomaly_detection.product_engine import warm_model_references
        from anomaly_detection.snapshot import canonical
        self.raw.execute('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns,version,processed_version,dirty,last_evaluated_ns,evaluation) '
            "SELECT 'actor-'||i,%s,3,3,FALSE,1,%s FROM generate_series(1,5) i",(FIVE_NS,canonical({'evaluator_version':'old',
                'decisions':[{'family':'rate_5m','model_id':'old-model'}]})))
        state=warm_model_references(self.store,1,limit=2)
        self.assertEqual(state['scanned'],2);self.assertFalse(state['done'])
        while not state['done']:state=warm_model_references(self.store,1,limit=2)
        self.assertEqual(self.raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_model_queue').fetchone()['n'],5)
        self.assertTrue(self.raw.execute('SELECT BOOL_AND(version=3 AND processed_version=3 AND NOT dirty) AS ok FROM anomaly_detection.adp_jobs').fetchone()['ok'])
