"""Independent numeric rank, pending-profile and publication regressions."""
from copy import deepcopy
from math import comb
from unittest.mock import patch
import json,re,unittest
from anomaly_detection import FIVE_NS as W
from anomaly_detection.snapshot import canonical
from anomaly_detection.scenario_models import numeric_separation,service
from anomaly_detection.request_profiles import output_features
from anomaly_detection.scenario_store import METHOD_VERSION,PROFILE_VERSION,upgrade_methods
from audit.run_independent_audit import service_data,T,S
from audit.sqlite_case_fixture import Store


def numeric_data():
    now,past=service_data()
    for i,r in enumerate(past):r['outputs']['provider']=output_features({'Result':{'Amount':100+i}})
    for i,r in enumerate(now):r['outputs']['provider']=output_features({'Result':{'Amount':1_000_000+i}})
    return now,past


class NumericControls(unittest.TestCase):
    def test_disjoint_unique_amounts_trigger_with_session_level_exact_tail(self):
        now,past=numeric_data()
        d=next(d for d in service(S,T,now,past,independent=True) if d['family']=='response_content_change')
        self.assertEqual(d['status'],'CANDIDATE')
        item=next(x for x in d['changed_fields'] if x.get('statistic'))
        self.assertEqual(item['current_sessions'],3);self.assertEqual(item['reference_sessions'],20)
        self.assertAlmostEqual(item['p'],1/comb(23,3));self.assertLessEqual(item['adjusted_p'],.01)
    def test_downward_numeric_shift_is_supported(self):
        now,past=numeric_data()
        for r in now:r['outputs']['provider']=output_features({'Result':{'Amount':-100}})
        self.assertEqual(numeric_separation(now,past,'provider','$.Result.Amount')['direction'],'decrease')
    def test_request_repetition_does_not_multiply_session_trials(self):
        now,past=numeric_data();base=numeric_separation(now,past,'provider','$.Result.Amount')
        now+=deepcopy(now)*10
        self.assertEqual(base,numeric_separation(now,past,'provider','$.Result.Amount'))
    def test_one_actor_cannot_become_service_wide_incident(self):
        now,past=numeric_data()
        for r in now:r['session_key']='one-session'
        self.assertIsNone(numeric_separation(now,past,'provider','$.Result.Amount'))
    def test_same_sessions_do_not_train_against_themselves(self):
        now,past=numeric_data()
        for i,r in enumerate(now):r['session_key']='peer-'+str(i%3)
        self.assertIsNone(numeric_separation(now,past,'provider','$.Result.Amount')) # 17 reference actors remain
    def test_missing_or_nonfinite_value_is_unknown(self):
        for value in (None,float('nan'),float('inf'),True):
            now,past=numeric_data();now[0]['outputs']['provider']['numbers']['$.Result.Amount']=value
            self.assertIsNone(numeric_separation(now,past,'provider','$.Result.Amount'))
    def test_overlapping_or_equal_distributions_do_not_signal(self):
        now,past=numeric_data()
        for r in now:r['outputs']['provider']=output_features({'Result':{'Amount':1300}})
        self.assertIsNone(numeric_separation(now,past,'provider','$.Result.Amount')['direction'])
        for r in now+past:r['outputs']['provider']=output_features({'Result':{'Amount':100}})
        self.assertEqual(numeric_separation(now,past,'provider','$.Result.Amount')['p'],1.)


class MethodControls(unittest.TestCase):
    def setUp(self):
        self.store=Store()
        self.store.execute('CREATE TABLE anomaly_detection.adp_scenario_jobs(scope_key TEXT,kind TEXT,target_ns BIGINT,dirty BOOLEAN,evaluation TEXT,version BIGINT,due_ns BIGINT)')
    def tearDown(self):self.store.close()
    def test_completed_old_methods_requeue_in_bounded_batches_without_erasure(self):
        for i in range(20):self.store.insert('adp_scenario_jobs',dict(scope_key=str(i),kind='request_response',target_ns=i,dirty=False,evaluation=canonical({'input_receipt':{}}),version=4,due_ns=999))
        self.assertEqual(upgrade_methods(self.store),16)
        self.assertEqual(upgrade_methods(self.store),4)
        self.assertEqual(upgrade_methods(self.store),0)
        rows=self.store.execute('SELECT * FROM anomaly_detection.adp_scenario_jobs').fetchall()
        self.assertEqual(len(rows),20);self.assertTrue(all(r['dirty'] and r['version']==5 and r['due_ns']==0 for r in rows))
    def test_current_and_dirty_jobs_are_not_invalidated_again(self):
        for i,dirty in enumerate((False,True)):
            self.store.insert('adp_scenario_jobs',dict(scope_key=str(i),kind='actor',target_ns=i,dirty=dirty,evaluation=canonical({'input_receipt':{'method_version':METHOD_VERSION}}),version=4,due_ns=999))
        self.assertEqual(upgrade_methods(self.store),0)
    def test_operator_currentness_rejects_old_method_before_backfill(self):
        from anomaly_detection.case_summary import CURRENT_SIGNAL_SQL
        sql='SELECT '+CURRENT_SIGNAL_SQL+" AS current FROM (SELECT 'feature' AS source_kind,1 AS job_version,NULL AS primary_version) s CROSS JOIN (SELECT 1 AS scope_key,0 AS dirty,1 AS version,'request_response' AS kind,%s AS evaluation) fj CROSS JOIN (SELECT NULL AS session_key,0 AS dirty,1 AS version,NULL AS primary_version,'{}' AS evaluation) j CROSS JOIN (SELECT NULL AS start_ns,0 AS dirty,1 AS version) p"
        for method,expected in ((None,False),(METHOD_VERSION,True)):
            body=canonical({'input_receipt':{'profile_version':PROFILE_VERSION,'method_version':method}})
            self.assertEqual(bool(self.store.execute(sql,(body,)).fetchone()['current']),expected)
    def test_actor_currentness_checks_evaluator_without_revoking_primary_version(self):
        from anomaly_detection.case_summary import CURRENT_SIGNAL_SQL
        from anomaly_detection import EVALUATOR_VERSION
        sql='SELECT '+CURRENT_SIGNAL_SQL+" AS current FROM (SELECT 'actor' AS source_kind,1 AS job_version,%s AS primary_version) s CROSS JOIN (SELECT NULL AS scope_key,0 AS dirty,1 AS version,'actor' AS kind,'{}' AS evaluation) fj CROSS JOIN (SELECT 'actor' AS session_key,0 AS dirty,1 AS version,7 AS primary_version,%s AS evaluation) j CROSS JOIN (SELECT NULL AS start_ns,0 AS dirty,1 AS version) p"
        for primary,version,expected in ((None,None,False),(None,EVALUATOR_VERSION,True),(7,None,True)):
            self.assertEqual(bool(self.store.execute(sql,(primary,canonical({'evaluator_version':version}))).fetchone()['current']),expected)
    def test_model_receipts_change_when_implementation_changes_with_identical_inputs(self):
        from anomaly_detection import product_engine as engine
        from audit.run_independent_audit import behavior_context
        context,history=behavior_context()
        class CapturingStore:
            def history(self,job):return history
            def excluded_windows(self,job):return set()
            def details(self,job):return [],True
            def complete(self,job,ctx,decisions,now):return ctx,decisions
        job=dict(session_key=context['session_key'],target_ns=T,version=1)
        with patch('anomaly_detection.product_dependencies.peer_model',return_value=(None,{})), \
             patch('anomaly_detection.service_reference.decisions',return_value=([],{})), \
             patch('anomaly_detection.input_subjects.decisions',return_value=[]):
            first,items=engine.evaluate_job(CapturingStore(),job,context,T)
            with patch.object(engine,'EVALUATOR_VERSION','changed-method'):
                second,changed=engine.evaluate_job(CapturingStore(),job,context,T)
        old={d['family']:d['model']['model_id'] for d in items if d.get('model')}
        new={d['family']:d['model']['model_id'] for d in changed if d.get('model')}
        self.assertTrue(old);self.assertEqual(set(old),set(new));self.assertTrue(all(old[k]!=new[k] for k in old))
        self.assertNotEqual(first['evaluator_version'],second['evaluator_version'])


class LongitudinalControls(unittest.TestCase):
    def test_pending_task_changes_actual_sql_refresh_expression(self):
        from anomaly_detection import longitudinal as mod
        captured=[]
        class Rows:
            def __init__(self,rows):self.rows=rows
            def fetchall(self):return self.rows
        class Capture:
            raw=None
            def execute(self,sql,params):
                captured.append(sql)
                if 'source_windows' in sql:return Rows([{'start_ns':x} for x in range(T-12*W,T+W,W)])
                return Rows([])
        obj=Capture();obj.raw=obj
        mod.context(obj,{'target_ns':T,'service_path':S,'entity_key':'actor'})
        mod.reference(obj,S,T,T-12*W,['peer'],[12*W])
        queries=[q for q in captured if 'AS needs_refresh' in q]
        self.assertEqual(len(queries),2)
        db=Store()
        try:
            db.execute('CREATE TABLE anomaly_detection.adp_profile_tasks(request_key TEXT)')
            db.execute('CREATE TABLE anomaly_detection.adp_facts(request_key TEXT,revision INTEGER,anchor_key TEXT,session_key TEXT,service_path TEXT,at_ns BIGINT)')
            db.execute('CREATE TABLE anomaly_detection.adp_profiles(request_key TEXT,body TEXT,session_key TEXT,service_path TEXT,at_ns BIGINT)')
            db.execute('INSERT INTO anomaly_detection.adp_facts VALUES(%s,1,%s,%s,%s,1)',('r','anchor','actor',S))
            body=canonical({'qualified':True,'version':PROFILE_VERSION,'semantic_revision':1,'anchor_key':'anchor'})
            db.execute('INSERT INTO anomaly_detection.adp_profiles VALUES(%s,%s,%s,%s,1)',('r',body,'actor',S))
            for pending in (False,True,False):
                db.execute('DELETE FROM anomaly_detection.adp_profile_tasks')
                if pending:db.execute('INSERT INTO anomaly_detection.adp_profile_tasks VALUES(%s)',('r',))
                for query in queries:
                    fragment=query[query.index('(p.request_key IS NULL'):query.index(' AS needs_refresh')]
                    fragment=fragment.replace('f.revision::text','CAST(f.revision AS TEXT)')
                    actual=db.execute('SELECT '+fragment+' AS value FROM anomaly_detection.adp_facts f JOIN anomaly_detection.adp_profiles p USING(request_key)',(PROFILE_VERSION,)).fetchone()['value']
                    self.assertEqual(bool(actual),pending)
        finally:db.close()
    def test_reference_actor_with_pending_member_is_excluded_whole(self):
        from anomaly_detection.longitudinal import reference
        class Raw:
            def execute(self,*args):return self
            def fetchall(self):return [dict(duration=12*W,requests=20,active_days=1,qualified=True,groups=[],ips=1,ip_covered=20,missing='pending-request')]
        metrics,missing=reference(type('Store',(),{'raw':Raw()})(),S,T,T-12*W,['peer'],[12*W])
        self.assertFalse(metrics[12*W][0]['qualified']);self.assertEqual(missing,['pending-request'])


class CasePublicationControls(unittest.TestCase):
    def test_real_case_sql_publishes_defers_withdraws_and_reopens_same_case(self):
        from anomaly_detection.cases import identity,replace_scope,normal_observations
        db=Store();db.create_case_tables()
        try:
            now,past=numeric_data()
            for p in now:db.insert('adp_profiles',dict(request_key=p['request_key'],session_key=p['session_key'],service_path=S,at_ns=p['at_ns'],body=canonical(p),observed_ns=T))
            d=next(d for d in service(S,T,now,past,independent=True) if d['family']=='response_content_change')
            d['signal_key']='fixture-signal';job=dict(target_ns=T,version=1)
            key=identity('service',S,'response_content',S)
            def publish(item,version):
                replace_scope(db,'fixture-scope',[item],T+version,source_kind='feature',job=dict(job,version=version))
                return dict(db.execute('SELECT * FROM anomaly_detection.adp_cases WHERE case_key=%s',(key,)).fetchone())
            first=publish(d,1)
            self.assertEqual(first['state'],'NEEDS_REVIEW')
            self.assertEqual(json.loads(first['body'])['distinct_executions'],len(now))
            unknown=dict(d,status='INSUFFICIENT_DATA',evidence_verified=False,single_signal_review_eligible=False)
            deferred=publish(unknown,2);self.assertEqual(deferred['state'],'HOLD')
            normal=dict(d,status='NO_DEVIATION_OBSERVED',single_signal_review_eligible=False)
            withdrawn=publish(normal,3);self.assertEqual(withdrawn['state'],'WITHDRAWN')
            normal_observations(db,[normal],T+4)
            body=json.loads(db.execute('SELECT body FROM anomaly_detection.adp_cases WHERE case_key=%s',(key,)).fetchone()['body'])
            self.assertEqual(body['phase'],'NO_CURRENT_SIGNAL')
            reopened=publish(d,5)
            self.assertEqual(reopened['state'],'NEEDS_REVIEW');self.assertGreater(reopened['revision'],first['revision'])
            self.assertEqual(db.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_cases').fetchone()['n'],1)
            self.assertEqual(db.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_case_requests').fetchone()['n'],len(now))
        finally:db.close()


class SourceCompatibilityControls(unittest.TestCase):
    def test_only_exact_supplied_r31_overlay_identity_is_accepted(self):
        from anomaly_detection.source_profiles import R3_RUNTIME,R31_RUNTIME,R31_FILES,R31_VIEWER_DATA,r31_overlay_allowed
        self.assertTrue(r31_overlay_allowed(R3_RUNTIME,R31_RUNTIME,R31_FILES,R31_VIEWER_DATA))
        self.assertTrue(r31_overlay_allowed(R31_RUNTIME,R31_RUNTIME,R31_FILES,R31_VIEWER_DATA))
        for args in (('unknown',R31_RUNTIME,R31_FILES,R31_VIEWER_DATA),(R3_RUNTIME,'0'*64,R31_FILES,R31_VIEWER_DATA),
                     (R3_RUNTIME,R31_RUNTIME,179,R31_VIEWER_DATA),(R3_RUNTIME,R31_RUNTIME,180,'0'*64)):
            self.assertFalse(r31_overlay_allowed(*args))
    def test_snapshot_keeps_actual_known_runtime_and_defers_unknown_bytes(self):
        from tests.fixture_factory import initial
        from anomaly_detection.snapshot import Snapshot
        from anomaly_detection.source_profiles import R31_RUNTIME
        data=initial();data['source']['runtime_sha256']=R31_RUNTIME
        snapshot=Snapshot(data)
        self.assertNotIn('source_not_ready:runtime_sha256',snapshot.deferred_reasons)
        self.assertEqual(snapshot.source['runtime_sha256'],R31_RUNTIME)
        data['source']['runtime_sha256']='0'*64
        self.assertIn('source_not_ready:runtime_sha256',Snapshot(data).deferred_reasons)
    def test_audit_projection_receives_actual_r31_runtime(self):
        from anomaly_detection.product_source import ProductSource
        from anomaly_detection.source_profiles import R31_RUNTIME
        from contextlib import nullcontext
        from types import SimpleNamespace
        source=ProductSource.__new__(ProductSource);source.identity={'runtime_sha256':R31_RUNTIME}
        source.snapshot=lambda:nullcontext(object())
        with patch('anomaly_detection.product_source.collect_sample',return_value=(SimpleNamespace(occurrences={}),{})) as collect:
            source.audit(['a'*64])
            self.assertEqual(collect.call_args.kwargs['runtime_sha256'],R31_RUNTIME)


class NativeHarnessControls(unittest.TestCase):
    def test_native_guard_rejects_production_and_implicit_endpoints_before_connection(self):
        from validation.qualify_audit_native import config_guard
        valid={'isolated_audit_database':True,'connection':{'host':'127.0.0.1','port':55432,'dbname':'p24_audit_fixture','user':'fixture'}}
        self.assertEqual(config_guard(valid)['dbname'],'p24_audit_fixture')
        for changes in ({'dbname':'p24_design_viewer'},{'host':'example.org'},{'port':5432},{'service':'production'}):
            bad=deepcopy(valid);bad['connection'].update(changes)
            with self.assertRaises(ValueError):config_guard(bad)
        bad=deepcopy(valid);bad['isolated_audit_database']=False
        with self.assertRaises(ValueError):config_guard(bad)
    def test_native_seed_statements_match_actual_declared_table_shapes(self):
        from validation.qualify_audit_native import write_profiles,seed_frames
        from anomaly_detection.product_store import DDL as fact_ddl
        from anomaly_detection.product_pipeline import DDL as window_ddl
        from anomaly_detection.scenario_store import DDL as profile_ddl
        from audit.request_sample_fixture import Store as Fixture
        db=Store()
        try:
            tables=('adp_facts','adp_profiles','adp_service_profile_samples','adp_window_members','adp_source_windows')
            for sql in fact_ddl+window_ddl+profile_ddl:
                if sql.startswith('CREATE TABLE') and any('anomaly_detection.'+t+'(' in sql for t in tables):db.execute(sql)
            fixture=Fixture('response_content_change')
            write_profiles(db,fixture.current+fixture.past,T,S);seed_frames(db,fixture,S)
            for table in ('adp_profiles','adp_facts','adp_window_members'):
                self.assertEqual(db.execute('SELECT COUNT(*) AS n FROM anomaly_detection.'+table).fetchone()['n'],2412)
            self.assertEqual(db.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_source_windows').fetchone()['n'],121)
        finally:db.close()


if __name__=='__main__':unittest.main()
