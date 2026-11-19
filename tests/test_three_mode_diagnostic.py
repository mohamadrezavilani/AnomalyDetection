"""Real instrumentation/target SQL; role orchestration uses deterministic fakes."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch,MagicMock

from viewer_performance import Diagnose_Three_Modes as d


class DiagnosticTests(unittest.TestCase):
    def test_empty_target_set_is_never_completion(self):
        db=MagicMock();result=d.target_progress(db,[])
        self.assertFalse(result['observed_target_queues_drained']);db.execute.assert_not_called()

    def test_failure_of_a_target_query_is_unknown_and_not_success(self):
        db=MagicMock();db.execute.side_effect=TimeoutError('bounded diagnostic read')
        value=d.target_progress(db,[d.FIVE])
        self.assertEqual(value['status'],'UNAVAILABLE');self.assertFalse(value['observed_target_queues_drained'])

    def test_profile_stops_on_an_explicit_control_file_and_exports_a_partial_profile(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);p=d.RuntimeProfile(root,root,'ad',60)
            with p.active():
                with p.trace.span('fixture:work'):sum(range(100))
                d.save(root/'ad-stop.json',{'stop':True})
                with self.assertRaises(d.StopDiagnostic):p.checkpoint()
            data=d.read(root/'ad.json')
            self.assertTrue(data['instrumented']);self.assertIn('fixture:work',data['trace']['spans'])
            self.assertTrue(data['python_top']);self.assertEqual(data['full_method_acceptance'],'NOT_ASSIGNED')

    def test_controller_restores_original_roles_after_a_failed_middle_phase_and_exports_bundle(self):
        from contextlib import redirect_stdout
        import io,zipfile
        with tempfile.TemporaryDirectory() as temp:
            project=Path(temp);(project/'AnomalyDetection').mkdir();d.save(project/'AnomalyDetection/RELEASE_MANIFEST.json',{'build_id':'fixture'})
            plan=dict(active=dict.fromkeys(('viewer','viewer_web','ad_worker','ad_web'),True),task_restore=[],reviewed_proxy=None)
            previous=project/'previous.json';d.save(previous,{'before':{'restore_plan':plan}})
            host=MagicMock();host.inventory.return_value={'tasks':[]};host.h.cursors.return_value={}
            def command(script,*args):
                if script.endswith('run_anomaly.py'):return dict(process={'locked':True},web={'locked':True}),0
                return dict(status='VIEWER_WORKER_IDENTIFIED' if script.endswith('Stop_Viewer_Worker.py') else 'VIEWER_WEB_IDENTIFIED'),0
            host.command.side_effect=command
            def run_phase(*args,**kwargs):
                if args[2]=='ad_only':raise ValueError('FIXTURE_AD_START_FAILURE')
                return dict(mode=args[2],status='DIAGNOSTIC_TARGETS_FINISHED',targets=[d.FIVE,2*d.FIVE,3*d.FIVE])
            restored=[]
            def restore(project,path,state):restored.append(state['before']['restore_plan']['active']);state['restore_failures']=[]
            with patch('tools.check_viewer_install.verify_release',return_value={'status':'PASS'}),patch.object(d,'phase',side_effect=run_phase),patch('viewer_performance.Behavior_Release.restore',side_effect=restore),patch('viewer_performance.Run_Viewer_Catchup.choose_overrides',return_value={}),patch('viewer_performance.Run_Viewer_Catchup.supported_compression',return_value='pglz'),patch('viewer_performance.Run_Viewer_Memory.memory_info',return_value={}),redirect_stdout(io.StringIO()):
                result=d.run(project,previous,3,30,host)
            self.assertEqual(len(restored),1);self.assertEqual(result['status'],'THREE_MODE_PARTIAL_SEND_BUNDLE')
            self.assertEqual(len(result['phases']),1)
            self.assertEqual(result['failure']['code'],'FIXTURE_AD_START_FAILURE')
            bundle=next((project/'AnomalyDetection/reports').glob('*.zip'))
            with zipfile.ZipFile(bundle) as z:
                self.assertIn('run.json',z.namelist());self.assertIn('MANAGER_REPORT.md',z.namelist())
            self.assertEqual(result['database_copies'],0);self.assertEqual(result['scenario_families_disabled'],[])


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'disposable native PostgreSQL required')
class NativeDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        cls.psycopg=psycopg;cls.sql=sql
        cls.params=dict(host=os.environ['P24_DELTA_PG_HOST'],port=int(os.environ.get('P24_DELTA_PG_PORT','5432')),user=os.environ.get('P24_DELTA_PG_USER','postgres'))
        cls.admin=psycopg.connect(**cls.params,dbname='postgres',autocommit=True)
        cls.name='p24_design_capacity_'+__import__('uuid').uuid4().hex[:16]+'_qualification'
        cls.admin.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(cls.name)))
    @classmethod
    def tearDownClass(cls):
        cls.admin.execute(cls.sql.SQL('DROP DATABASE {}').format(cls.sql.Identifier(cls.name)));cls.admin.close()

    def test_actual_ad_worker_loop_runs_with_profiled_owned_connection_and_web_disabled(self):
        import sys
        from psycopg.rows import dict_row
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'AnomalyDetection'))
        from anomaly_detection import product_worker,BUILD_ID
        from contextlib import contextmanager
        class Source:
            last_source={};last_metrics=[]
            @contextmanager
            def snapshot(self):yield None
            def metadata(self,q):return dict(namespace='viewer:diagnostic',stream_key='test',keys_fingerprint='test',generation=1,semantic_generation=1,
                input_contract='viewer-behavior-1',scope_epoch=1,behavioral_features='observed-behavior-features-1',financial_relations='OUT_OF_SCOPE')
        original=product_worker.run
        def bounded(root,sha,**kwargs):
            self.assertFalse(kwargs['web'])
            return original(root,sha,max_cycles=1,source_factory=lambda _:Source(),
                prepare_pg=lambda _:self.psycopg.connect(**self.params,dbname=self.name,autocommit=True,row_factory=dict_row),**kwargs)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'AnomalyDetection').mkdir()
            d.save(root/'AnomalyDetection/RELEASE_MANIFEST.json',{'build_id':BUILD_ID,'source_sha256':'f'*64})
            d.save(root/'targets.json',{'targets':[]});profile=d.RuntimeProfile(root,root,'ad',60)
            with patch.object(product_worker,'run',side_effect=bounded),patch('anomaly_detection.runtime_lanes.maintenance'),patch(
                    'anomaly_detection.product_pipeline.read_window_burst',return_value=[{'status':'CAUGHT_UP'}]),patch(
                    'anomaly_detection.audit_scope.keys',return_value=[]),patch('anomaly_detection.product_scheduling.EvaluationScheduler.choose',return_value=(None,'history')):
                with profile.active():d.ad_lane(profile)
            value=d.read(root/'ad.json')
            self.assertEqual(value['status'],'WORKER_RETURNED')
            self.assertEqual(value['worker']['state'],'STOPPED')
            self.assertIn('driver:execute',value['trace']['spans'])
            self.assertTrue(any('adp_state' in item['relations'] for item in value['trace']['sql']))

    def test_connection_proxy_preserves_transactions_copy_fetch_and_rollback(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);profile=d.RuntimeProfile(root,root,'viewer',60)
            with profile.active():
                with self.psycopg.connect(**self.params,dbname=self.name) as conn:
                    conn.execute('CREATE TEMP TABLE observed(value INTEGER)')
                    with conn.cursor() as cursor:
                        with cursor.copy('COPY observed(value) FROM STDIN') as copy:
                            copy.write_row((1,));copy.write_row((2,))
                    self.assertEqual(conn.execute('SELECT value FROM observed ORDER BY value').fetchall(),[(1,),(2,)])
                    conn.commit()
                    with self.assertRaisesRegex(RuntimeError,'rollback'):
                        with conn.transaction():conn.execute('INSERT INTO observed VALUES(3)');raise RuntimeError('rollback')
                    self.assertEqual(conn.execute('SELECT COUNT(*) FROM observed').fetchone()[0],2)
                    with conn.cursor(name='stream') as cursor:
                        cursor.execute('SELECT value FROM observed ORDER BY value');self.assertEqual(list(cursor),[(1,),(2,)])
            value=d.read(root/'viewer.json')
            self.assertGreater(value['trace']['spans']['driver:copy']['inclusive_seconds'],0)
            self.assertGreater(value['rows_fetched'],0)

    def test_deadline_cancels_an_owned_long_sql_call_and_allows_transaction_rollback(self):
        import time
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);profile=d.RuntimeProfile(root,root,'ad',0.5,monitor_interval=0.02)
            began=time.monotonic()
            with profile.active():
                with self.assertRaises(self.psycopg.errors.QueryCanceled):
                    with self.psycopg.connect(**self.params,dbname=self.name) as conn:conn.execute('SELECT pg_sleep(10)')
            self.assertLess(time.monotonic()-began,5)
            self.assertEqual(d.read(root/'ad.json')['trace']['spans']['driver:execute']['failures'],1)

    def test_real_three_window_viewer_preserves_pipeline_and_commits_fresh_windows(self):
        from p24_foundation.privacy import generate_keys
        from p24_foundation.viewer_data import ViewerDB
        from p24_foundation.viewer_online import initialize_live,bind_stream
        from p24_foundation.viewer_product_scope import set_scope,BEHAVIOR
        from viewer_performance.capacity.fixtures import corpus,START,FIVE
        from viewer_performance import fast_writer
        digest=fast_writer.verify_sources()
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);keys=root/'keys.json';generate_keys(keys)
            config=dict(self.params,dbname=self.name)
            jobs=corpus(root,(1,2,3));paths={j['start']:j['path'] for j in jobs}
            (root/'viewer_config.local.py').write_text("ELASTICSEARCH={}\nLIVE={}\n",encoding='utf-8')
            with ViewerDB(config=config,keys_path=keys) as db:
                db.init();initialize_live(db);bind_stream(db,start_ns=START,stream_key='diagnostic-fixture')
                set_scope(db,BEHAVIOR);db.conn.commit()
            profile=d.RuntimeProfile(root,root,'viewer',60)
            with patch('viewer_performance.Run_Viewer_Web.existing_options',return_value=dict(config=config,keys_path=keys)),patch(
                    'viewer_performance.Run_Viewer_Memory.memory_info',return_value={'total_bytes':32*1024**3,'available_bytes':20*1024**3}),patch(
                    'p24_foundation.viewer_elastic.ElasticREST'),patch('p24_foundation.viewer_elastic.ElasticCapture',return_value=lambda begin,end:paths[begin]),patch(
                    'viewer_performance.fast_writer.verify_sources',return_value=digest),patch('viewer_performance.fast_writer.ROOT',root):
                with profile.active():d.viewer_lane(profile,3)
            value=d.read(root/'viewer.json')
            self.assertEqual(value['status'],'THREE_FRESH_PUBLICATIONS_FINISHED')
            self.assertEqual([r['start_ns'] for r in value['windows']],[START,START+FIVE,START+2*FIVE])
            self.assertEqual(len(value['windows']),3)
            with ViewerDB(config=config,keys_path=keys) as db:
                self.assertEqual(db.one('SELECT next_ns FROM viewer_live_state WHERE id=1')['next_ns'],START+3*FIVE)
                self.assertEqual(db.one('SELECT COUNT(*) AS n FROM viewer_live_windows')['n'],3)
            self.assertIn('source:elasticsearch_capture',value['trace']['spans'])
            self.assertIn('driver:fetch',value['trace']['spans'])

    def test_target_queue_sql_requires_source_primary_secondary_population_and_census_progress(self):
        from psycopg.rows import dict_row
        with self.psycopg.connect(**self.params,dbname=self.name,autocommit=True,row_factory=dict_row) as conn:
            conn.execute('DROP SCHEMA IF EXISTS anomaly_detection CASCADE');conn.execute('CREATE SCHEMA anomaly_detection')
            statements=[
                'CREATE TABLE anomaly_detection.adp_source_windows(start_ns BIGINT PRIMARY KEY,complete BOOLEAN)',
                'CREATE TABLE anomaly_detection.adp_jobs(target_ns BIGINT,dirty BOOLEAN,version INTEGER,processed_version INTEGER,primary_version INTEGER,primary_processed_version INTEGER,evaluation TEXT,target_scope TEXT)',
                'CREATE TABLE anomaly_detection.adp_model_queue(target_ns BIGINT)',
                'CREATE TABLE anomaly_detection.adp_population_jobs(start_ns BIGINT,dirty BOOLEAN,version INTEGER,processed_version INTEGER)',
                'CREATE TABLE anomaly_detection.adp_scenario_jobs(target_ns BIGINT,dirty BOOLEAN,version INTEGER,processed_version INTEGER)',
                'CREATE TABLE anomaly_detection.adp_profile_tasks(request_key TEXT)',
                'CREATE TABLE anomaly_detection.adp_window_members(start_ns BIGINT,request_key TEXT)',
                'CREATE TABLE anomaly_detection.adp_profiles(request_key TEXT,at_ns BIGINT)',
                'CREATE TABLE anomaly_detection.adp_state(name TEXT,body TEXT)']
            for sql in statements:conn.execute(sql)
            targets=[d.FIVE,2*d.FIVE,3*d.FIVE]
            for at in targets:
                conn.execute('INSERT INTO anomaly_detection.adp_source_windows VALUES(%s,TRUE)',(at,))
                conn.execute('INSERT INTO anomaly_detection.adp_population_jobs VALUES(%s,FALSE,1,1)',(at,))
                conn.execute("INSERT INTO anomaly_detection.adp_jobs VALUES(%s,FALSE,1,1,1,1,%s,'BEHAVIOR_TARGET')",(at,json.dumps({'pending_families':[],'evaluator_version':__import__('AnomalyDetection.anomaly_detection',fromlist=['EVALUATOR_VERSION']).EVALUATOR_VERSION})))
            for key in ('fresh_cursor','scenario_traffic_cursor','service_sample_fresh_cursor'):
                conn.execute('INSERT INTO anomaly_detection.adp_state VALUES(%s,%s)',(key,json.dumps({'next_ns':4*d.FIVE})))
            self.assertTrue(d.target_progress(conn,targets)['observed_target_queues_drained'])
            conn.execute('INSERT INTO anomaly_detection.adp_model_queue VALUES(%s)',(d.FIVE,))
            self.assertFalse(d.target_progress(conn,targets)['observed_target_queues_drained'])
            conn.execute('DELETE FROM anomaly_detection.adp_model_queue')
            conn.execute("INSERT INTO anomaly_detection.adp_profile_tasks VALUES('unread')")
            conn.execute("INSERT INTO anomaly_detection.adp_window_members VALUES(%s,'unread')",(d.FIVE,))
            self.assertFalse(d.target_progress(conn,targets)['observed_target_queues_drained'])
            conn.execute('DELETE FROM anomaly_detection.adp_profile_tasks')
            conn.execute('UPDATE anomaly_detection.adp_jobs SET primary_processed_version=0 WHERE target_ns=%s',(d.FIVE,))
            self.assertFalse(d.target_progress(conn,targets)['observed_target_queues_drained'])


if __name__=='__main__':unittest.main()
