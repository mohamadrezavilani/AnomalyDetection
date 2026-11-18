"""Missing history, retained high-watermark and crash-safe replay progress."""
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.viewer_online import (FIVE_NS,SECOND_NS,bind_stream,initialize_live,
    publish_capture,resume_recent,live_status,iso,single_worker)
from p24_foundation.viewer_elastic import stream_key
from viewer_performance import history_replay as replay_module
from viewer_performance.history_replay import HistoryReplay,boundary,handoff,pending_day,invoke_ad,ReplayControlError
from tests import test_viewer_minimal_pg as native
from tests.test_viewer_online import verified_file,snapshot
from tests.test_viewer_r6_service_journey import log,sql

DAY='2026-10-01'
BEGIN=boundary(DAY)


def verified_ad_fixture(root):
    """Copy public verified code only; no installed credentials/status are read."""
    source=Path(__file__).resolve().parents[1]/'AnomalyDetection'
    manifest=json.loads((source/'RELEASE_MANIFEST.json').read_text(encoding='utf-8'))
    ad=root/'AnomalyDetection'
    for name in [*manifest['files_sha256'],'RELEASE_MANIFEST.json']:
        target=ad/name;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(source/name,target)
    (ad/'reports').mkdir(exist_ok=True)
    (ad/'reports/product_status.json').write_text(
        json.dumps({'state':'STOPPED','note':'وضعیت اجرای پروژه'},ensure_ascii=False),encoding='utf-8')
    return ad


class RecordingConsole:
    def __init__(self):self.messages=[]
    def emit(self,message):self.messages.append(message)
    def progress(self,event):self.messages.append({'progress':event})
    def close(self):pass


class ControlWireTests(unittest.TestCase):
    def test_real_verified_ad_status_with_persian_survives_a_legacy_windows_pipe_encoding(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'سرور';root.mkdir();ad=verified_ad_fixture(root)
            with patch.dict(os.environ,{'PYTHONIOENCODING':'cp1252','PYTHONUTF8':'0'}):
                # The old invocation reproduces the otherwise hidden RuntimeError.
                old=subprocess.run([sys.executable,'-B',str(ad/'run_anomaly.py'),'worker-status'],
                    cwd=root,capture_output=True,timeout=20)
                self.assertNotEqual(old.returncode,0)
                self.assertEqual(json.loads(old.stdout)['failure']['error_type'],'UnicodeEncodeError')
                result=invoke_ad(root,['worker-status'])
                self.assertFalse(result['process']['locked']);self.assertFalse(result['web']['locked'])
                self.assertEqual(result['unverified_worker_status']['note'],'وضعیت اجرای پروژه')
                self.assertEqual(os.environ['PYTHONIOENCODING'],'cp1252')

    def test_control_failures_keep_structured_causes_without_exporting_child_payload_or_stderr(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);ad=root/'AnomalyDetection';ad.mkdir();launcher=ad/'run_anomaly.py'
            error={'status':'ERROR','failure':{'code':'WORKER_OPERATION_ERROR','error_type':'PermissionError',
                'errno':13,'sqlstate':None,'message':'private-control-payload'}}
            launcher.write_text('import sys\nprint('+repr(json.dumps(error))+')\nprint("private-stderr",file=sys.stderr)\nraise SystemExit(1)\n',encoding='utf-8')
            with self.assertRaises(ReplayControlError) as raised:invoke_ad(root,['worker-status'])
            failure=raised.exception.failure
            self.assertEqual(failure['code'],'AD_CONTROL_FAILED')
            self.assertEqual(failure['child_failure'],{'code':'WORKER_OPERATION_ERROR','error_type':'PermissionError','errno':13})
            self.assertNotIn('private-',json.dumps(failure))
            launcher.write_text('print("private-invalid-output")\n',encoding='utf-8')
            with self.assertRaises(ReplayControlError) as raised:invoke_ad(root,['worker-status'])
            self.assertEqual(raised.exception.failure['code'],'AD_CONTROL_OUTPUT_INVALID')
            self.assertNotIn('private-',json.dumps(raised.exception.failure))

    def test_missing_or_ambiguous_lock_observation_cannot_be_accepted_as_ad_stopped(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);ad=root/'AnomalyDetection';ad.mkdir()
            for result in ({'health':'STOPPED'}, {'process':{'locked':'False'},'web':{'locked':False}}):
                (ad/'run_anomaly.py').write_text('print('+repr(json.dumps(result))+')\n',encoding='utf-8')
                with self.assertRaises(ReplayControlError) as raised:invoke_ad(root,['worker-status'])
                self.assertEqual(raised.exception.failure['code'],'AD_CONTROL_STATUS_UNVERIFIED')


class ReplayChecks:
    def test_explicit_aban_scope_supersedes_only_scheduling_and_keeps_its_audit(self):
        self.seed_gap();self.replay.step(self.capture)
        old=dict(self.replay.state());before=snapshot(self.db)
        future=boundary('2026-11-12')
        resume_recent(self.db,lookback_windows=1,now=future+60*1_000_000_000)
        main=self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'];self.db.conn.commit()
        aban=HistoryReplay(self.db,'2026-10-23')
        with self.assertRaisesRegex(ValueError,'different_history'):aban.initialize()
        self.db.conn.rollback()
        def fail(stage):raise RuntimeError('controlled_scope_crash')
        with self.assertRaises(RuntimeError):aban.initialize(skip_earlier=True,fault=fail)
        self.assertEqual(self.replay.state()['run_id'],old['run_id']);self.db.conn.rollback()
        row=aban.initialize(skip_earlier=True)
        self.assertEqual(iso(row['from_ns']),'2026-10-22T20:30:00+00:00')
        self.assertEqual(row['next_ns'],row['from_ns']);self.assertNotEqual(row['run_id'],old['run_id'])
        self.assertEqual(row['end_ns'],main)
        self.assertEqual(row['ad_prepared'],0);self.assertEqual(row['ad_started'],0)
        self.assertEqual(snapshot(self.db),before)
        saved=self.db.one('SELECT body FROM '+aban.table+'_superseded WHERE run_id=?',(old['run_id'],))
        self.assertEqual(json.loads(saved['body']),old)
        identity=row['run_id'];self.db.conn.commit()
        self.assertEqual(aban.initialize(skip_earlier=True)['run_id'],identity)
        self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'],main)

    def capture(self,start,end):
        self.assertEqual(end,start+FIVE_NS)
        self.fetched.append(start)
        index=(start-BEGIN)//FIVE_NS
        # A payment root arriving earlier than a retained callback must still
        # repair the same cross-window group and authoritative session.
        if index==1:
            rows=[log(101,'pay','Core.v1/WalletPayment Line:1','POST (G00000 | successful)'),
                  log(102,'pay','DBPath.x.ud_prc_paymentExists',sql('ud_prc_paymentExists',paymentKey='K'))]
        elif index==5:
            rows=[log(105,'callback','DBPath.x.ud_prc_paymentExists',sql('ud_prc_paymentExists',paymentKey='K'))]
        else:rows=[log(100+index,'r'+str(index),'Services.v1/WaterBills Line:1','POST (G00000 | successful)')]
        for offset,row in enumerate(rows):
            row['_source_id']='synthetic-index:'+str(1000+10*index+offset)
            row['@timestamp']=iso(start+SECOND_NS)
        return verified_file(self.root/(uuid.uuid4().hex+'.gz'),rows,start)

    def seed_gap(self):
        self.fetched=[]
        path=self.capture(BEGIN,BEGIN+FIVE_NS)
        publish_capture(self.db,path,BEGIN,BEGIN+FIVE_NS)
        # Windows 1..4 are missing; 0,5,6 already have committed proofs.
        now=BEGIN+6*FIVE_NS+60*SECOND_NS
        resume_recent(self.db,lookback_windows=1,now=now)
        for i in (5,6):
            start=BEGIN+i*FIVE_NS
            publish_capture(self.db,self.capture(start,start+FIVE_NS),start,start+FIVE_NS)
        self.fetched=[]
        self.replay=HistoryReplay(self.db,DAY);self.replay.initialize();self.db.conn.commit()

    def finish(self):
        for _ in range(15):
            result=self.replay.step(self.capture)
            if result['status']=='HISTORY_REPLAY_COMPLETE':return result
        self.fail('replay did not complete')

    def test_missing_only_replay_closes_gaps_without_rewinding_or_losing_late_payment(self):
        self.seed_gap();before=self.db.one('SELECT * FROM viewer_live_state')
        result=self.finish()
        self.assertEqual(self.fetched,[BEGIN+i*FIVE_NS for i in (1,2,3,4)])
        self.assertEqual(result['skipped_complete_windows'],3)
        self.assertEqual(result['published_missing_windows'],4)
        self.assertEqual(result['remaining_windows'],0)
        self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'],before['next_ns'])
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_events')['n'],8)
        self.assertFalse(live_status(self.db)['history_has_gaps'])
        self.assertEqual(self.db.lookup_request('pay')['session_key'],self.db.lookup_request('callback')['session_key'])
        incremental=snapshot(self.db)
        self.db.rebuild();self.db.rebuild_payment_contract();self.db.build_semantic_index()
        self.assertEqual(incremental,snapshot(self.db))
        self.db.conn.commit()
        # Completed replay remains a no-op, including a process restart.
        identity=self.replay.state()['run_id']
        self.replay=HistoryReplay(self.db,DAY);self.replay.initialize()
        self.assertEqual(self.replay.state()['run_id'],identity)
        self.finish();self.assertEqual(len(self.fetched),4)

    def test_receipt_is_required_and_duplicate_recapture_preserves_event_counts(self):
        self.seed_gap()
        self.db.sql('DELETE FROM viewer_live_receipts WHERE start_ns=?',(BEGIN,));self.db.conn.commit()
        result=self.replay.step(self.capture)
        self.assertEqual(result['status'],'HISTORY_WINDOW_PUBLISHED')
        self.assertEqual(self.fetched,[BEGIN]);self.assertEqual(result['publication']['new_events'],0)
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_events')['n'],3)
        self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'],BEGIN+7*FIVE_NS)

    def test_skip_and_publish_failures_keep_progress_atomic_and_restart_idempotent(self):
        self.seed_gap()
        def fail_at(point):
            def fail(stage):
                if stage==point:raise RuntimeError('controlled_crash')
            return fail
        with self.assertRaisesRegex(RuntimeError,'controlled_crash'):
            self.replay.step(self.capture,fault=fail_at('before_skip_commit'))
        self.assertEqual(self.replay.state()['next_ns'],BEGIN)
        self.replay.step(self.capture)  # skips only window 0
        before=snapshot(self.db)
        with self.assertRaisesRegex(RuntimeError,'controlled_crash'):
            self.replay.step(self.capture,fault=fail_at('before_commit'))
        self.assertEqual(self.replay.state()['next_ns'],BEGIN+FIVE_NS)
        self.assertEqual(before,snapshot(self.db))
        with self.assertRaisesRegex(RuntimeError,'controlled_crash'):
            self.replay.step(self.capture,fault=fail_at('after_commit'))
        self.assertEqual(self.replay.state()['next_ns'],BEGIN+2*FIVE_NS)
        self.assertEqual(self.replay.state()['published_windows'],1)
        self.replay=HistoryReplay(self.db,DAY);self.replay.initialize();self.finish()
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_events')['n'],8)
        self.assertEqual(self.replay.state()['published_windows'],4)


class HistoryReplayTests(ReplayChecks,unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.keys=self.root/'keys';generate_keys(self.keys)
        self.db=ViewerDB(sqlite_path=self.root/'viewer.db',keys_path=self.keys);self.addCleanup(self.db.close)
        self.db.init();initialize_live(self.db);bind_stream(self.db,start_ns=BEGIN,stream_key='history-test')

    def test_tehran_midnight_and_invalid_boundaries(self):
        self.assertEqual(iso(BEGIN),'2026-09-30T20:30:00+00:00')
        for day in ('2026-10-1','20261001','2026-02-30','not-a-date'):
            with self.assertRaises(ValueError):boundary(day)
        with self.assertRaisesRegex(ValueError,'outside_existing_stream'):HistoryReplay(self.db,'2026-09-30').initialize()

    def test_unavailable_source_never_advances_or_invents_empty_coverage(self):
        self.seed_gap();self.replay.step(self.capture)
        row=self.replay.state()
        def unavailable(*args):raise ConnectionError('controlled_source_failure')
        with self.assertRaises(ConnectionError):self.replay.step(unavailable)
        self.assertEqual(row,self.replay.state())
        self.assertIsNone(self.db.one('SELECT * FROM viewer_live_windows WHERE start_ns=?',(BEGIN+FIVE_NS,)))

    def test_another_start_cannot_silently_replace_an_existing_replay(self):
        self.seed_gap()
        resume_recent(self.db,now=BEGIN+2*288*FIVE_NS+60*SECOND_NS)
        with self.assertRaisesRegex(ValueError,'different_history_replay'):
            HistoryReplay(self.db,'2026-10-02').initialize()

    def test_ad_handoff_retries_start_without_resetting_models_or_rescan_again(self):
        self.seed_gap();self.finish();calls=[]
        def invoke(root,args):
            calls.append(args)
            if args[0]=='history-rescan':return {'status':'HISTORY_RESCAN_PREPARED'}
            if len(calls)==2:raise RuntimeError('controlled_start_failure')
            return {'status':'STARTED'}
        with self.assertRaises(RuntimeError):handoff(self.replay,self.root,invoke=invoke)
        self.assertEqual(self.replay.state()['ad_prepared'],1)
        self.assertEqual(self.replay.state()['ad_started'],0)
        result=handoff(self.replay,self.root,invoke=invoke)
        self.assertEqual(result['status'],'HISTORY_REPLAY_HANDOFF_COMPLETE')
        self.assertEqual([x[0] for x in calls],['history-rescan','worker-start','worker-start'])
        self.assertEqual(self.replay.state()['ad_started'],1)

    def test_concurrent_ad_prepares_once_and_resumes_without_resetting_cursors(self):
        self.seed_gap();calls=[]
        def invoke(root,args):
            calls.append(args)
            return {'status':'HISTORY_RESCAN_PREPARED' if args[0]=='history-rescan' else 'ALREADY_RUNNING'}
        replay_module.start_anomaly(self.replay,self.root,invoke=invoke)
        self.assertEqual(self.replay.state()['status'],'RUNNING')
        self.assertEqual(self.replay.state()['ad_prepared'],1)
        self.assertEqual(self.replay.state()['ad_started'],1)
        replay_module.start_anomaly(self.replay,self.root,invoke=invoke)
        self.finish();handoff(self.replay,self.root,invoke=invoke)
        self.assertEqual([x[0] for x in calls],['history-rescan','worker-start','worker-start','worker-start'])

    def test_live_progress_uses_historical_cursor_and_preserves_the_forward_backlog(self):
        self.seed_gap();self.replay.step(self.capture)
        status=live_status(self.db,now=BEGIN+20*FIVE_NS)
        replay=status['history_replay']
        self.assertEqual(replay['current_window_start_utc'],iso(BEGIN+FIVE_NS))
        self.assertEqual(replay['remaining_windows'],6)
        self.assertEqual(replay['checked_windows'],1)
        self.assertEqual(replay['skipped_complete_windows'],1)
        self.assertEqual(replay['published_missing_windows'],0)
        self.assertIsNone(replay['publisher_active'])
        self.assertEqual(status['continuous_published_to_utc'],iso(BEGIN+7*FIVE_NS))
        self.assertGreater(status['backlog_windows'],0)
        self.finish()
        replay=live_status(self.db)['history_replay']
        self.assertEqual(replay['status'],'COMPLETE')
        self.assertEqual(replay['progress_percent'],100)
        self.assertIsNone(replay['current_window_start_utc'])

    def test_progress_endpoint_does_not_query_the_behavior_list_and_renders_replay(self):
        from p24_foundation.viewer_ui import create_viewer_app
        self.seed_gap();self.replay.step(self.capture);self.db.conn.commit()
        app=create_viewer_app({'sqlite_path':self.root/'viewer.db','keys_path':self.keys})
        with patch.object(ViewerDB,'semantic_sessions',side_effect=AssertionError('progress must not reload sessions')):
            with app.test_client() as client:
                response=client.get('/live-progress')
                self.assertEqual(response.status_code,200)
                text=response.get_data(as_text=True)
                self.assertIn('2026-10-01 00:05:00',text)
                self.assertIn('پنجرهٔ بعدی بازپخش',text)
                self.assertIn('6 پنجره تا پایان پیمایش',text)
                self.assertIn('شامل پنجره‌های کامل قبلی',text)
                self.assertEqual(response.headers['Cache-Control'],'no-store')
                result=client.get('/live-status').get_json()
                self.assertEqual(result['history_replay']['checked_windows'],1)


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'native PG18 cluster not configured')
class NativeHistoryReplayTests(ReplayChecks,unittest.TestCase):
    setUpClass=classmethod(native.NativeMinimalPublicationTests.setUpClass.__func__)
    tearDownClass=classmethod(native.NativeMinimalPublicationTests.tearDownClass.__func__)

    def setUp(self):
        native.NativeMinimalPublicationTests.setUp(self)
        # The disposable fixture has no captures yet; bind it to Oct 1.
        self.db.sql('UPDATE viewer_live_state SET start_ns=?,next_ns=?',(BEGIN,BEGIN));self.db.conn.commit()

    def runner_config(self):
        es={'host':'http://example.invalid','index_pattern':'logs-*'}
        (self.root/'viewer_config.local.py').write_text('LIVE_START_UTC='+repr(iso(BEGIN))+
            '\nELASTICSEARCH='+repr(es)+'\nLIVE='+repr({'capture_dir':str(self.root/'captures')})+'\n',encoding='utf-8')
        self.db.sql('UPDATE viewer_live_state SET stream_key=?',(stream_key(es),));self.db.conn.commit()
        # Only inject the disposable connection mapping. Production's exact
        # database-name guard remains unchanged and no product DB is opened.
        return patch('viewer_performance.Run_Viewer_Web.existing_options',
            return_value={'config':self.config,'keys_path':self.keys})

    def test_readonly_ad_source_follows_committed_history_instead_of_jumping_to_newer_islands(self):
        from contextlib import contextmanager
        import sys
        with patch.object(sys,'path',[str(Path(__file__).resolve().parents[1]/'AnomalyDetection'),*sys.path]):
            from anomaly_detection.product_source import ProductSource
            from anomaly_detection.product_pipeline import read_window,apply_window
            from anomaly_detection.product_store import ProductStore
        import psycopg
        from psycopg.rows import dict_row
        self.seed_gap();self.db.conn.commit()
        source=object.__new__(ProductSource)
        source.identity={'runtime_sha256':'fixture'};source.config={'user':self.config['user']}
        source.analysis_floor_ns=BEGIN;source.page_size=128;source.last_source=None
        @contextmanager
        def snapshot():
            with psycopg.connect(**self.config,row_factory=dict_row) as raw:
                raw.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
                def query(statement,parameters=(),*,cap):
                    rows=raw.execute(statement,parameters).fetchall()
                    # The exact product database guard stays in production;
                    # this fixture only owns a disposable p24_design_delta DB.
                    if statement.startswith('SELECT current_database()'):rows[0]['db']='p24_design_viewer'
                    self.assertLessEqual(len(rows),cap)
                    return rows
                yield query
        source.snapshot=snapshot
        with psycopg.connect(**self.config,autocommit=True,row_factory=dict_row) as owned:
            owned.execute('CREATE SCHEMA anomaly_detection')
            store=ProductStore(owned);store.initialize()
            self.assertIsNone(read_window(source,{'next_ns':BEGIN})['target_ns'])
            self.replay.step(self.capture)  # confirmed window 0
            packet=read_window(source,{'next_ns':BEGIN})
            self.assertEqual(packet['target_ns'],BEGIN)
            self.assertEqual(packet['source']['viewer_forward_next_ns'],BEGIN+7*FIVE_NS)
            self.assertEqual(packet['source']['next_ns'],BEGIN+FIVE_NS)
            self.assertEqual(apply_window(store,packet)['status'],'COMPLETE')
            cursor=store.state('fresh_cursor')
            self.assertIsNone(read_window(source,cursor)['target_ns'])
            # Even explicit continuations cannot read a newer retained island.
            self.assertIsNone(read_window(source,{'target_ns':BEGIN+5*FIVE_NS})['target_ns'])
            self.assertEqual(source.cohort(target=BEGIN+5*FIVE_NS)['target_ns'],None)
            def fail(stage):
                if stage=='before_commit':
                    self.assertIsNone(read_window(source,cursor)['target_ns'])
                    raise RuntimeError('controlled_uncommitted_history')
            with self.assertRaises(RuntimeError):self.replay.step(self.capture,fault=fail)
            self.assertIsNone(read_window(source,cursor)['target_ns'])
            self.replay.step(self.capture)
            packet=read_window(source,cursor)
            self.assertEqual(packet['target_ns'],BEGIN+FIVE_NS)
            self.assertEqual(apply_window(store,packet)['status'],'COMPLETE')
            self.assertEqual(owned.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_source_windows WHERE complete').fetchone()['n'],2)
            self.assertEqual(store.state('fresh_cursor'),{'next_ns':BEGIN+2*FIVE_NS})
            self.finish()
            packet=read_window(source,store.state('fresh_cursor'))
            self.assertEqual(packet['source']['next_ns'],BEGIN+7*FIVE_NS)
            self.assertEqual(packet['source']['history_replay']['status'],'COMPLETE')

    def test_active_replay_progress_is_based_on_the_live_singleton_lease(self):
        self.seed_gap();self.db.conn.commit()
        self.assertFalse(live_status(self.db)['history_replay']['publisher_active']);self.db.conn.rollback()
        with single_worker(self.db,self.root/'progress.lock'):
            self.assertTrue(live_status(self.db)['history_replay']['publisher_active']);self.db.conn.rollback()
        self.assertFalse(live_status(self.db)['history_replay']['publisher_active'])

    def test_native_runner_reaches_real_ad_status_and_publishes_history_under_legacy_encoding(self):
        options=self.runner_config();self.seed_gap();verified_ad_fixture(self.root)
        console=RecordingConsole()
        def completed(replay,root):
            self.assertEqual(replay.state()['status'],'COMPLETE')
            return {'status':'HISTORY_REPLAY_HANDOFF_COMPLETE'}
        self.db.conn.rollback()
        with options,patch.dict(os.environ,{'PYTHONIOENCODING':'cp1252','PYTHONUTF8':'0'}), \
             patch('p24_foundation.viewer_elastic.ElasticCapture',return_value=self.capture), \
             patch('p24_foundation.viewer_runtime.ProgressConsole',return_value=console), \
             patch.object(replay_module,'handoff',side_effect=completed):
            replay_module.run(self.root,DAY)
        self.db.conn.rollback()
        self.assertIn('HISTORY_REPLAY_RESUMING',[x.get('status') for x in console.messages])
        self.assertEqual(self.replay.state()['published_windows'],4)
        self.assertEqual(self.replay.state()['skipped_windows'],3)
        self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'],BEGIN+7*FIVE_NS)
        self.assertFalse(live_status(self.db)['history_has_gaps'])

    def test_concurrent_runner_restart_keeps_prepared_ad_and_replay_cursors(self):
        options=self.runner_config();self.seed_gap();self.db.conn.commit()
        calls=[];start=replay_module.start_anomaly
        def invoke(root,args):
            calls.append(args)
            return {'status':'HISTORY_RESCAN_PREPARED' if args[0]=='history-rescan' else 'ALREADY_RUNNING'}
        def start_with_fixture(replay,root):return start(replay,root,invoke=invoke)
        def completed(replay,root):return {'status':'HISTORY_REPLAY_HANDOFF_COMPLETE'}
        with options,patch('p24_foundation.viewer_runtime.ProgressConsole',side_effect=RecordingConsole), \
             patch.object(replay_module,'start_anomaly',side_effect=start_with_fixture), \
             patch.object(replay_module,'handoff',side_effect=completed):
            with patch('p24_foundation.viewer_elastic.ElasticCapture',return_value=lambda *_:(_ for _ in ()).throw(KeyboardInterrupt())):
                with self.assertRaises(KeyboardInterrupt):replay_module.run(self.root,DAY,with_anomaly=True)
            self.db.conn.rollback()
            self.assertEqual(self.replay.state()['next_ns'],BEGIN+FIVE_NS)
            self.assertEqual(self.replay.state()['ad_started'],1);self.db.conn.commit()
            with patch('p24_foundation.viewer_elastic.ElasticCapture',return_value=self.capture):
                replay_module.run(self.root,DAY)
        self.db.conn.rollback()
        self.assertEqual(self.replay.state()['status'],'COMPLETE')
        self.assertEqual([args[0] for args in calls],['history-rescan','worker-start','worker-start'])

    def test_ad_probe_failure_is_reported_once_and_releases_the_viewer_lease(self):
        options=self.runner_config();self.seed_gap();console=RecordingConsole();self.db.conn.rollback()
        error=ReplayControlError('AD_CONTROL_FAILED',ad_command='worker-status',
            child_failure={'error_type':'PermissionError','errno':13})
        with options,patch('p24_foundation.viewer_elastic.ElasticCapture',return_value=self.capture), \
             patch('p24_foundation.viewer_runtime.ProgressConsole',return_value=console), \
             patch.object(replay_module,'invoke_ad',side_effect=error) as probe, \
             patch.object(replay_module.clock,'sleep',side_effect=AssertionError('control errors must not retry init')):
            with self.assertRaises(ReplayControlError) as raised:replay_module.run(self.root,DAY)
        self.assertEqual(raised.exception.failure['stage'],'verify_ad_stopped');self.assertEqual(probe.call_count,1)
        self.assertNotIn('HISTORY_REPLAY_RETRY',[x.get('status') for x in console.messages])
        self.assertEqual(self.replay.state()['next_ns'],BEGIN)
        self.assertTrue(self.db.one('SELECT pg_try_advisory_lock(240026,1) AS locked')['locked'])
        self.db.sql('SELECT pg_advisory_unlock(240026,1)');self.db.conn.commit()

    def test_existing_worker_is_not_replaced_and_its_database_backend_is_reported(self):
        options=self.runner_config();console=RecordingConsole()
        with single_worker(self.db,self.root/'worker.lock'):
            with options,patch('p24_foundation.viewer_runtime.ProgressConsole',return_value=console), \
                 patch.object(replay_module,'invoke_ad',side_effect=AssertionError('must not reach AD')):
                with self.assertRaises(ReplayControlError) as raised:replay_module.run(self.root,DAY)
            self.assertEqual(raised.exception.failure['code'],'VIEWER_WORKER_ALREADY_RUNNING')
            self.assertEqual(raised.exception.failure['postgres_backend_pid'],self.db.conn.info.backend_pid)
            self.assertIsNone(self.db.one("SELECT to_regclass('public.viewer_history_replay_state') AS present")['present'])

    def test_active_ad_blocks_scope_change_before_the_old_replay_is_replaced(self):
        options=self.runner_config();self.seed_gap()
        old=self.replay.state()['run_id']
        future=boundary('2026-11-12')
        resume_recent(self.db,lookback_windows=1,now=future+60*1_000_000_000);self.db.conn.commit()
        running={'process':{'locked':True},'web':{'locked':False}}
        with options,patch('p24_foundation.viewer_runtime.ProgressConsole',side_effect=RecordingConsole), \
             patch.object(replay_module,'invoke_ad',return_value=running):
            with self.assertRaisesRegex(ValueError,'ad_must_be_stopped_before_history_scope_change'):
                replay_module.run(self.root,'2026-10-23',skip_earlier=True,with_anomaly=True)
        self.db.conn.rollback()
        self.assertEqual(self.replay.state()['run_id'],old)

    def test_native_killed_process_commits_progress_exactly_with_its_capture(self):
        self.seed_gap();self.replay.step(self.capture);self.db.conn.commit()
        start=BEGIN+FIVE_NS;path=self.capture(start,start+FIVE_NS)
        program='''import json,os,sys
from p24_foundation.viewer_data import ViewerDB
from viewer_performance.history_replay import HistoryReplay
args=json.load(sys.stdin)
with ViewerDB(config=args['config'],keys_path=args['keys']) as db:
    replay=HistoryReplay(db,args['day']);replay.initialize();db.conn.commit()
    replay.step(lambda *_:args['capture'],fault=lambda stage:os._exit(73) if stage==args['point'] else None)
'''
        for point,next_ns,count in (('before_commit',start,0),('after_commit',start+FIVE_NS,1)):
            args=dict(config=self.config,keys=str(self.keys),day=DAY,capture=str(path),point=point)
            child=subprocess.run([sys.executable,'-B','-c',program],input=json.dumps(args),text=True,
                capture_output=True,cwd=Path(__file__).resolve().parents[1],timeout=45)
            self.assertEqual(child.returncode,73,child.stderr[-1200:])
            self.db.conn.rollback()
            row=self.replay.state();self.assertEqual(row['next_ns'],next_ns);self.assertEqual(row['published_windows'],count)
            self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_requests WHERE request_key=(SELECT request_key FROM viewer_events WHERE at_ns=? LIMIT 1)',(start+SECOND_NS,))['n'],count)
            self.db.conn.rollback()
        self.assertEqual(pending_day(self.db),DAY)
        self.finish();self.assertEqual(self.replay.state()['published_windows'],4)
        self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'],BEGIN+7*FIVE_NS)


if __name__=='__main__':unittest.main()
