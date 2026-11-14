"""Missing history, retained high-watermark and crash-safe replay progress."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.viewer_online import (FIVE_NS,SECOND_NS,bind_stream,initialize_live,
    publish_capture,resume_recent,live_status,iso)
from viewer_performance.history_replay import HistoryReplay,boundary,handoff,pending_day
from tests import test_viewer_minimal_pg as native
from tests.test_viewer_online import verified_file,snapshot
from tests.test_viewer_r6_service_journey import log,sql

DAY='2026-10-01'
BEGIN=boundary(DAY)


class ReplayChecks:
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


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'native PG18 cluster not configured')
class NativeHistoryReplayTests(ReplayChecks,unittest.TestCase):
    setUpClass=classmethod(native.NativeMinimalPublicationTests.setUpClass.__func__)
    tearDownClass=classmethod(native.NativeMinimalPublicationTests.tearDownClass.__func__)

    def setUp(self):
        native.NativeMinimalPublicationTests.setUp(self)
        # The disposable fixture has no captures yet; bind it to Oct 1.
        self.db.sql('UPDATE viewer_live_state SET start_ns=?,next_ns=?',(BEGIN,BEGIN));self.db.conn.commit()

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
