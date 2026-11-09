"""Bounded read-ahead, real atomic publication, late evidence and failure guards."""
import copy
from pathlib import Path
import tempfile
import threading
import unittest
import uuid

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB,token
from p24_foundation.viewer_elastic import ElasticCapture
from p24_foundation.viewer_online import LiveWorker,initialize_live,bind_stream,FIVE_NS,iso
from p24_foundation.viewer_prefetch import OneWindowPrefetch
from tests.test_viewer_online import START,verified_file,snapshot
from tests.test_viewer_pit_capture import PitTransport,pit_page,hit
from tests.test_viewer_r6_service_journey import log


class PrefetchQueueTests(unittest.TestCase):
    def test_only_one_closed_window_can_be_pending(self):
        began=threading.Event();release=threading.Event();calls=[]
        def capture(start,end,*,cancel_event=None):
            calls.append((start,end));began.set();release.wait(2)
            return Path('complete.json.gz')
        with OneWindowPrefetch(capture) as p:
            self.assertFalse(p.prepare(START,START+FIVE_NS,closed_ns=START))
            self.assertTrue(p.prepare(START,START+FIVE_NS,closed_ns=START+FIVE_NS))
            self.assertTrue(began.wait(1))
            self.assertFalse(p.prepare(START+FIVE_NS,START+2*FIVE_NS,closed_ns=START+2*FIVE_NS))
            release.set();value=p.take(START,START+FIVE_NS)
        self.assertTrue(value['prefetched']);self.assertEqual(len(calls),1)

    def test_stale_capture_is_fetched_afresh_and_complete_file_is_retained(self):
        clock=[0];calls=[]
        def capture(start,end,*,cancel_event=None):
            calls.append(cancel_event is not None);return Path('retained-evidence.json.gz')
        with OneWindowPrefetch(capture,clock=lambda:clock[0]) as p:
            p.prepare(START,START+FIVE_NS,closed_ns=START+FIVE_NS)
            self.assertTrue(p.job.done.wait(1));clock[0]=301
            result=p.take(START,START+FIVE_NS)
        self.assertEqual(calls,[True,False]);self.assertFalse(result['prefetched'])
        self.assertEqual(result['prefetch_discard_reason'],'stale')

    def test_wrong_window_and_background_failure_get_one_fresh_attempt(self):
        for fail in (False,True):
            calls=[]
            def capture(start,end,*,cancel_event=None):
                calls.append((start,cancel_event is not None))
                if fail and cancel_event is not None:raise RuntimeError('PRIVATE_ERROR')
                return Path('complete.json.gz')
            with OneWindowPrefetch(capture) as p:
                p.prepare(START,START+FIVE_NS,closed_ns=START+FIVE_NS)
                self.assertTrue(p.job.done.wait(1))
                start=START if fail else START+FIVE_NS
                result=p.take(start,start+FIVE_NS)
            self.assertEqual(len(calls),2);self.assertFalse(result['prefetched'])
            self.assertNotIn('PRIVATE_ERROR',str(result))

    def test_close_and_restart_never_adopt_a_previous_pending_file(self):
        calls=[]
        def capture(start,end,*,cancel_event=None):
            calls.append(cancel_event is not None);return Path('same-path.json.gz')
        old=OneWindowPrefetch(capture)
        old.prepare(START,START+FIVE_NS,closed_ns=START+FIVE_NS)
        self.assertTrue(old.job.done.wait(1));old.close()
        with self.assertRaisesRegex(ValueError,'prefetch_closed'):old.take(START,START+FIVE_NS)
        with OneWindowPrefetch(capture) as new:
            self.assertFalse(new.take(START,START+FIVE_NS)['prefetched'])
        self.assertEqual(calls,[True,False])

    def test_cancellation_closes_pit_and_removes_only_incomplete_file(self):
        cancel=threading.Event()
        class CancellingTransport(PitTransport):
            def pit_search(self,body,timeout):
                response=super().pit_search(body,timeout);cancel.set();return response
        transport=CancellingTransport([pit_page([hit(1)],total=1,pit='new-pit')])
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(TimeoutError,'capture_cancelled'):
                ElasticCapture(transport,folder)(START,START+FIVE_NS,cancel_event=cancel)
            self.assertEqual(list(Path(folder).iterdir()),[])
        self.assertEqual(transport.closed,['new-pit'])


class PrefetchPublicationTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);keys=self.root/'keys.json';generate_keys(keys)
        self.db=ViewerDB(sqlite_path=self.root/'viewer.db',keys_path=keys);self.addCleanup(self.db.close)
        self.db.init();initialize_live(self.db);bind_stream(self.db,start_ns=START,stream_key='synthetic')
        self.sources={};self.calls=[];self.lock=threading.Lock()
        def capture(start,end,*,cancel_event=None):
            with self.lock:
                self.calls.append((start,cancel_event is not None,threading.get_ident()))
                rows=copy.deepcopy(self.sources.get(start,[]))
            return verified_file(self.root/(uuid.uuid4().hex+'.json.gz'),rows,start)
        self.capture=capture;self.p=OneWindowPrefetch(capture);self.addCleanup(self.p.close)
        self.worker=LiveWorker(self.db,capture,prefetch=self.p)
        self.now=START+4*FIVE_NS+60_000_000_000
        self.row(START,1,'first');self.row(START+FIVE_NS,2,'second')

    def row(self,start,n,req):
        value=log(n,req,'Services.v1/WaterBills Line:1','POST (G00000 | successful)')
        value['@timestamp']=iso(start+1_000_000_000)
        self.sources.setdefault(start,[]).append(value)
        return value

    def test_next_capture_finishes_before_commit_but_publishes_only_in_order(self):
        main=threading.get_ident();seen=[]
        def progress(event):
            self.assertEqual(threading.get_ident(),main)
            if event['stage']=='before_commit':
                self.assertTrue(self.p.job.done.wait(1))
                seen.append(self.db.one('SELECT COUNT(*) AS n FROM viewer_events')['n'])
        self.db.progress_callback=progress
        first=self.worker.step(now=self.now)
        self.db.progress_callback=None
        second=self.worker.step(now=self.now,prefetch_next=False)
        self.assertEqual(seen,[1]);self.assertFalse(first['prefetched']);self.assertTrue(second['prefetched'])
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_live_receipts')['n'],2)
        self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'],START+2*FIVE_NS)
        self.assertEqual(len(self.calls),2)
        self.assertNotEqual(self.calls[1][2],main)
        receipt=self.db.one('SELECT * FROM viewer_live_receipts WHERE start_ns=?',(START+FIVE_NS,))
        self.assertAlmostEqual(receipt['cycle_seconds'],
                               receipt['elapsed_seconds']+second['capture_wait_seconds'],delta=.002)

    def test_failed_publication_does_not_admit_future_capture_or_skip_cursor(self):
        def fail(event):
            if event['stage']=='before_commit':
                self.assertTrue(self.p.job.done.wait(1));raise RuntimeError('controlled')
        self.db.progress_callback=fail
        with self.assertRaises(RuntimeError):self.worker.step(now=self.now)
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_events')['n'],0)
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_live_receipts')['n'],0)
        self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'],START)
        self.db.progress_callback=None
        retry=self.worker.step(now=self.now,prefetch_next=False)
        self.assertEqual(retry['window_start_utc'],iso(START))
        self.assertFalse(retry['prefetched'])

    def test_late_recheck_is_fresh_cross_window_session_and_repeat_counts_match_full(self):
        # An independent repeated inquiry keeps its own RequestID. One older
        # request continues into the next window with the same Session/IP change.
        later=self.row(START+FIVE_NS,3,'first');later['IP']='192.0.2.99'
        def add_late(event):
            if event['stage']=='before_commit':
                self.assertTrue(self.p.job.done.wait(1))
                self.row(START+FIVE_NS,4,'late-arrival')
        self.db.progress_callback=add_late
        self.worker.step(now=self.now);self.db.progress_callback=None
        self.worker.step(now=self.now,prefetch_next=False)
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_events')['n'],3)
        before=self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns']
        result=self.worker.step(now=self.now,recheck_start=START+FIVE_NS)
        self.assertEqual(result['mode'],'manual_recheck')
        self.assertEqual(self.calls[-1][1],False)
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_events')['n'],4)
        self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'],before)
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_requests')['n'],3)
        key=token(self.db.keys,'request',self.sources[START][0]['RequestID'])
        request=self.db.one('SELECT * FROM viewer_requests WHERE request_key=?',(key,))
        self.assertEqual(request['event_count'],2);self.assertEqual(request['identity_state'],'assigned')
        incremental=snapshot(self.db)
        self.db.rebuild();self.db.rebuild_payment_contract();self.db.build_semantic_index()
        self.assertEqual(incremental,snapshot(self.db))

    def test_incomplete_prefetched_file_cannot_enter_database(self):
        self.worker.step(now=self.now)
        self.assertTrue(self.p.job.done.wait(1));self.p.job.path.write_bytes(b'not gzip')
        with self.assertRaises(RuntimeError):self.worker.step(now=self.now,prefetch_next=False)
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_live_receipts')['n'],1)
        self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'],START+FIVE_NS)

    def test_post_commit_disconnect_resumes_durable_cursor_without_duplicate_receipt(self):
        def fail(event):
            if event['stage']=='after_commit':raise RuntimeError('connection_lost')
        self.db.progress_callback=fail
        with self.assertRaises(RuntimeError):self.worker.step(now=self.now)
        self.db.progress_callback=None
        self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'],START+FIVE_NS)
        next_window=self.worker.step(now=self.now,prefetch_next=False)
        self.assertEqual(next_window['window_start_utc'],iso(START+FIVE_NS))
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_live_receipts')['n'],2)
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_events')['n'],2)

    def test_prefetched_cross_request_version_invalidates_both_requests_globally(self):
        changed=copy.deepcopy(self.sources[START][0])
        changed['RequestID']='other-request';changed['message']='POST (GD2016 | failure)'
        changed['@timestamp']=iso(START+FIVE_NS+1_000_000_000)
        self.sources[START+FIVE_NS]=[changed]
        self.worker.step(now=self.now)
        self.assertTrue(self.p.job.done.wait(1))
        second=self.worker.step(now=self.now,prefetch_next=False)
        self.assertTrue(second['prefetched'])
        requests=self.db.all('SELECT identity_state,conflicted,session_key FROM viewer_requests')
        self.assertEqual(len(requests),2)
        self.assertTrue(all(r['conflicted'] and r['identity_state']=='conflicting' and r['session_key'] is None for r in requests))
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_raw_events')['n'],2)
        incremental=snapshot(self.db)
        self.db.rebuild();self.db.rebuild_payment_contract();self.db.build_semantic_index()
        self.assertEqual(incremental,snapshot(self.db))


if __name__=='__main__':unittest.main()
