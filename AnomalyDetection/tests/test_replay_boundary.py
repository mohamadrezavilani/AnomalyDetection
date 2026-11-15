"""Historical reading cannot jump across the replay's uncommitted frontier."""
import unittest
from anomaly_detection import FIVE_NS
from anomaly_detection.history_scope import replay_boundary
from anomaly_detection.scenario_traffic import read_page
from contextlib import contextmanager


class ReplayBoundaryTests(unittest.TestCase):
    def source(self):return dict(stream_key='stream',keys_fingerprint='keys',next_ns=20*FIVE_NS)
    def row(self):return dict(run_id='a'*32,status='RUNNING',from_ns=FIVE_NS,next_ns=3*FIVE_NS,
        end_ns=15*FIVE_NS,stream_key='stream',keys_fingerprint='keys')

    def test_prefix_preserves_real_forward_checkpoint_and_complete_releases_it(self):
        source=self.source();row=self.row();replay_boundary(source,row)
        self.assertEqual(source['next_ns'],3*FIVE_NS)
        self.assertEqual(source['viewer_forward_next_ns'],20*FIVE_NS)
        self.assertEqual(source['analysis_floor_ns'],FIVE_NS)
        source=self.source();row.update(status='COMPLETE',next_ns=row['end_ns']);replay_boundary(source,row)
        self.assertEqual(source['next_ns'],20*FIVE_NS)

    def test_changed_identity_and_invalid_cursor_cannot_be_admitted(self):
        for change in ({'stream_key':'other'},{'keys_fingerprint':'other'},{'next_ns':0},
                {'next_ns':3*FIVE_NS+1},{'next_ns':16*FIVE_NS},{'end_ns':21*FIVE_NS},{'status':'unknown'},{'status':'COMPLETE'}):
            with self.subTest(change=change):
                row=self.row();row.update(change)
                with self.assertRaises(ValueError):replay_boundary(self.source(),row)

    def test_explicit_traffic_continuation_past_prefix_waits_without_querying_newer_window(self):
        source=self.source();replay_boundary(source,self.row())
        class Reader:
            def metadata(self,q):return source
            @contextmanager
            def snapshot(self):
                def q(*args,**kwargs):raise AssertionError('future window was queried')
                yield q
        self.assertEqual(read_page(Reader(),{'target_ns':5*FIVE_NS})['status'],'CAUGHT_UP')


if __name__=='__main__':unittest.main()
