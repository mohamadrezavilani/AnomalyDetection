"""An unfinished dense historical window must finish without losing fairness."""
import unittest
from anomaly_detection.source_scheduling import WindowContinuations


class SourceSchedulingTests(unittest.TestCase):
    def test_dense_window_gets_continuations_before_unrelated_publication(self):
        work=WindowContinuations();work.notice('learning_cursor',{'status':'READING'})
        self.assertEqual([work.take() for _ in range(3)],['learning_cursor']*3)
        self.assertIsNone(work.take())

    def test_continuously_unfinished_window_cannot_starve_regular_lanes(self):
        work=WindowContinuations();work.notice('older_learning_cursor',{'status':'READING'})
        turns=[work.take() for _ in range(40)]
        self.assertEqual(turns.count(None),10)

    def test_finishing_a_lane_does_not_erase_another_pending_lane(self):
        work=WindowContinuations();work.notice('learning_cursor',{'status':'READING'})
        work.notice('fresh_cursor',{'status':'CAUGHT_UP'})
        self.assertEqual(work.take(),'learning_cursor')
        work.notice('learning_cursor',{'status':'COMPLETE'})
        self.assertIsNone(work.take());self.assertFalse(work.ready())

    def test_rejected_snapshot_can_restart_but_never_counts_as_completion(self):
        work=WindowContinuations();work.notice('overlap_cursor',{'status':'RESTART_SNAPSHOT'})
        self.assertEqual(work.take(),'overlap_cursor')
        work.notice('overlap_cursor',{'status':'COMPLETE'})
        self.assertIsNone(work.take())


if __name__=='__main__':unittest.main()
