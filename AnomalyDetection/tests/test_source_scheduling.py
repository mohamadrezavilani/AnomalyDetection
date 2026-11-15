"""An unfinished dense historical window must finish without losing fairness."""
import unittest
from anomaly_detection.source_scheduling import WindowContinuations,reduce_failed_page
from anomaly_detection.product_source import ProductSource


class SourceSchedulingTests(unittest.TestCase):
    def test_twenty_single_request_failures_do_not_shrink_window_or_semantic_pages(self):
        source=ProductSource.__new__(ProductSource);source.page_size=512;source.semantic_page_size=128
        for lane in ('fresh_cursor','learning_cursor','older_learning_cursor','overlap_cursor','semantic_keyset'):
            for _ in range(20):
                self.assertFalse(reduce_failed_page(source,'read_request_evidence',lane))
                self.assertFalse(reduce_failed_page(source,'read_historical_session',lane))
        self.assertEqual(source.page_sizes(),{'window':512,'semantic_keyset':128})
        self.assertTrue(reduce_failed_page(source,'read_overlap_cursor','overlap_cursor'))
        self.assertEqual(source.page_sizes(),{'window':256,'semantic_keyset':128})
        self.assertTrue(reduce_failed_page(source,'read_semantic_keyset','semantic_keyset'))
        self.assertEqual(source.page_sizes(),{'window':256,'semantic_keyset':64})

    def test_only_the_failed_page_lane_adapts(self):
        for phase,lane in (('read_fresh_window','fresh_cursor'),('read_learning_window','learning_cursor'),
                           ('read_older_learning_cursor','older_learning_cursor'),('read_fresh_cursor','fresh_cursor')):
            source=ProductSource.__new__(ProductSource);source.page_size=512;source.semantic_page_size=128
            self.assertTrue(reduce_failed_page(source,phase,lane))
            self.assertEqual(source.page_sizes(),{'window':256,'semantic_keyset':128})
        self.assertFalse(reduce_failed_page(source,'read_request_evidence',None))

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
