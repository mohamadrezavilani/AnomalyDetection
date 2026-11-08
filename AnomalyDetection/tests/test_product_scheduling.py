"""Reserved turns survive a work budget allowing only one job per cycle."""
import unittest
from unittest.mock import patch

from anomaly_detection.product_scheduling import EvaluationScheduler


class Store:
    def next_live_job(self,now):return {'lane':'live'}
    def next_backlog_job(self,now):return {'lane':'backlog'}
    def next_candidate_job(self,now):return {'lane':'candidate'}
    def next_ready_job(self,now):return {'lane':'ready'}
    def next_job(self,now,*,recheck=False,recent=False):return {'lane':'recheck' if recheck else 'history'}


class SchedulerTests(unittest.TestCase):
    def test_single_slow_job_cycles_reach_fresh_history_reference_and_rechecks(self):
        scheduler=EvaluationScheduler();store=Store();lanes=[]
        with patch('anomaly_detection.service_reference.next_case',return_value={'lane':'reference'}), \
             patch('anomaly_detection.product_priority.next_evidence_job',return_value={'lane':'evidence'}):
            # Each iteration represents a new batch after its first slow job.
            for _ in range(32):
                job,lane=scheduler.choose(store,0);lanes.append(lane)
                self.assertEqual(job['lane'],lane)
        self.assertEqual(lanes.count('live'),6)
        self.assertEqual(lanes.count('history'),6)
        self.assertEqual(lanes.count('reference'),2)
        self.assertEqual(lanes.count('recheck'),6)
        self.assertEqual(lanes.count('ready'),4)
        self.assertEqual(lanes.count('evidence'),4)
        self.assertEqual(lanes.count('backlog'),2)
        self.assertEqual(lanes.count('candidate'),2)

    def test_empty_live_lane_lends_turn_to_finite_ready_pass(self):
        scheduler=EvaluationScheduler();store=Store();store.next_live_job=lambda now:None
        job,lane=scheduler.choose(store,0)
        self.assertEqual(lane,'ready');self.assertEqual(job['lane'],'ready')

    def test_empty_queues_return_without_creating_or_marking_a_job(self):
        scheduler=EvaluationScheduler();store=Store()
        store.next_live_job=store.next_ready_job=lambda now:None
        store.next_job=lambda now,**kwargs:None
        self.assertEqual(scheduler.choose(store,0),(None,'history'))


if __name__=='__main__':unittest.main()
