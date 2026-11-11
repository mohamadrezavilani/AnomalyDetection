"""Counter reports distinguish mutations, resets and missing observations."""
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('queue_observer',Path(__file__).resolve().parents[1]/'validation/observe_viewer_live.py')
observer=importlib.util.module_from_spec(spec);spec.loader.exec_module(observer)


class QueueObservationTests(unittest.TestCase):
    def row(self,updates):
        return dict(relname='adp_scenario_jobs',n_tup_ins=5,n_tup_upd=updates,n_tup_del=0,n_tup_hot_upd=2,
                    seq_scan=1,idx_scan=10,autovacuum_count=1,n_live_tup=100,n_dead_tup=20)
    def test_mutations_are_reported_as_a_rate_and_not_unique_job_count(self):
        before={'status':'READ','value':[self.row(100)]};after={'status':'READ','value':[self.row(700)]}
        result=observer.ad_counter_deltas(before,after,60)
        self.assertEqual(result['tables']['adp_scenario_jobs']['updates_per_second'],10)
        self.assertEqual(result['tables']['adp_scenario_jobs']['values']['n_tup_upd'],600)
        self.assertTrue(result['counts_are_row_mutations_not_unique_jobs_or_sql_calls'])
    def test_reset_and_unavailable_are_never_reported_as_zero_work(self):
        a={'status':'READ','value':[self.row(700)]};b={'status':'READ','value':[self.row(100)]}
        self.assertEqual(observer.ad_counter_deltas(a,b,60)['tables']['adp_scenario_jobs']['status'],'STATS_RESET_OR_OBJECT_REPLACED')
        self.assertEqual(observer.ad_counter_deltas(a,b,60,stats_reset=True)['status'],'STATS_RESET')
        self.assertEqual(observer.ad_counter_deltas({'status':'READ_FAILED'},b,60)['status'],'COUNTERS_UNAVAILABLE')


if __name__=='__main__':unittest.main()
