"""A rare count need not exceed an arbitrary multiple of the largest count."""
import unittest
from anomaly_detection.service_reference import rank_screen


def ref(values,ready=True):
    return {'status':'READY_BASELINE' if ready else 'INSUFFICIENT_DATA','expected':1,
        'upper':max(values),'reference_values':values}


class RankScreenTests(unittest.TestCase):
    def test_one_large_historical_value_does_not_hide_a_rare_large_count(self):
        result=rank_screen(ref([1]*999+[34]),100,2)
        self.assertTrue(result['high']);self.assertLess(result['adjusted_empirical_tail_rank'],.01)

    def test_a_rare_count_can_be_below_the_historical_maximum(self):
        self.assertTrue(rank_screen(ref([1]*2000+[20,24]),20,2)['high'])
        self.assertFalse(rank_screen(ref([1]*1000+[20]*1000),20,2)['high'])

    def test_ties_and_comparison_count_are_conservative(self):
        self.assertFalse(rank_screen(ref([1]*1000),1,1)['high'])
        self.assertTrue(rank_screen(ref([1]*120),2,1)['high'])
        self.assertFalse(rank_screen(ref([1]*120),2,2)['high'])

    def test_insufficient_reference_never_becomes_a_candidate(self):
        self.assertFalse(rank_screen(ref([1]*1000,False),1000,1)['high'])

    def test_not_an_error_rate_or_fraud_probability_claim(self):
        result=rank_screen(ref([1]*1000),1000,1)
        self.assertEqual(result['calibration_status'],'DESCRIPTIVE_RANK_PRODUCTION_ERROR_RATE_NOT_VALIDATED')


if __name__=='__main__':unittest.main()
