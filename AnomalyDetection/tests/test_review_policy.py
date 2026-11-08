import unittest
from anomaly_detection import FIVE_NS
from anomaly_detection.review_policy import eligible
from anomaly_detection.product_models import evaluate


class ReviewPolicyTests(unittest.TestCase):
    def test_descriptive_rarity_below_or_equal_to_known_maximum_is_not_a_single_review_vote(self):
        value={'family':'peer_service_rate_5m','single_signal_review_eligible':True,'observed':9,'upper':20}
        self.assertFalse(eligible(value));value['observed']=20;self.assertFalse(eligible(value))
        value['observed']=21;self.assertTrue(eligible(value))

    def test_qualified_independent_evidence_is_retained(self):
        value={'family':'peer_service_rate_5m','single_signal_review_eligible':True,'observed':9,'upper':20,
            'review_basis':'QUALIFIED_INDEPENDENT_DIMENSIONS'}
        self.assertTrue(eligible(value))

    def test_continuous_review_needs_a_known_same_duration_reference_bound(self):
        value={'family':'continuous_rate','single_signal_review_eligible':True,'observed':40}
        self.assertFalse(eligible(value));value['reference_max']=30;self.assertTrue(eligible(value))

    def test_hour_vote_requires_full_span_evidence(self):
        value={'family':'rate_60m','single_signal_review_eligible':True,'review_basis':'QUALIFIED_INDEPENDENT_DIMENSIONS'}
        self.assertFalse(eligible(value));value['span_evidence_verified']=True;self.assertTrue(eligible(value))

    def test_one_old_burst_cannot_supply_twelve_independent_positive_hour_observations(self):
        t=1000*FIVE_NS;service='Services.v1/PostPackagesStatus'
        history=[{'start_ns':t-(300-i)*FIVE_NS,'coverage_complete':True,'population_complete':True,
            'counts':{service:1} if i==240 else {}} for i in range(300)]
        context={'session_key':'a'*64,'target_ns':t,'target_complete':True,'events':[],
            'windows':[{'start_ns':t,'coverage_complete':True,'population_complete':True,'counts':{service:6}}]}
        result=evaluate(context,history)
        hour=next(v for v in result if v['family']=='rate_60m')
        self.assertEqual(hour['status'],'INSUFFICIENT_DATA');self.assertEqual(hour['positive_history_windows'],1)


if __name__=='__main__':unittest.main()
