"""Product algorithms: time leakage, gaps, peer fallback and correlated signals."""
from copy import deepcopy
import math
import random
from statistics import median
import unittest

from anomaly_detection import FIVE_NS
from anomaly_detection.product_models import evaluate,SmallIsolationForest
from anomaly_detection.temporal import Point,fit

START=1793005200000000000
SERVICE='Services.v1/WaterBills'


def example(n=120,current=100):
    target=START+n*FIVE_NS
    history=[{'start_ns':START+i*FIVE_NS,'coverage_complete':True,'population_complete':True,'counts':{SERVICE:2},
        'first_observed_ns':START} for i in range(n)]
    context={'session_key':'a'*64,'target_ns':target,'target_complete':True,'target_events_complete':True,
        'windows':[{'start_ns':target,'coverage_complete':True,'population_complete':True,'counts':{SERVICE:current},'first_observed_ns':START,
            'witnesses':{SERVICE:'1'*64}}],'events':[]}
    return context,history


class ProductModelTests(unittest.TestCase):
    def test_rate_uses_automatic_history_and_returns_witness(self):
        context,history=example()
        result=next(row for row in evaluate(context,history) if row['family']=='rate_5m')
        self.assertEqual(result['status'],'CANDIDATE');self.assertEqual(result['observed'],100)
        self.assertEqual(result['witness_request_key'],'1'*64)
        self.assertEqual(result['model']['cutoff_ns'],context['target_ns'])
        self.assertFalse(result['operator_alert'])
    def test_future_counts_and_future_arrivals_cannot_train_the_model(self):
        context,history=example();first=evaluate(context,history)
        history.append(dict(history[0],start_ns=context['target_ns']+FIVE_NS,counts={SERVICE:1000000000}))
        context['events'].append({'anchor_ns':context['target_ns']+FIVE_NS,'root_call':SERVICE})
        self.assertEqual(first,evaluate(context,history))
    def test_constant_usual_high_activity_is_not_anomaly(self):
        context,history=example(current=100)
        for row in history:row['counts']={SERVICE:100}
        result=evaluate(context,history)
        self.assertFalse(any(row['status']=='CANDIDATE' for row in result))
    def test_target_gap_is_insufficient_not_normal(self):
        context,history=example();context['target_complete']=False
        self.assertTrue(all(row['status']=='INSUFFICIENT_DATA' for row in evaluate(context,history)))
    def test_gap_inside_rolling_hour_is_not_zero_filled(self):
        context,history=example();history[-3].update(coverage_complete=False,counts=None)
        result=next(row for row in evaluate(context,history) if row['family']=='rate_60m')
        self.assertEqual(result['status'],'INSUFFICIENT_DATA')
    def test_empty_complete_target_does_not_leave_old_candidates_active(self):
        context,history=example();context['windows'][0]['counts']={}
        self.assertTrue(all(row['status']=='NO_DEVIATION_OBSERVED' for row in evaluate(context,history)))
    def test_short_history_is_not_labelled_normal(self):
        context,history=example(n=20)
        self.assertTrue(all(row['status']=='INSUFFICIENT_DATA' for row in evaluate(context,history)))
    def test_new_session_can_use_complete_service_peers(self):
        context,history=example(n=120);context['windows'][0]['first_observed_ns']=context['target_ns']+1
        peer=fit([Point(START+i*FIVE_NS,2,True,True) for i in range(120)],before_ns=context['target_ns'])
        result=next(row for row in evaluate(context,[],peer_provider=lambda *_:peer) if row['family']=='rate_5m')
        self.assertEqual(result['status'],'CANDIDATE');self.assertEqual(result['baseline_origin'],'active_session_peers')
    def test_peer_explanation_does_not_erase_real_personal_deviation(self):
        context,history=example()
        peer=fit([Point(START+i*FIVE_NS,100,True,True) for i in range(120)],before_ns=context['target_ns'])
        result=next(row for row in evaluate(context,history,peer_provider=lambda *_:peer) if row['family']=='rate_5m')
        self.assertEqual(result['status'],'CANDIDATE');self.assertTrue(result['peer_activity_can_explain'])
    def test_all_count_based_detectors_share_the_same_dimension(self):
        context,history=example(current=100)
        result=evaluate(context,history)
        self.assertEqual({row['dimension'] for row in result if row['family'] in ('rate_5m','rate_60m','service_mix','isolation_forest')},{'activity'})
    def test_request_completion_time_does_not_move_the_event_time_identity(self):
        context,history=example();before=evaluate(context,history)
        context['source']={'captured_at_ns':context['target_ns']+100*288*FIVE_NS}
        self.assertEqual(before,evaluate(context,history))
    def test_isolation_forest_is_reproducible_and_scores_extreme_point_higher(self):
        rng=random.Random(42);rows=[[rng.gauss(0,1),rng.gauss(0,1)] for _ in range(256)]
        left=SmallIsolationForest().fit(rows);right=SmallIsolationForest().fit(rows)
        self.assertEqual(left.trees,right.trees)
        self.assertGreater(left.score([100,100]),median(left.score(row) for row in rows))
        self.assertTrue(0<=left.score([100,100])<=1)
    def test_constant_features_do_not_recurse_forever_or_force_anomaly_fraction(self):
        model=SmallIsolationForest().fit([[1,1]]*128)
        self.assertAlmostEqual(model.score([1,1]),.5)
    def test_sequence_history_is_not_reset_at_five_minute_boundaries(self):
        context,history=example()
        events=[{'anchor_ns':context['target_ns']-(1200-i)*1_000_000_000,'root_call':SERVICE if i%2 else 'Services.v1/ElectricBills'} for i in range(1200)]
        events += [{'anchor_ns':context['target_ns']+i*1_000_000_000,'root_call':'Services.v1/TopUpProductPurchase'} for i in range(20)]
        for event in events:event.update(identity_state='assigned',conflicted=0,request_session_key=context['session_key'])
        context['events']=events
        result=next(row for row in evaluate(context,history) if row['family']=='service_sequence')
        self.assertEqual(result['status'],'CANDIDATE')
        self.assertEqual(result['model']['cutoff_ns'],context['target_ns'])
        for event in events:event['capture_window']=event['anchor_ns']//FIVE_NS
        again=next(row for row in evaluate(context,history) if row['family']=='service_sequence')
        self.assertEqual(result,again)
    def test_unmapped_canonical_execution_is_not_a_verified_empty_target(self):
        context,history=example();context['windows'][0].update(counts={},unmapped_behaviors=1)
        self.assertEqual({d['status'] for d in evaluate(context,history)},{'INSUFFICIENT_DATA'})
    def test_same_timestamp_does_not_create_causal_bigram_order(self):
        context,history=example()
        rows=[{'anchor_ns':context['target_ns']-(1200-i//2)*1_000_000_000,'root_call':SERVICE if i%2 else 'Services.v1/ElectricBills'} for i in range(1200)]
        rows += [{'anchor_ns':context['target_ns']+i//2*1_000_000_000,'root_call':SERVICE} for i in range(40)]
        for row in rows:row.update(identity_state='assigned',conflicted=0,request_session_key=context['session_key'])
        context['events']=rows
        result=next(d for d in evaluate(context,history) if d['family']=='service_sequence')
        self.assertEqual(result['model']['family'],'unigram')
    def test_gap_in_observed_event_history_defers_sequence_and_timing(self):
        context,history=example();history[-2].update(coverage_complete=False,population_complete=False)
        rows=[{'anchor_ns':context['target_ns']-(1200-i)*1_000_000_000,'root_call':SERVICE} for i in range(1200)]
        rows += [{'anchor_ns':context['target_ns']+i*1_000_000_000,'root_call':SERVICE} for i in range(40)]
        for row in rows:row.update(identity_state='assigned',conflicted=0,request_session_key=context['session_key'])
        context['events']=rows
        results=evaluate(context,history)
        self.assertEqual({d['status'] for d in results if d['family'] in ('service_sequence','timing_regularization')},{'INSUFFICIENT_DATA'})


if __name__=='__main__':unittest.main()
