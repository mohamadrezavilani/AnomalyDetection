import unittest
from anomaly_detection import FIVE_NS
from anomaly_detection.continuous import peak,coverage_runs,histogram_reference
from anomaly_detection.cases import identity,episodes
from anomaly_detection.population import assess,outcome


class ContinuousTests(unittest.TestCase):
    def test_burst_on_both_sides_of_midnight_and_source_boundary_is_one_rolling_count(self):
        t=1000*FIVE_NS;events=[]
        for i in range(20):events.append({'request_key':str(i),'at_ns':t-30_000_000_000+i,'qualified':True})
        for i in range(20):events.append({'request_key':str(i+20),'at_ns':t+60_000_000_000+i,'qualified':True})
        value=peak(events,FIVE_NS,t,t+FIVE_NS,[[t-288*FIVE_NS,t+FIVE_NS]])
        self.assertEqual(value['observed'],40);self.assertEqual(len(set(value['request_keys'])),40)
        self.assertLess(value['begin_ns'],t);self.assertTrue(value['evidence_verified'])

    def test_event_aligned_range_excludes_left_endpoint_and_future(self):
        t=1000*FIVE_NS
        rows=[{'request_key':str(i),'at_ns':at,'qualified':True} for i,at in enumerate((t-FIVE_NS,t-1,t,t+FIVE_NS))]
        value=peak(rows,FIVE_NS,t,t+FIVE_NS,[[t-2*FIVE_NS,t+2*FIVE_NS]])
        self.assertEqual(value['observed'],2);self.assertEqual(value['request_keys'],['1','2'])

    def test_simultaneous_distinct_requests_are_all_counted(self):
        rows=[{'request_key':str(i),'at_ns':100,'qualified':True} for i in range(4)]
        self.assertEqual(peak(rows,50,100,101,[[0,200]])['observed'],4)

    def test_coverage_gap_and_unknown_population_are_not_zeroes(self):
        proof={'peer_population_valid':True};rows=[{'start_ns':i*FIVE_NS,'complete':i!=2,'source':proof} for i in range(5)]
        runs=coverage_runs(rows);self.assertEqual(runs,[[0,2*FIVE_NS],[3*FIVE_NS,5*FIVE_NS]])
        self.assertIsNone(peak([{'request_key':'a','at_ns':3*FIVE_NS,'qualified':True}],2*FIVE_NS,3*FIVE_NS,4*FIVE_NS,runs))

    def test_partial_request_evidence_never_qualifies_the_whole_span(self):
        events=[{'request_key':'a','at_ns':99,'qualified':False},{'request_key':'b','at_ns':100,'qualified':True}]
        self.assertFalse(peak(events,10,100,101,[[0,200]])['evidence_verified'])

    def test_missing_reference_or_span_cannot_be_forced_to_candidate(self):
        h=[{'value':1,'n':99,'low_ns':0,'high_ns':288*FIVE_NS}]
        self.assertFalse(histogram_reference(h,1000,1)['ready'])
        h[0]['n']=400;h[0]['high_ns']=1
        self.assertFalse(histogram_reference(h,1000,1)['ready'])

    def test_comparisons_are_adjusted_and_reference_median_is_exact(self):
        h=[{'value':1,'n':200,'low_ns':0,'high_ns':288*FIVE_NS},
           {'value':3,'n':200,'low_ns':0,'high_ns':288*FIVE_NS}]
        self.assertEqual(histogram_reference(h,50,3)['expected'],2)
        self.assertTrue(histogram_reference(h,50,3)['high'])
        self.assertFalse(histogram_reference(h,50,24)['high'])

    def test_reference_without_resolution_for_all_comparisons_is_insufficient_not_normal(self):
        h=[{'value':1,'n':100,'low_ns':0,'high_ns':288*FIVE_NS}]
        ref=histogram_reference(h,8300,4)
        self.assertFalse(ref['ready']);self.assertEqual(ref['minimum_other_session_epochs'],399)

    def test_case_identity_is_separate_from_time_and_algorithm(self):
        self.assertEqual(identity('actor','a','activity','water'),identity('actor','a','activity','water'))
        self.assertNotEqual(identity('actor','a','activity','water'),identity('actor','a','otp','water'))
        self.assertNotEqual(identity('actor','a','activity','water'),identity('service','water','activity','water'))
        self.assertEqual(episodes([(1,4),(2,3),(4,6),(10,11),(10,11)]),[[1,6],[10,11]])


class PopulationTests(unittest.TestCase):
    def history(self):
        return [{'start_ns':(i+1)*FIVE_NS,'executions':20,'sessions':4,'service_count':2,'top_session_share':.25,
            'outcomes':{'direct_api_reported_result':{'G00000':20}},'outcome_cutoffs':{'direct_api_reported_result':(i+1)*FIVE_NS+1},'covered':True} for i in range(100)]
    def test_fully_observed_service_errors_across_users_produce_service_issue(self):
        current=self.history()[-1]|{'outcomes':{'direct_api_reported_result':{'G00000':2,'GD9999':18}}}
        health=next(d for d in assess('service',200*FIVE_NS,current,self.history()) if d['family']=='service_health')
        self.assertEqual(health['status'],'CANDIDATE');self.assertTrue(health['evidence_verified'])
        self.assertEqual(health['entity_type'],'service');self.assertEqual(health['observed'],18)

    def test_selected_audited_sample_does_not_establish_population_error_rate(self):
        current=self.history()[-1]|{'executions':100,'outcomes':{'direct_api_reported_result':{'GD9999':20}}}
        health=next(d for d in assess('service',200*FIVE_NS,current,self.history()) if d['family']=='service_health')
        self.assertEqual(health['status'],'INSUFFICIENT_DATA')

    def test_traffic_growth_alone_is_not_a_service_outage(self):
        current=self.history()[-1]|{'executions':1000,'sessions':200,'outcomes':{'direct_api_reported_result':{'G00000':1000}}}
        result=assess('service',200*FIVE_NS,current,self.history())
        self.assertEqual(next(d for d in result if d['family']=='service_health')['status'],'NO_DEVIATION_OBSERVED')
        profile=next(d for d in result if d['family']=='service_population')
        self.assertEqual(profile['status'],'CANDIDATE');self.assertFalse(profile['single_signal_review_eligible'])

    def test_one_service_does_not_create_an_independent_system_outage(self):
        current=self.history()[-1]|{'service_count':1}
        self.assertTrue(all(d['status']=='INSUFFICIENT_DATA' for d in assess('*',200*FIVE_NS,current,self.history())))

    def test_results_completed_after_target_cannot_enter_its_historical_reference(self):
        history=[r|{'outcome_cutoffs':{'direct_api_reported_result':300*FIVE_NS}} for r in self.history()]
        current=self.history()[-1]|{'outcomes':{'direct_api_reported_result':{'GD9999':20}}}
        health=next(d for d in assess('service',200*FIVE_NS,current,history) if d['family']=='service_health')
        self.assertEqual(health['status'],'INSUFFICIENT_DATA')

    def test_dispatcher_transport_success_does_not_replace_service_result(self):
        fact={'source_present':True,'quality':{'evidence_available':True},
            'transport':{'root_call':'Services.v1/Service','root_code':'G00000'},'observations':[]}
        self.assertIsNone(outcome(fact,'Services.v1/WaterBills'))
        fact['observations']=[{'axis':'service_dispatch.inquiry_result','qualified':True,'value':'GD9999'}]
        self.assertEqual(outcome(fact,'Services.v1/WaterBills'),('dispatcher_inquiry_result','GD9999'))
        fact['observations'].append({'axis':'service_dispatch.inquiry_result','qualified':True,'value':'G00000'})
        self.assertIsNone(outcome(fact,'Services.v1/WaterBills'))


if __name__=='__main__':unittest.main()
