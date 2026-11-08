"""Positive, ordinary and unknown controls for owner scenario families."""
from copy import deepcopy
import json,unittest
from anomaly_detection import FIVE_NS
from anomaly_detection.request_profiles import VERSION,input_features,output_features,build
from anomaly_detection.scenario_models import actor,service,traffic,fisher_greater

T=1_800_000_000_000_000_000//FIVE_NS*FIVE_NS
S='Services.v1/FixtureInquiry'


def point(i,who,at,*,topic=None,subject=None,ip='ip1',access=True,value=True,code='G00000'):
    return {'version':VERSION,'request_key':f'{i:064x}','session_key':who,'service_path':S,'at_ns':at,'ended_ns':at+1,
        'qualified':True,'content_complete':True,'complete_event_scope':True,'targets':{'provider':str(i) if topic is None else topic},
        'subjects':[{'channel':'provider','field':'$.NationalCode','key':str(i) if subject is None else subject}],
        'ip_keys':[ip],'stages':[S]+(['DB.Access'] if access else []),
        'outputs':{'provider':output_features({'Result':{'Exists':value},'Status':{'Code':code}})},
        'result':{'scope':'fixture_direct_result','code':code},'witnesses':[{'at_ns':at}]}


def refs(repeat=False,diverse=True):
    return [[point(100000+k*100+i,f'ref{k}',T-2*288*FIVE_NS+i,topic='same'+str(k) if repeat else None,subject=None if diverse else str(k)) for i in range(20)] for k in range(400)]


def decision(items,family):return next(d for d in items if d['family']==family)


class ScenarioTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.normal_refs=refs()
    def test_same_bill_different_trace_and_auth_has_same_business_fingerprint(self):
        a=input_features([{'ElectricityBillID':'00123','TraceNumber':'a','Token':'secret-a'}],'provider')
        b=input_features([{'ElectricityBillID':'00123','TraceNumber':'b','Token':'secret-b'}],'provider')
        c=input_features([{'ElectricityBillID':'00124','TraceNumber':'a'}],'provider')
        self.assertEqual(a['key'],b['key']);self.assertNotEqual(a['key'],c['key'])
        self.assertNotIn('secret',json.dumps(a));self.assertNotIn('00123',json.dumps(a))
    def test_bulk_ids_keep_typed_identity_but_not_array_position(self):
        a=input_features([{'NationalCode':'123'},{'NationalCode':'123'}],'p')
        b=input_features([{'NationalCode':'123'},{'NationalCode':'124'}],'p')
        self.assertEqual(len({x['key'] for x in a['subjects']}),1)
        self.assertEqual(len({x['key'] for x in b['subjects']}),2)
    def test_invoice_references_do_not_replace_a_bill_subject(self):
        a=input_features({'ServiceID':1,'InvoiceUniqueID':'new-every-call','TraceNumber':'x'},'p')
        self.assertIsNone(a['key']);self.assertFalse(a['subjects'])
    def test_snake_case_identifiers_and_transport_noise_keep_the_same_business_input(self):
        a=input_features({'bill_id':'001234','trace_number':'a','client_ip':'192.0.2.1','session_id':'s1'},'provider')
        b=input_features({'bill_id':'001234','trace_number':'b','client_ip':'192.0.2.2','session_id':'s2'},'provider')
        self.assertEqual(a['key'],b['key']);self.assertEqual(len(a['subjects']),1)
    def test_same_typed_bill_is_repeated_even_when_other_business_parameters_change(self):
        now=[point(i,'a',T+i,topic='changing-parameters-'+str(i),subject='same-bill') for i in range(20)]
        for r in now:
            r['subjects'][0]['field']='$.BillID'
            r['subjects'].append(dict(r['subjects'][0])) # duplicate array element is not another request
        baseline=deepcopy(self.normal_refs)
        for unit in baseline:
            for r in unit:r['subjects'][0]['field']='$.BillID'
        d=decision(actor('a',S,T,now,[],baseline,complete=True),'repeated_target')
        self.assertEqual(d['observed'],20);self.assertEqual(len(d['request_keys']),20)
        self.assertTrue(d['single_signal_review_eligible'])
        unknown=decision(actor('a',S,T,now,[],self.normal_refs,complete=True),'repeated_target')
        self.assertFalse(unknown['single_signal_review_eligible']) # incompatible subject basis is not a reference
    def test_20_same_bill_is_not_20_different_bills(self):
        same=[point(i,'new',T+i,topic='bill',subject='bill') for i in range(20)]
        different=[point(i,'new',T+i) for i in range(20)]
        a=decision(actor('new',S,T,same,[],self.normal_refs,complete=True),'repeated_target')
        b=decision(actor('new',S,T,different,[],self.normal_refs,complete=True),'repeated_target')
        self.assertTrue(a['single_signal_review_eligible']);self.assertEqual(a['observed'],20)
        self.assertNotEqual(b['status'],'CANDIDATE')
    def test_legitimate_usual_retries_are_not_promoted_from_count_alone(self):
        same=[point(i,'a',T+i,topic='bill') for i in range(20)]
        r=decision(actor('a',S,T,same,[],refs(repeat=True),complete=True),'repeated_target')
        self.assertEqual(r['observed'],20);self.assertFalse(r['single_signal_review_eligible'])
    def test_repeat_crosses_source_window_and_midnight_without_new_actor_baseline(self):
        before=[point(i,'a',T-FIVE_NS+i,topic='bill') for i in range(10)]
        after=[point(20+i,'a',T+i,topic='bill') for i in range(10)]
        r=decision(actor('a',S,T,after,before,self.normal_refs,complete=True),'repeated_target')
        self.assertEqual(r['observed'],20);self.assertLess(r['begin_ns'],T);self.assertTrue(r['single_signal_review_eligible'])
    def test_many_typed_subjects_can_be_detected_without_personal_history(self):
        now=[point(i,'new',T+i) for i in range(20)]
        r=decision(actor('new',S,T,now,[],refs(diverse=False),complete=True),'subject_enumeration')
        self.assertTrue(r['cold_start']);self.assertTrue(r['single_signal_review_eligible']);self.assertEqual(r['observed'],20)
    def test_reference_must_resolve_the_adjusted_rank_before_reporting_no_deviation(self):
        now=[point(i,'new',T+i) for i in range(20)]
        baseline=refs(diverse=False)
        limited=decision(actor('new',S,T,now,[],baseline[:298],complete=True),'subject_enumeration')
        self.assertEqual(limited['status'],'INSUFFICIENT_DATA')
        self.assertEqual(limited['reason'],'REFERENCE_TAIL_RESOLUTION_INSUFFICIENT')
        boundary=decision(actor('new',S,T,now,[],baseline[:299],complete=True),'subject_enumeration')
        self.assertEqual(boundary['status'],'CANDIDATE')
        self.assertAlmostEqual(boundary['adjusted_empirical_tail_rank'],.01)
    def test_new_session_usual_behavior_is_not_flagged_for_newness(self):
        now=[point(i,'new',T+i) for i in range(20)]
        items=actor('new',S,T,now,[],self.normal_refs,complete=True)
        self.assertFalse(any(d.get('single_signal_review_eligible') for d in items))
    def test_ip_changes_need_behavioral_corroboration_for_independent_review(self):
        regular=[point(i,'a',T+i,ip=f'ip{i}') for i in range(20)]
        suspicious=[point(i,'a',T+i,ip=f'ip{i}',topic='bill') for i in range(20)]
        a=decision(actor('a',S,T,regular,[],self.normal_refs,complete=True),'client_ip_rotation')
        b=decision(actor('a',S,T,suspicious,[],self.normal_refs,complete=True),'client_ip_rotation')
        self.assertFalse(a['single_signal_review_eligible']);self.assertTrue(b['single_signal_review_eligible'])
    def test_usual_access_stage_disappears_but_optional_stage_does_not(self):
        now=[point(i,'a',T+i,access=False) for i in range(20)]
        r=decision(actor('a',S,T,now,[],self.normal_refs,complete=True),'workflow_change')
        self.assertTrue(r['single_signal_review_eligible']);self.assertIn('DB.Access',[s['stage'] for s in r['changed_stages']])
        optional=deepcopy(self.normal_refs)
        for unit in optional:
            for p in unit[::2]:p['stages']=[S]
        r=decision(actor('a',S,T,now,[],optional,complete=True),'workflow_change')
        self.assertFalse(r['single_signal_review_eligible'])
    def test_missing_profile_or_reference_is_unknown(self):
        now=[point(i,'a',T+i,topic='bill') for i in range(20)]
        a=actor('a',S,T,now,[],[],complete=True)
        b=actor('a',S,T,now,[],self.normal_refs,complete=False)
        self.assertFalse(any(d.get('single_signal_review_eligible') for d in a+b))
    def history(self):
        return [point(10000+i,f'h{i%100}',T-(100+i//10)*FIVE_NS+i%10) for i in range(1000)]
    def current(self,**kw):return [point(i,f'new{i%5}',T+i,**kw) for i in range(20)]
    def test_wrong_negative_response_with_success_code_and_same_schema_is_detected(self):
        d=service(S,T,self.current(value=False),self.history(),independent=True)
        self.assertEqual(decision(d,'response_schema_change')['status'],'NO_DEVIATION_OBSERVED')
        self.assertEqual(decision(d,'response_content_change')['status'],'CANDIDATE')
        self.assertEqual(decision(d,'service_health')['status'],'NO_DEVIATION_OBSERVED')
    def test_changed_schema_is_detected(self):
        now=self.current()
        for p in now:p['outputs']['provider']=output_features({'NewEnvelope':{'HasResult':True}})
        self.assertEqual(decision(service(S,T,now,self.history(),independent=True),'response_schema_change')['status'],'CANDIDATE')
    def test_outage_requires_comparable_reported_outcomes_and_has_normal_control(self):
        a=service(S,T,self.current(code='GD9999'),self.history(),independent=True)
        b=service(S,T,self.current(),self.history(),independent=True)
        self.assertEqual(decision(a,'service_health')['status'],'CANDIDATE')
        self.assertEqual(decision(b,'service_health')['status'],'NO_DEVIATION_OBSERVED')
    def test_candidate_selected_samples_and_unlogged_outputs_do_not_pass_as_service_census(self):
        d=service(S,T,self.current(value=False),self.history(),independent=False)
        self.assertTrue(all(x['status']=='INSUFFICIENT_DATA' for x in d))
        now=self.current()
        for p in now:p['outputs']={};p.pop('result')
        d=service(S,T,now,self.history(),independent=True)
        self.assertEqual(decision(d,'response_schema_change')['status'],'INSUFFICIENT_DATA')
        self.assertIsNone(decision(d,'service_health')['observed'])
    def test_shared_target_can_change_without_total_service_traffic_changing(self):
        now=self.current(topic='same')
        d=service(S,T,now,self.history(),independent=True)
        self.assertEqual(decision(d,'multi_session_target')['status'],'CANDIDATE')
    def test_future_completion_and_unqualified_evidence_never_train_a_model(self):
        history=self.history()
        for p in history:p['ended_ns']=T+1
        d=service(S,T,self.current(value=False),history,independent=True)
        self.assertTrue(all(x['status']=='INSUFFICIENT_DATA' for x in d))
    def traffic_history(self):return [{'start_ns':T-(i+1)*FIVE_NS,'requests':100,'sessions':5,'complete':True} for i in range(200)]
    def test_service_volume_checks_both_increase_and_decrease(self):
        for n,direction in ((0,'decrease'),(400,'increase')):
            r=decision(traffic(S,T,{'requests':n,'sessions':5,'complete':True},self.traffic_history()),'service_volume')
            self.assertEqual(r['status'],'CANDIDATE');self.assertEqual(r['direction'],direction)
        r=decision(traffic(S,T,{'requests':100,'sessions':5,'complete':True},self.traffic_history()),'service_volume')
        self.assertEqual(r['status'],'NO_DEVIATION_OBSERVED')
    def test_no_traffic_is_not_zero_without_complete_coverage(self):
        d=traffic(S,T,{'requests':0,'sessions':0,'complete':False},self.traffic_history())
        self.assertTrue(all(x['status']=='INSUFFICIENT_DATA' for x in d))
    def test_multi_session_volume_has_ordinary_and_anomalous_controls(self):
        a=decision(traffic(S,T,{'requests':100,'sessions':40,'complete':True},self.traffic_history()),'multi_session_service')
        b=decision(traffic(S,T,{'requests':100,'sessions':5,'complete':True},self.traffic_history()),'multi_session_service')
        self.assertEqual(a['status'],'CANDIDATE');self.assertEqual(b['status'],'NO_DEVIATION_OBSERVED')
    def test_exact_table_probability_small_known_example(self):
        self.assertAlmostEqual(fisher_greater(3,0,0,3),1/20)
        self.assertAlmostEqual(fisher_greater(0,3,0,3),1.)
    def test_ip_rotation_and_traversal_are_seen_across_services_in_same_session(self):
        now=[point(i,'new',T+i,ip=f'ip{i}') for i in range(20)]
        for i,p in enumerate(now):p['service_path']='Services.v1/Service'+str(i)
        items=actor('new','*',T,now,[],self.normal_refs,complete=True)
        self.assertTrue(decision(items,'service_traversal')['single_signal_review_eligible'])
        self.assertTrue(decision(items,'client_ip_rotation')['single_signal_review_eligible'])
    def test_profile_uses_client_root_ip_not_backend_provider_ip(self):
        request={'request_key':'a'*64,'session_key':'s','root_call':S,'root_ns':T+1,'ended_ns':T+2,'identity_state':'assigned','conflicted':False}
        events=[{'origin_key':str(i),'version_key':'v','at_ns':T+1,'kind':kind,'callpath':path,'session_key':who,'ip_key':ip,'variant_count':1,'raw_available':True} for i,(kind,path,who,ip) in enumerate((('client',S,'s','client'),('provider','Client.Provider','s','backend'),('client',S,'other','other-ip')))]
        p=build(request,events,{},[],lambda *_:(None,'unlogged'))
        self.assertEqual(p['ip_keys'],['client']);self.assertTrue(p['qualified'])
    def test_conflicting_raw_origin_does_not_qualify_content(self):
        request={'request_key':'a'*64,'session_key':'s','root_call':S,'root_ns':T+1,'ended_ns':T+2,'identity_state':'assigned','conflicted':False}
        event={'origin_key':'o','version_key':'v','at_ns':T+1,'kind':'client','callpath':S,'session_key':'s','ip_key':'ip','variant_count':2,'raw_available':True}
        self.assertFalse(build(request,[event],{},[],lambda *_:(None,'unlogged'))['qualified'])
    def test_diverse_result_collapsing_to_one_negative_message_is_detected(self):
        history=self.history();now=self.current()
        for i,p in enumerate(history):p['outputs']['provider']=output_features({'Result':'result-'+str(i),'Status':{'Code':'G00000'}})
        for p in now:p['outputs']['provider']=output_features({'Result':'No license record found','Status':{'Code':'G00000'}})
        result=decision(service(S,T,now,history,independent=True),'response_content_change')
        self.assertEqual(result['status'],'CANDIDATE')
    def test_missing_reference_ip_and_target_fields_are_not_zero_baselines(self):
        history=deepcopy(self.normal_refs)
        for unit in history:
            for p in unit:p['ip_keys']=[];p['targets']={}
        now=[point(i,'a',T+i,topic='bill',ip=f'ip{i}') for i in range(20)]
        d=actor('a',S,T,now,[],history,complete=True)
        self.assertEqual(decision(d,'client_ip_rotation')['status'],'INSUFFICIENT_DATA')
        self.assertFalse(decision(d,'repeated_target')['single_signal_review_eligible'])
    def test_unclassified_subject_fields_use_input_topics_without_claiming_people(self):
        history=refs(repeat=True);now=[point(i,'new',T+i) for i in range(20)]
        for p in now:p['subjects']=[]
        for unit in history:
            for p in unit:p['subjects']=[]
        d=decision(actor('new',S,T,now,[],history,complete=True),'subject_enumeration')
        self.assertTrue(d['single_signal_review_eligible']);self.assertEqual(d['subject_basis'],'business_input_fingerprints')
    def test_anonymous_calls_count_as_requests_without_inventing_sessions(self):
        d=traffic(S,T,{'requests':400,'sessions':0,'complete':True,'sessions_complete':False},self.traffic_history())
        self.assertEqual(decision(d,'service_volume')['status'],'CANDIDATE')
        self.assertEqual(decision(d,'multi_session_service')['status'],'INSUFFICIENT_DATA')
    def test_repeated_failed_inquiry_has_retry_context_without_independent_customer_accusation(self):
        now=[point(i,'a',T+i,topic='bill',code='GD9999') for i in range(20)]
        d=decision(actor('a',S,T,now,[],self.normal_refs,complete=True),'repeated_target')
        self.assertEqual(d['observed'],20);self.assertFalse(d['single_signal_review_eligible'])
        self.assertIn('retry',d['explanation_fa'])
    def test_one_heavy_actor_cannot_create_a_service_wide_content_or_outage_incident(self):
        now=[point(i,'heavy',T+i,value=False,code='GD9999') for i in range(100)]
        now += [point(100+i,f'ordinary{i}',T+100+i) for i in range(5)]
        d=service(S,T,now,self.history(),independent=True)
        self.assertNotEqual(decision(d,'response_content_change')['status'],'CANDIDATE')
        self.assertNotEqual(decision(d,'service_health')['status'],'CANDIDATE')
    def test_missing_session_does_not_hide_request_level_workflow_evidence(self):
        now=[point(i,None,T+i,access=False) for i in range(10)]
        for p in now:p['actor_qualified']=False
        d=decision(actor('request-scope',S,T,now,[],self.normal_refs,complete=True),'workflow_change')
        self.assertTrue(d['single_signal_review_eligible'])
        self.assertEqual(d['changed_stages'][0]['missing'],10)
    def test_reference_sequences_use_latest_events_independent_of_database_row_order(self):
        # A cohort spanning several frames may be returned newest-first.
        history=[[point(500000+k*200+i,f'ref{k}',T-(200-i)*FIVE_NS,topic='old-repeat' if i<100 else str(i)) for i in range(120)] for k in range(400)]
        now=[point(i,'a',T+i,topic='bill') for i in range(20)]
        a=decision(actor('a',S,T,now,[],history,complete=True),'repeated_target')
        b=decision(actor('a',S,T,now,[],[list(reversed(x)) for x in history],complete=True),'repeated_target')
        self.assertEqual(a['reference_values'],b['reference_values'])
        self.assertEqual(a['upper'],80)
    def test_result_records_collapse_to_empty_even_when_personal_fields_are_omitted(self):
        history=self.history();now=self.current()
        for p in history:p['outputs']['provider']=output_features({'Records':[{'Name':'do-not-store'}],'Code':'G00000'})
        for p in now:p['outputs']['provider']=output_features({'Records':[],'Code':'G00000'})
        a=history[0]['outputs']['provider'];b=now[0]['outputs']['provider']
        self.assertEqual(a['shape'],b['shape'])
        d=decision(service(S,T,now,history,independent=True),'response_content_change')
        self.assertEqual(d['status'],'CANDIDATE')
        self.assertNotIn('do-not-store',json.dumps(a))
    def test_distinct_sparse_output_values_skip_expensive_exact_tail_tests(self):
        from unittest.mock import patch
        history=self.history();now=self.current()
        for i,p in enumerate(history+now):p['outputs']['provider']=output_features({'Response':'value-'+str(i)})
        with patch('anomaly_detection.scenario_models.fisher_greater',wraps=fisher_greater) as exact:
            d=service(S,T,now,history,independent=True)
        self.assertLessEqual(exact.call_count,1) # same-scope health comparison
        self.assertEqual(decision(d,'response_content_change')['status'],'NO_DEVIATION_OBSERVED')


if __name__=='__main__':unittest.main()
