import gzip
import json
from pathlib import Path
import tempfile
import unittest
from compact_behavior.extract import Extractor,Limits,LimitExceeded,behavior_id,facts,merge,materialize,instant,scrub,sql_parameters
from compact_behavior.source import WindowFile,ElasticWindow,settings,ElasticPageError,response_summary

T=instant('2026-10-20T08:20:00Z')
def row(request='req-1',session='session-1',path='Services.v1/WaterBills',message=None,at='2026-10-20T08:20:10Z'):
    return {'RequestID':request,'Session':session,'CallPath':path+' Line:32','@timestamp':at,'ExecutionTime':'12.5',
            'message':message if message is not None else 'POST https://example.test/WaterBills HTTP/1.1 (G00000 | successful)'}


def extract(rows):
    e=Extractor()
    for r in rows:e.add(r)
    return e.finish()


class CompactExtractionTests(unittest.TestCase):
    def test_identical_input_in_different_requests_is_two_behaviors(self):
        rows=[]
        for key in ['req-1','req-2']:
            rows.extend([row(key),row(key,path='ClientAyanCoInquiry.WaterBillInquiry',message='Input:[{"WaterBillID":"123"}] Output:[{"Parameters":{"Amount":10}}]')])
        states=extract(rows)
        self.assertEqual(len(states),2)
        bodies=[materialize('stream',s) for s in states.values()]
        self.assertEqual(len({b['behavior_id'] for b in bodies}),2)
        self.assertTrue(all(b['features']['input_eligible'] for b in bodies))
    def test_duplicate_and_reordered_events_are_idempotent(self):
        records=[row(),row(path='ClientAyanCoInquiry.WaterBillInquiry',message='Input:[{"WaterBillID":"123"}] Output:[]')]
        self.assertEqual(extract(records),extract(list(reversed(records))*3))
    def test_late_provider_fills_same_behavior_and_session_conflict_disables_input(self):
        before=extract([row()])['req-1']
        after=extract([row(session='session-2',path='ClientAyanCoInquiry.WaterBillInquiry',message='Input:[{"WaterBillID":"123"}] Output:[]')])['req-1']
        a=materialize('s',before);b=materialize('s',merge(before,after))
        self.assertEqual(a['behavior_id'],b['behavior_id']);self.assertIsNone(b['session_id'])
        self.assertIn('session_conflict',b['quality']);self.assertFalse(b['features']['input_eligible'])
    def test_unrelated_provider_does_not_replace_public_result_or_water_input(self):
        state=extract([row(),row(path='ClientAyanCoPaymentGateway.PaymentInquiry',message='Input:[{"BillID":"different"}] Output:[{"Status":{"Code":"G00000"}}]')])['req-1']
        body=materialize('s',state)
        self.assertIsNone(body['features']['input']);self.assertIn('input_unavailable',body['quality'])
        self.assertEqual(body['result_kind'],'reported_success')
    def test_business_parameters_precede_provider_and_secrets_removed(self):
        msg='(SQL Parameters: @queryParameters={"WaterBillID":"001","Token":"do-not-store"} @queryResult={"Amount":30} @flag=1)'
        state=extract([row(),row(path='DBPath.pishkhan24.application.ud_prc_inquiryInvoiceResult2',message=msg),
                       row(path='ClientAyanCoInquiry.WaterBillInquiry',message='Input:[{"WaterBillID":"222"}]')])['req-1']
        body=materialize('s',state)
        self.assertEqual(body['features']['input']['targets']['WaterBillID'],'001')
        self.assertNotIn('do-not-store',json.dumps(state))
    def test_nested_encoded_secrets_and_otp_are_removed_but_result_code_retained(self):
        x=scrub({'Parameters':'{"Password":"secret","OTP":"12345","Code":"G00000"}','AccessToken':'secret'})
        self.assertEqual(x,{'Parameters':{'Code':'G00000'}})
    def test_binary_document_is_a_descriptor_not_a_hidden_raw_archive(self):
        value=scrub({'GreenSheetBase64Image':'/9j/'+'x'*3000000})
        self.assertTrue(value['GreenSheetBase64Image']['binary_content_omitted'])
        self.assertLess(len(json.dumps(value)),250)
    def test_unconfirmed_provider_content_remains_explicitly_ineligible(self):
        state=extract([row(path='Services.v1/Other'),row(path='ClientAyanCoNaja.Other',message='Input:[{"NationalCode":"001"}] Output:[]')])['req-1']
        b=materialize('s',state);self.assertIn('input_binding_unconfirmed',b['quality'])
        self.assertFalse(b['features']['input_eligible']);self.assertFalse(b['features']['output_eligible'])
    def test_provider_success_without_public_completion_does_not_become_success(self):
        state=extract([row(message='an intermediate message'),row(path='ClientAyanCoInquiry.WaterBillInquiry',message='Input:[] Output:[{"Status":{"Code":"G00000"}}]')])['req-1']
        body=materialize('s',state)
        self.assertEqual(body['result_kind'],'unknown');self.assertFalse(body['features']['rate_eligible'])
    def test_conflicting_payload_is_not_input_eligible(self):
        states=extract([row(),row(path='ClientAyanCoInquiry.WaterBillInquiry',message='Input:[{"WaterBillID":"1"}]'),
                        row(path='ClientAyanCoInquiry.WaterBillInquiry',message='Input:[{"WaterBillID":"2"}]')])
        b=materialize('s',states['req-1']);self.assertIn('input_conflict',b['quality']);self.assertFalse(b['features']['input_eligible'])
    def test_guid_identity_stable_original_spelling_kept_and_unknown_session_not_ip_linked(self):
        key='01234567-89AB-CDEF-0123-456789ABCDEF'
        state=extract([row(key,session='N/A')])[key.replace('-','').lower()]
        self.assertEqual(behavior_id('s',key),behavior_id('s',key.lower().replace('-','')))
        self.assertEqual(state['raw_request_ids'],[key]);self.assertIsNone(materialize('s',state)['session_id'])
    def test_timestamp_preserves_nanoseconds_and_timezone(self):
        self.assertEqual(instant('2026-10-20T11:50:00.1234567+03:30'),T+123456700)
    def test_resource_limits_stop_instead_of_silently_dropping(self):
        e=Extractor(Limits(requests=1));e.add(row())
        with self.assertRaises(LimitExceeded):e.add(row('req-2'))
        e=Extractor(Limits(total_state_bytes=100))
        with self.assertRaises(LimitExceeded):e.add(row())
    def test_conflicting_representations_and_malformed_body_are_explicit(self):
        a=row();r={'_source':a,'fields':{'Session':['different']}}
        b=materialize('s',extract([r])['req-1'])
        self.assertIn('session_field_conflict',b['quality']);self.assertFalse(b['features']['rate_eligible'])
        a=row(path='ClientAyanCoInquiry.WaterBillInquiry',message='Input:[broken')
        self.assertIn('inputs_parse_error',facts(a)['issues'])
    def test_multiple_primary_apis_and_automatic_calls_are_not_eligible(self):
        state=extract([row(),row(path='Services.v1/GasBills')])['req-1']
        self.assertIsNone(materialize('s',state)['api'])
        state=extract([row(path='Core.v1/AddUserData')])['req-1']
        self.assertFalse(materialize('s',state)['features']['rate_eligible'])


class SourceTests(unittest.TestCase):
    def test_rejection_retains_exact_protocol_reason_without_documents(self):
        response={'timed_out':True,'_shards':{'total':3,'successful':2,'failed':1},
            'hits':{'total':{'relation':'eq','value':9},'hits':[{'_source':{'password':'PRIVATE'}}]},'pit_id':'PRIVATE_PIT'}
        with self.assertRaises(ElasticPageError) as caught:ElasticWindow.checked(response)
        details=caught.exception.details
        self.assertIn('timed_out_not_explicit_false',details['rejected_checks'])
        self.assertIn('successful_shards_not_total',details['rejected_checks'])
        self.assertEqual(details['shards']['failed'],1);self.assertNotIn('PRIVATE',json.dumps(details))
    def test_missing_flag_and_invalid_shard_shape_are_not_treated_as_complete(self):
        for response in [{'_shards':{'failed':0}}, {'timed_out':False,'_shards':None}, []]:
            with self.assertRaises(ElasticPageError) as caught:ElasticWindow.checked(response)
            self.assertTrue(caught.exception.details['rejected_checks'])
    def test_read_only_probe_closes_rotated_pit_on_valid_first_hit(self):
        from compact_behavior.probe_elastic import probe
        instances=[]
        class Fake(ElasticWindow):
            def __init__(self,*a,**kw):super().__init__(*a,**kw);self.calls=[];instances.append(self)
            def request(self,path,body=None,method='POST'):
                self.calls.append((path,body,method))
                if path=='/':return {'version':{'number':'8.19'}}
                if '_pit?' in path:return {'id':'pit1'}
                if method=='DELETE':return {}
                return {'pit_id':'pit2','timed_out':False,'_shards':{'total':1,'successful':1,'failed':0},
                    'hits':{'total':{'relation':'eq','value':100},'hits':[{'sort':[1],'_source':row()}]}}
        result=probe({'host':'http://example.test','index_pattern':'logs-*'},T,source_factory=Fake)
        self.assertEqual(result['status'],'FIRST_SEARCH_PAGE_VALID');self.assertFalse(result['services_stopped'])
        self.assertEqual(result['full_window_completeness'],'NOT_TESTED')
        self.assertEqual(instances[0].calls[-1],('/_pit',{'id':'pit2'},'DELETE'))
        self.assertEqual(result['response_diagnostics'][0]['summary']['returned_hits'],1)
        self.assertNotIn('RequestID',json.dumps(result))
    def test_read_only_probe_reports_rejection_without_stopping_services(self):
        from compact_behavior.probe_elastic import probe
        class Fake(ElasticWindow):
            def request(self,path,body=None,method='POST'):
                if path=='/':return {'version':{'number':'8.19'}}
                if '_pit?' in path:return {'id':'pit1'}
                if method=='DELETE':return {}
                return {'timed_out':True,'_shards':{'total':1,'successful':1,'failed':0},'hits':{'total':0,'hits':[]}}
        result=probe({'host':'http://example.test','index_pattern':'logs-*'},T,source_factory=Fake)
        self.assertEqual(result['status'],'FIRST_SEARCH_PAGE_REJECTED')
        self.assertEqual(result['failure']['details']['timed_out'],True)
        self.assertFalse(result['database_modified']);self.assertFalse(result['services_stopped'])
    def test_file_stream_checks_footer_complete_and_count(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'window.json.gz'
            packet={'logs':[row()],'count':1,'window_start':'2026-10-20T08:20:00Z','window_end':'2026-10-20T08:25:00Z','complete':True}
            with gzip.open(path,'wt') as f:json.dump(packet,f)
            source=WindowFile(path);self.assertEqual(list(source.records()),[row()])
            packet['count']=2
            with gzip.open(path,'wt') as f:json.dump(packet,f)
            with self.assertRaisesRegex(ValueError,'count_mismatch'):list(WindowFile(path).records())
    def test_stream_number_crossing_chunk_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'window.json'
            # The count is a multi-digit scalar exactly at a read boundary.
            packet={'padding':'x'*(65536-28),'count':123,'logs':[],'window_start':'2026-10-20T08:20:00Z','window_end':'2026-10-20T08:25:00Z','complete':True}
            p.write_text(json.dumps(packet))
            with self.assertRaisesRegex(ValueError,'count_mismatch'):list(WindowFile(p).records())
    def test_partial_es_page_rejected_and_pit_rotation_closed(self):
        class Fake(ElasticWindow):
            def request(self,path,body=None,method='POST'):
                self.calls.append((path,body,method))
                if '_pit?' in path:return {'id':'pit1'}
                if method=='DELETE':return {}
                return {'pit_id':'pit2','timed_out':True,'_shards':{'failed':0,'successful':1,'total':1},'hits':{'total':{'relation':'eq','value':0},'hits':[]}}
        source=Fake({'host':'http://example.test','index_pattern':'logs-*'},T,T+300000000000);source.calls=[]
        with self.assertRaisesRegex(ValueError,'partial_page'):list(source.records())
        self.assertEqual(source.calls[-1],('/_pit',{'id':'pit2'},'DELETE'))
    def test_es_pages_use_exact_pit_count_and_no_callpath_filter(self):
        class Fake(ElasticWindow):
            def request(self,path,body=None,method='POST'):
                self.calls.append((path,body,method))
                if '_pit?' in path:return {'id':'pit1'}
                if method=='DELETE':return {}
                total={'relation':'eq','value':2} if len(self.calls)==2 else None
                return {'timed_out':False,'_shards':{'failed':0,'successful':1,'total':1},'hits':{'total':total,'hits':[{'sort':[len(self.calls)],'_source':row(str(len(self.calls)))}]}}
        s=Fake({'host':'http://example.test','index_pattern':'logs-*'},T,T+300000000000);s.calls=[]
        self.assertEqual(len(list(s.records())),2);self.assertEqual(s.metadata['count'],2)
        self.assertNotIn('CallPath.keyword',json.dumps(s.calls));self.assertEqual(s.calls[2][1]['search_after'],[2])


if __name__=='__main__':unittest.main()
