import gzip
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
from compact_behavior.extract import Extractor,Limits,LimitExceeded,behavior_id,facts,merge,materialize,instant,scrub,sql_parameters
from compact_behavior.source import WindowFile,ElasticWindow,settings,ElasticPageError,response_summary,retryable_source_failure

T=instant('2026-10-20T08:20:00Z')
def row(request='req-1',session='session-1',path='Services.v1/WaterBills',message=None,at='2026-10-20T08:20:10Z'):
    return {'RequestID':request,'Session':session,'CallPath':path+' Line:32','@timestamp':at,'ExecutionTime':'12.5',
            'message':message if message is not None else 'POST https://example.test/WaterBills HTTP/1.1 (G00000 | successful)'}


def extract(rows):
    e=Extractor()
    for r in rows:e.add(r)
    return e.finish()


class FlakyWindow(ElasticWindow):
    """The failed snapshot contains a row absent from the successful snapshot."""
    def __init__(self,*,always_fail=False):
        super().__init__({'host':'http://example.test','index_pattern':'logs-*'},T,T+300000000000)
        self.attempts=0;self.always_fail=always_fail
    def records(self):
        self.attempts+=1
        if self.attempts==1 or self.always_fail:
            yield row('discarded-only')
            raise ElasticPageError('elastic_partial_page',{'timed_out':True,'shards':{'failed':0}})
        yield row('r1');yield row('r2')
        self.metadata={'window_start':'2026-10-20T08:20:00Z','window_end':'2026-10-20T08:25:00Z','complete':True,'count':2}


def es_document(key,*,request=None,index='logs-2026.11.21'):
    return {'_index':index,'_id':str(key),'_source':row(request or str(key))}


def scroll_packet(sid,documents,total,*,early=False,initial=False):
    shards=40 if initial else 1
    result={'_scroll_id':sid,'timed_out':False,'took':12 if initial else 9,
        '_shards':{'total':shards,'successful':shards,'failed':0,'skipped':39 if initial else 0},
        'hits':{'total':{'relation':'eq','value':total},'hits':documents}}
    if early:result['terminated_early']=True
    return result


class ScriptedScroll(ElasticWindow):
    """Real owner's protocol shape: exact first count, then _doc page flags."""
    def __init__(self,packets,**kwargs):
        super().__init__({'host':'http://example.test','index_pattern':'logs-*'},T,T+300000000000,**kwargs)
        self.packets=list(packets);self.calls=[];self.deleted=[]
    def request(self,path,body=None,method='POST'):
        from urllib.error import HTTPError
        self.calls.append((path,body,method))
        if '_pit?' in path:raise HTTPError('http://example.test',400,'PIT unsupported',None,None)
        if method=='DELETE':self.deleted.extend(body['scroll_id']);return {}
        if not self.packets:raise AssertionError('unexpected_extra_scroll_request')
        return self.packets.pop(0)


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
        self.assertEqual(body['features']['input']['targets']['WaterBillID'],[{'type':'string','value':'001'}])
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
    def test_transient_failure_discards_entire_attempt_before_one_publication(self):
        from compact_behavior.__main__ import measure_window
        db=Mock();db.limits=Limits();db.publish.return_value={}
        source=FlakyWindow();result=measure_window(db,'stream',source)
        self.assertEqual(source.attempts,2);db.publish.assert_called_once()
        self.assertEqual(set(db.publish.call_args.args[3]),{'r1','r2'})
        self.assertEqual(db.publish.call_args.args[4],2)
        self.assertEqual(result['source_attempts'][0]['source_records_discarded'],1)
        self.assertEqual([x['status'] for x in result['source_attempts']],['DISCARDED_INCOMPLETE_ATTEMPT','COMPLETE'])
        self.assertEqual(source.page_size,125)
    def test_invalid_protocol_is_not_retried_or_published(self):
        from compact_behavior.__main__ import measure_window
        class Corrupt(FlakyWindow):
            def records(self):
                self.attempts+=1
                raise ElasticPageError('elastic_partial_page',{'timed_out':None,'rejected_checks':['timed_out_not_explicit_false']})
                yield
        db=Mock();db.limits=Limits();source=Corrupt()
        with self.assertRaises(ElasticPageError):measure_window(db,'stream',source)
        self.assertEqual(source.attempts,1);db.publish.assert_not_called()
    def test_only_transient_protocol_errors_are_retryable(self):
        from urllib.error import HTTPError
        self.assertTrue(retryable_source_failure(HTTPError('http://example.test',429,'rate',None,None)))
        self.assertFalse(retryable_source_failure(HTTPError('http://example.test',403,'denied',None,None)))
        self.assertTrue(retryable_source_failure(LimitExceeded('elastic_page_bytes_limit')))
        self.assertFalse(retryable_source_failure(LimitExceeded('request_state_bytes_limit')))
    def test_scroll_retry_reopens_snapshot_and_closes_latest_failed_handle(self):
        from urllib.error import HTTPError
        from compact_behavior.__main__ import measure_window
        class Scroll(ElasticWindow):
            def __init__(self):
                super().__init__({'host':'http://example.test','index_pattern':'logs-*'},T,T+300000000000)
                self.attempts=0;self.deleted=[];self.initial=[]
            def packet(self,sid,records,timeout=False):
                return {'_scroll_id':sid,'timed_out':timeout,'_shards':{'total':40,'successful':40,'failed':0,'skipped':39},
                    'hits':{'total':{'relation':'eq','value':2},'hits':[{'_index':'logs','_id':r['RequestID'],'_source':r} for r in records]}}
            def request(self,path,body=None,method='POST'):
                if '_pit?' in path:raise HTTPError('http://example.test',400,'PIT unsupported',None,None)
                if method=='DELETE':self.deleted.extend(body['scroll_id']);return {}
                if '/_search?' in path:
                    self.attempts+=1;self.initial.append((path,body))
                    return self.packet('bad1' if self.attempts==1 else 'good1',[row('discarded-only' if self.attempts==1 else 'r1')])
                if self.attempts==1:return self.packet('bad2',[],True)
                return self.packet('good3',[]) if body['scroll_id']=='good2' else self.packet('good2',[row('r2')])
        source=Scroll();db=Mock();db.limits=Limits();db.publish.return_value={}
        result=measure_window(db,'stream',source)
        self.assertEqual(source.deleted,['bad2','good3']);self.assertEqual([v[1]['size'] for v in source.initial],[500,125])
        self.assertTrue(all('allow_partial_search_results=false' in v[0] for v in source.initial))
        self.assertEqual(set(db.publish.call_args.args[3]),{'r1','r2'});self.assertEqual(db.publish.call_args.args[4],2)
        self.assertEqual(len(result['source_attempts']),2)
    def test_doc_scroll_early_continuation_requires_unique_total_and_empty_terminal(self):
        packets=[scroll_packet('p1',[es_document(i) for i in range(500)],1002,initial=True),
            scroll_packet('p2',[es_document(i) for i in range(500,1000)],1002,early=True),
            scroll_packet('p3',[es_document(i) for i in range(1000,1002)],1002,early=True),
            scroll_packet('p4',[],1002)]
        source=ScriptedScroll(packets)
        self.assertEqual(len(list(source.records())),1002)
        self.assertEqual(source.metadata['expected_count'],1002)
        self.assertEqual(source.metadata['unique_documents'],1002)
        self.assertEqual(source.metadata['scroll_early_terminated_pages'],2)
        self.assertTrue(source.metadata['terminal_empty_page']);self.assertTrue(source.metadata['complete'])
        self.assertEqual(source.deleted,['p4']);self.assertFalse(source.packets)
        self.assertEqual([c[1]['scroll_id'] for c in source.calls if c[0]=='/_search/scroll' and c[2]=='POST'],['p1','p2','p3'])
    def test_early_flag_on_initial_search_or_pit_is_still_rejected(self):
        packet=scroll_packet('p1',[es_document(1)],1,early=True,initial=True)
        source=ScriptedScroll([packet])
        with self.assertRaises(ElasticPageError) as caught:list(source.records())
        self.assertIn('terminated_early',caught.exception.details['rejected_checks']);self.assertEqual(source.metadata,{})
        with self.assertRaises(ElasticPageError):ElasticWindow.checked(packet,1)
        with self.assertRaises(ElasticPageError):ElasticWindow.checked(packet,scroll_continuation=True)
    def test_short_scroll_is_not_complete_even_with_early_flag_and_exact_total(self):
        source=ScriptedScroll([scroll_packet('p1',[es_document(1)],2,initial=True),scroll_packet('p2',[],2,early=True)])
        with self.assertRaisesRegex(ValueError,'elastic_incomplete_window'):list(source.records())
        self.assertEqual(source.metadata,{});self.assertEqual(source.deleted,['p2'])
    def test_scroll_duplicate_cannot_fill_the_expected_document_count(self):
        source=ScriptedScroll([scroll_packet('p1',[es_document(1)],2,initial=True),
            scroll_packet('p2',[es_document(1)],2,early=True),scroll_packet('p3',[],2)])
        with self.assertRaisesRegex(ValueError,'elastic_duplicate_document'):list(source.records())
        self.assertEqual(source.metadata,{});self.assertEqual(source.deleted,['p2'])
    def test_scroll_reads_after_total_and_rejects_surplus_document(self):
        source=ScriptedScroll([scroll_packet('p1',[es_document(1)],1,initial=True),
            scroll_packet('p2',[es_document(2)],1,early=True),scroll_packet('p3',[],1)])
        with self.assertRaisesRegex(ValueError,'elastic_count_exceeded'):list(source.records())
        self.assertEqual(source.metadata,{});self.assertEqual(source.deleted,['p2'])
    def test_scroll_same_id_in_different_indices_and_same_request_are_not_deduplicated(self):
        source=ScriptedScroll([scroll_packet('p1',[es_document(1,request='r1',index='a')],2,initial=True),
            scroll_packet('p2',[es_document(1,request='r1',index='b')],2,early=True),scroll_packet('p3',[],2)])
        records=list(source.records());self.assertEqual(len(records),2);self.assertEqual(len(extract(records)),1)
        self.assertEqual(source.metadata['unique_documents'],2)
    def test_early_continuation_never_excuses_timeout_shard_failure_or_changed_total(self):
        for mode in ['timeout','failed_shard','missing_shard','changed_total','inexact_total']:
            with self.subTest(mode=mode):
                packet=scroll_packet('bad',[es_document(2)],2,early=True)
                if mode=='timeout':packet['timed_out']=True
                elif mode=='failed_shard':packet['_shards'].update(successful=0,failed=1)
                elif mode=='missing_shard':packet['_shards'].update(successful=0)
                elif mode=='changed_total':packet['hits']['total']['value']=3
                else:packet['hits']['total']['relation']='gte'
                source=ScriptedScroll([scroll_packet('p1',[es_document(1)],2,initial=True),packet])
                with self.assertRaises(ElasticPageError):list(source.records())
                self.assertEqual(source.metadata,{});self.assertEqual(source.deleted,['bad'])
    def test_scroll_identity_missing_cursor_and_resource_limits_are_explicit(self):
        for mode in ['missing_id','missing_index','missing_cursor','document_limit','identity_bytes_limit']:
            with self.subTest(mode=mode):
                packet=scroll_packet('p1',[es_document(1)],1,initial=True);options={}
                if mode=='missing_id':del packet['hits']['hits'][0]['_id']
                elif mode=='missing_index':del packet['hits']['hits'][0]['_index']
                elif mode=='missing_cursor':del packet['_scroll_id']
                elif mode=='document_limit':options['max_documents']=0
                else:options['max_identity_bytes']=1
                source=ScriptedScroll([packet],**options)
                with self.assertRaises(ValueError):list(source.records())
                self.assertEqual(source.metadata,{})
    def test_empty_initial_scroll_is_complete_with_exact_zero(self):
        source=ScriptedScroll([scroll_packet('p1',[],0,initial=True)])
        self.assertEqual(list(source.records()),[]);self.assertTrue(source.metadata['terminal_empty_page'])
        self.assertEqual(source.metadata['unique_documents'],0);self.assertEqual(source.deleted,['p1'])
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
        self.assertEqual(s.page_size,500);self.assertEqual(s.calls[1][1]['timeout'],'30s');self.assertEqual(s.calls[1][1]['terminate_after'],0)


if __name__=='__main__':unittest.main()
