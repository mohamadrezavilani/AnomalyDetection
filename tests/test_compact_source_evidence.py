import json
import unittest
from tools.Review_Compact_Source_Evidence import choose_samples,request_query,inspect_sample,collect
from compact_behavior.source import ElasticWindow,ElasticPageError
from tests.test_compact_extract import row,T

KEY='12345678123456781234567812345678'
RAW='12345678-1234-5678-1234-567812345678'


def sample(**kwargs):
    return dict(request_id=KEY,source_request_ids=[RAW],first_observed_ns=T,last_observed_ns=T,
        review_group='WAITING',**kwargs)


def packet(rows,total=None):
    return dict(timed_out=False,_shards=dict(total=2,successful=2,failed=0),
        hits=dict(total=dict(value=len(rows) if total is None else total,relation='eq'),
            hits=[dict(_id=str(i),_index='logs-test',_source=r) for i,r in enumerate(rows)]))


class Source(ElasticWindow):
    def __init__(self,result):
        super().__init__({'host':'http://example.test','index_pattern':'logs-*'},T,T+1)
        self.result=result;self.calls=[]
    def request(self,path,body=None,method='POST'):
        self.calls.append((path,body,method));return self.result


class SourceEvidenceTests(unittest.TestCase):
    def test_reconciliation_rejects_cross_stream_duplicate_or_foreign_request_samples(self):
        from tools.Reconcile_Compact_Samples import validate_reports
        from copy import deepcopy
        unknown=dict(status='READ_ONLY_UNKNOWN_REVIEW',counters={'stream_id':'test'},groups={'WAITING':{'samples':[sample()]}})
        source=dict(status='READ_ONLY_SOURCE_EVIDENCE',samples=[sample()])
        self.assertEqual(len(validate_reports(unknown,source,'test')[1]),1)
        with self.assertRaises(ValueError):validate_reports(unknown,source,'other')
        bad=deepcopy(source);bad['samples']*=2
        with self.assertRaises(ValueError):validate_reports(unknown,bad,'test')
        bad=deepcopy(source);bad['samples'][0]['request_id']='f'*32
        with self.assertRaises(ValueError):validate_reports(unknown,bad,'test')
        bad=deepcopy(source);bad['samples'][0]['documents']=[{}]*257
        with self.assertRaises(ValueError):validate_reports(unknown,bad,'test')

    def test_query_is_bounded_and_does_not_request_personal_context(self):
        query=request_query(sample())
        self.assertEqual(query['size'],256)
        self.assertEqual(query['timeout'],'5s')
        self.assertTrue(query['track_total_hits'])
        for key in ('Session','IP','UserAgent'):
            self.assertNotIn(key,query['_source'])
        self.assertIn(RAW,json.dumps(query));self.assertIn(KEY,json.dumps(query))
        bad=sample();bad['last_observed_ns']=T+3_600_000_000_001
        with self.assertRaises(ValueError):request_query(bad)
        bad=sample();bad['source_request_ids']=['f'*32]
        with self.assertRaises(ValueError):request_query(bad)

    def test_source_paths_and_unrecognized_dispatch_survive_without_payload_values(self):
        s=Source(packet([row(RAW,path='DBPath.pishkhan24.application.ud_prc_userSessionHasAccess',
            message='(SQL Parameters: @action=v1/NewUnknownRoute @userAgent=private-agent @rsaKey=private-secret)'),
            row(RAW,path='ClientAyanCoTopUp.TopUpChargeCustom',message='Input:{"LineNumber":"private-number"} Output:{"Amount":987654321}')]))
        report=inspect_sample(s,sample());text=json.dumps(report)
        self.assertEqual(report['coverage'],'COMPLETE_WITHIN_QUERY_RANGE')
        self.assertIn('v1/NewUnknownRoute',text);self.assertIn('LineNumber',text)
        for value in ('private-agent','private-secret','private-number','987654321'):
            self.assertNotIn(value,text)
        self.assertEqual(len(s.calls),1)
        self.assertIn('_search?allow_partial_search_results=false',s.calls[0][0])

    def test_oversize_or_mismatched_or_duplicate_search_is_not_complete(self):
        s=Source(packet([row(RAW)],total=300))
        self.assertEqual(inspect_sample(s,sample())['coverage'],'PARTIAL_WITHIN_QUERY_RANGE')
        s=Source(packet([row('f'*32)]))
        result=inspect_sample(s,sample());self.assertEqual(result['identity_mismatches'],1)
        self.assertEqual(result['documents'],[])
        s=Source(packet([row(RAW),row(RAW)]));s.result['hits']['hits'][1]['_id']='0'
        self.assertEqual(inspect_sample(s,sample())['coverage'],'PARTIAL_WITHIN_QUERY_RANGE')

    def test_timeouts_and_partial_shards_are_rejected(self):
        s=Source(packet([]));s.result['timed_out']=True
        with self.assertRaises(ElasticPageError):inspect_sample(s,sample())
        s=Source(packet([]));s.result['_shards']['failed']=1
        with self.assertRaises(ElasticPageError):inspect_sample(s,sample())

    def test_zero_results_are_visible_and_not_proof_of_global_absence(self):
        report=inspect_sample(Source(packet([])),sample())
        self.assertEqual(report['matched_source_documents'],0)
        self.assertEqual(report['coverage'],'COMPLETE_WITHIN_QUERY_RANGE')
        self.assertIn('query_range',report)

    def test_diverse_selection_is_bounded_and_deduplicated(self):
        rows=[dict(sample(),request_id=f'{i:032x}',retained_paths=['common']) for i in range(10)]
        rows.append(dict(sample(),request_id='f'*32,retained_paths=['rare']))
        review={'groups':{'WAITING':{'samples':rows},'EXPIRED':{'samples':rows}}}
        selected=choose_samples(review,2)
        self.assertEqual(len(selected),4)
        self.assertEqual(len({r['request_id'] for r in selected}),4)
        self.assertEqual(selected[1]['retained_paths'],['rare'])
        with self.assertRaises(ValueError):choose_samples(review,9)

    def test_collection_reports_failures_without_exception_text_or_database_access(self):
        s=Source(packet([]))
        def failure(*args,**kwargs):raise RuntimeError('credential-do-not-export')
        s.request=failure
        review={'groups':{'WAITING':{'samples':[sample()]}}}
        r=collect({},review,source_factory=lambda *a,**k:s)
        self.assertEqual(r['samples'][0]['coverage'],'QUERY_FAILED')
        self.assertNotIn('credential-do-not-export',json.dumps(r))
        self.assertFalse(r['database_modified']);self.assertFalse(r['workers_restarted'])
        review['counters']={'stream_id':'another-source'}
        with self.assertRaisesRegex(ValueError,'namespace_mismatch'):
            collect({},review,source_factory=lambda *a,**k:s)


if __name__=='__main__':unittest.main()
