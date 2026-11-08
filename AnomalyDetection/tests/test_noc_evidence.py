from copy import deepcopy
import unittest
from anomaly_detection.noc_evidence import aggregate,reason
from anomaly_detection.request_profiles import input_features
from anomaly_detection.case_summary import explanation
from anomaly_detection.snapshot import digest
from tests.test_longitudinal import request,T,DAY,SERVICE


class NocEvidenceTests(unittest.TestCase):
    def test_100_requests_for_one_bill_and_100_distinct_bills_are_distinguished(self):
        same=[request('a',T+i,'bill') for i in range(100)]
        distinct=[request('a',T+i,'bill'+str(i)) for i in range(100)]
        a=aggregate(same+same);b=aggregate(distinct)
        self.assertEqual(a['requests'],100);self.assertEqual(len(a['fields'][(SERVICE,'$.BillID')]),1)
        self.assertEqual(len(a['tokens'][0]['requests']),100)
        self.assertEqual(len(b['fields'][(SERVICE,'$.BillID')]),100)
    def test_unknown_profiles_are_not_reported_as_zero_or_a_complete_one_bill(self):
        rows=[request('a',T+i,'bill') for i in range(100)]
        for r in rows[:20]:r['qualified']=False
        a=aggregate(rows)
        self.assertEqual(a['qualified'],80);self.assertEqual(a['unknown_profiles'],20)
        self.assertEqual(a['field_coverage'][(SERVICE,'$.BillID')],80)
    def test_field_and_endpoint_namespaces_never_collapse_identifiers(self):
        r=request('a',T,'bill')
        r['subjects']+=[dict(r['subjects'][0],channel='another-service'),dict(r['subjects'][0],field='$.NationalCode')]
        a=aggregate([r]);self.assertEqual(len(a['fields']),3)
    def test_ip_counts_have_exact_request_members_and_do_not_merge_sessions(self):
        rows=[request('a',T+i,'b','client'+str(i%3)) for i in range(12)]
        a=aggregate(rows)
        self.assertEqual(len(a['ips']),3);self.assertEqual(len(a['ips'][0]['requests']),4)
        self.assertEqual(a['ip_covered_requests'],12)
    def test_days_use_tehran_and_unknown_days_are_not_filled_as_zero(self):
        a=aggregate([request('a',T,'b'),request('a',T+3*DAY,'b')])
        self.assertEqual(len(a['days']),2)
    def test_noc_reason_escapes_data_and_explains_actual_coverage(self):
        html=reason({'family':'service_health','explanation_fa':'<script>x</script>','begin_ns':T,'end_ns':T+1,
            'evidence_verified':False,'single_signal_review_eligible':False,'supporting_failure_sessions':3},fresh=False)
        self.assertNotIn('<script>',html);self.assertIn('&lt;script&gt;',html)
        self.assertIn('قطعی',html);self.assertIn('بازبینی',html);self.assertIn('کامل یا تأییدشده نیست',html)
    def test_decrease_and_error_have_distinct_plain_language_summaries(self):
        body={'issue_kind':'service_volume','strongest':{'family':'service_volume','direction':'decrease','observed':0,'expected':100,'lower':90,'upper':110,'duration_ns':300000000000}}
        self.assertIn('کاهش فعالیت',explanation(body));self.assertIn('کاهش درخواست با قطعی یکسان نیست',reason(body['strongest']))
        body['phase']='NO_CURRENT_SIGNAL';self.assertIn('این الگو در ارزیابی بعدی دیده نشده',explanation(body))
        body['phase']='RETURNED';self.assertIn('دوباره دیده شده',explanation(body))
    def test_masked_identifier_keeps_original_equality_without_persisting_secret_or_full_id(self):
        a=input_features({'BillID':'00123456789','NationalCode':'0041234567','Token':'secret'},SERVICE)
        self.assertNotIn('00123456789',str(a));self.assertNotIn('0041234567',str(a));self.assertNotIn('secret',str(a))
        self.assertEqual(a['subjects'][0]['display'],'…6789')
    def test_export_omits_plain_client_ip_displays_from_profiles_and_profile_versions(self):
        import json
        from anomaly_detection.case_export import compact
        for name in ('case_request_profiles','case_profile_versions'):
            row=compact(name,{'body':json.dumps({'ip_keys':['digest'],'ip_display':{'digest':'192.0.2.5'},'subjects':[]})})
            self.assertNotIn('192.0.2.5',row['body']);self.assertIn('digest',row['body'])


if __name__=='__main__':unittest.main()
