import unittest
from compact_behavior.extract import facts, merge, materialize, sql_fields
from tests.test_compact_extract import row


class NullableContentTests(unittest.TestCase):
    def request(self, payload):
        base = facts(row('r', 's', path='Services.v1/WaterBills'))
        provider = facts(row('r', 's', path='ClientAyanCoInquiry.WaterBillInquiry', message='Input:{"BillID":"123"} Output:{"Amount":42}'))
        sql = facts(row('r', 's', path='DBPath.pishkhan24.application.ud_prc_inquiryInvoiceResult2',message='(SQL Parameters: @queryParameters={"BillID":"123"} @queryResult='+payload+' @queryResultHash= @flag=1)'))
        return materialize('stream',merge(merge(base,provider),sql))

    def test_empty_sql_payload_is_absent_and_reviewed_provider_is_eligible(self):
        result=self.request('')
        self.assertTrue(result['features']['output_feature_eligibility']['shape'])
        self.assertTrue(result['features']['output_feature_eligibility']['numeric'])
        self.assertNotIn('outputs_parse_error',result['quality'])

    def test_nonempty_invalid_sql_still_blocks_fallback(self):
        result=self.request('{broken}')
        self.assertFalse(result['features']['output_feature_eligibility']['shape'])
        self.assertIn('outputs_parse_error',result['quality'])

    def test_duplicate_keys_are_not_absence(self):
        self.assertFalse(self.request('{"Amount":1,"Amount":2}')['features']['output_feature_eligibility']['numeric'])

    def test_empty_does_not_synthesize_output(self):
        values,errors=sql_fields('(SQL Parameters: @queryParameters= @queryResult= @flag=1)')
        self.assertEqual((values,errors),({},set()))

    def test_reviewed_post_provider_is_bound_but_other_provider_is_not(self):
        base=facts(row('r','s',path='Services.v1/PostPackagesStatus'))
        for path,expected in [('ClientAyanCoInquiry.PostTrackingInquiry',True),('ClientAyanCoInquiry.SfaraCouponInquiry',False)]:
            provider=facts(row('r','s',path=path,message='Output:{"Count":42}'))
            result=materialize('stream',merge(base,provider))
            self.assertEqual(result['features']['output_feature_eligibility']['shape'],expected)
