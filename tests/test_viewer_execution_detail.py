"""Execution presentation: truthful outcomes, bounded reads and usable drilldown."""
import copy
from html.parser import HTMLParser
import json
import unittest
from unittest.mock import patch

from p24_foundation.viewer_execution_detail import execution_detail
from p24_foundation.viewer_online import FIVE_NS
from p24_foundation.viewer_ui import create_viewer_app
from tests import test_viewer_service_dispatch as fixture
from tests import test_viewer_payment_correlations as payments
from tests.test_viewer_online import START, snapshot
from tests.test_viewer_r6_service_journey import sql


class Sections(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.stack = []
        self.folded = {}
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get('id'):
            self.folded[attrs['id']] = any(t == 'details' and 'open' not in a for t, a in self.stack)
        if tag not in ('meta', 'link', 'br', 'hr', 'input', 'img', 'wbr'):
            self.stack.append((tag, attrs))

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break


class ExecutionDetailTests(unittest.TestCase):
    setUp = fixture.ServiceDispatchTests.setUp
    row = fixture.ServiceDispatchTests.row
    provider = fixture.ServiceDispatchTests.provider
    flow = fixture.ServiceDispatchTests.flow
    publish = fixture.ServiceDispatchTests.publish

    def postal(self, request='postal'):
        rows = self.flow(request, 'F' * 32, 'result')
        for row in rows:
            if row['CallPath'].endswith('userSessionHasAccess'):
                row['message'] = sql('ud_prc_userSessionHasAccess', action='v1/PostPackagesStatus')
            if row['CallPath'].endswith('invoiceRequest'):
                row['message'] = sql('ud_prc_invoiceRequest', serviceID=1460)
            if 'ElectronicPrescriptionInquiry' in row['CallPath']:
                row['CallPath'] = 'ClientAyanCoInquiry.PostTrackingInquiry Line:727'
                row['message'] = 'POST (G00000 | successful) Input:' + json.dumps([
                    dict(PackageNumber='001234567890123456789012')]) + ' Output:' + json.dumps([
                    dict(Status=dict(Code='G00000', Description='reported'),
                         Parameters=dict(Source='مبدأ نمونه', Destination='مقصد نمونه'))])
        return [r for r in rows if 'MyGovRequestOtp' not in r['CallPath']]

    def detail(self, request):
        card = self.db.lookup_request(request)
        return execution_detail(self.db, card)

    def test_postal_summary_and_each_step_open_original_evidence_without_writes(self):
        self.publish(self.postal())
        before = snapshot(self.db)
        raw = self.db.all('SELECT * FROM viewer_raw_events ORDER BY origin_key,version_key')
        roles = self.db.all('SELECT * FROM viewer_service_roles ORDER BY service_path')
        detail = self.detail('postal')
        self.assertEqual(detail['service'], 'Services.v1/PostPackagesStatus')
        self.assertEqual(detail['result_basis'], 'نتیجهٔ استعلام')
        self.assertEqual(detail['result_status'], 'success')
        self.assertEqual(detail['result_codes'], ['G00000'])
        self.assertEqual(detail['invoices'], ['F' * 32])
        self.assertEqual(detail['highlights'][0]['value'], '001234567890123456789012')
        self.assertFalse(detail['otp_observed'])
        self.assertFalse(detail['has_payments'])
        self.assertEqual([s['kind'] for s in detail['steps']], ['request', 'provider', 'inquiry_result'])
        client = create_viewer_app(self.opts).test_client()
        key = self.db.lookup_request('postal')['request_key']
        response = client.get('/request/' + key)
        self.assertEqual(response.status_code, 200)
        sections = Sections(response.get_data(as_text=True))
        for name in ('execution-overview', 'execution-steps'):
            self.assertFalse(sections.folded[name])
        for name in ('service-dispatch-context', 'request-raw', 'bill-item-journey'):
            self.assertTrue(sections.folded[name])
        self.assertNotIn('execution-payments', sections.folded)
        for step in detail['steps']:
            self.assertTrue(step['proofs'])
            for proof in step['proofs']:
                self.assertEqual(client.get('/evidence/' + proof['origin_key'] + '/' + proof['version_key']).status_code, 200)
        self.assertEqual(before, snapshot(self.db))
        self.assertEqual(raw, self.db.all('SELECT * FROM viewer_raw_events ORDER BY origin_key,version_key'))
        self.assertEqual(roles, self.db.all('SELECT * FROM viewer_service_roles ORDER BY service_path'))

    def test_successful_otp_and_provider_transport_do_not_hide_failed_inquiry(self):
        rows = self.flow('insurance', 'C' * 32, 'otp')
        rows[0]['message'] = 'POST (GD2076 | TaminHistoryInquiryFailed)'
        for row in rows:
            if row['CallPath'].endswith('userSessionHasAccess'):
                row['message'] = sql('ud_prc_userSessionHasAccess', action='v2/SocialSecurityInsuranceHistory')
        rows += [self.provider('insurance', 'MyGovLogin', inp=dict(OtpCode='test-secret-otp', TraceNumber='C' * 32)),
                 self.provider('insurance', 'TaminHistoryInquiry', code='GD2076'),
                 self.row('insurance', 'DBPath.a.ud_prc_inquiryInvoiceResult2',
                          sql('ud_prc_inquiryInvoiceResult2', invoiceUniqueID='C' * 32, statusCode='GD2076'))]
        self.publish(rows)
        detail = self.detail('insurance')
        self.assertEqual(detail['result_status'], 'failure')
        self.assertEqual(detail['result_codes'], ['GD2076'])
        verify = next(s for s in detail['steps'] if s['kind'] == 'otp_validation')
        provider = next(s for s in detail['steps'] if s['kind'] == 'provider')
        self.assertEqual(verify['status'], 'success')
        self.assertEqual(provider['status'], 'failure')
        self.assertIn(('پاسخ ارتباطی Provider', 'G00000'), provider['fields'])
        self.assertIn(('نتیجهٔ داخل پاسخ Provider', 'GD2076'), provider['fields'])
        self.assertNotIn('test-secret-otp', json.dumps(detail))
        self.assertEqual(detail['related_count'], 0)

    def test_raw_pagination_does_not_change_result_and_opens_technical_details(self):
        self.publish(self.postal())
        key = self.db.lookup_request('postal')['request_key']
        client = create_viewer_app(self.opts).test_client()
        html = client.get('/request/' + key + '?page=2&limit=1').get_data(as_text=True)
        self.assertIn('id="request-technical" open', html)
        self.assertIn('001234567890123456789012', html)
        self.assertIn('G00000', html.split('id="execution-overview"', 1)[1].split('</section>', 1)[0])
        with patch('p24_foundation.viewer_execution_detail.EVENT_LIMIT', 1):
            detail = self.detail('postal')
        self.assertTrue(detail['incomplete'])
        self.assertEqual(detail['result_codes'], ['G00000'])

    def test_global_competing_version_cannot_create_success_or_postal_highlight(self):
        rows = self.postal()
        self.publish(rows)
        provider = next(r for r in rows if 'PostTrackingInquiry' in r['CallPath'])
        conflict = copy.deepcopy(provider)
        conflict['RequestID'] = 'outside-request'
        conflict['message'] = 'POST (GD2076 | failed)'
        self.publish([conflict], start=START + FIVE_NS)
        detail = self.detail('postal')
        self.assertTrue(detail['conflicted'])
        self.assertEqual(detail['result_status'], 'mixed')
        self.assertEqual(detail['highlights'], [])
        self.assertFalse(any(s['status'] == 'success' for s in detail['steps']))

    def test_payment_namespaces_and_multiple_reports_of_one_request_stay_separate(self):
        rows = payments.scenario()
        rows.append(payments.correlation(60, 'fee-result', 'PaymentKey-Status',
                                        dict(PaymentKey=payments.FEE, Status='Failed'), session='N/A'))
        self.publish(rows)
        detail = self.detail('inquiry')
        self.assertEqual(detail['fee_payment_count'], 1)
        self.assertEqual(detail['bill_payment_count'], 1)
        self.assertTrue(detail['has_payments'])
        self.assertTrue(any(r['label'] == 'پرداخت هزینهٔ استعلام' for r in detail['related']))
        self.assertTrue(any(r['label'] == 'پرداخت قبض' for r in detail['related']))
        status_rows = [r for r in detail['related'] if r['label'] == 'گزارش وضعیت پرداخت'
                       and r['raw_request_id'] == 'fee-result']
        self.assertEqual({r['code'] for r in status_rows}, {'Success', 'Failed'})
        payment = self.db.lookup_request('inquiry')['service_payments']['invoices'][0]['inquiry_payments'][0]
        self.assertEqual(payment['outcome'], 'multiple_statuses')

    def test_provider_html_is_escaped_and_duplicate_json_is_not_positive(self):
        rows = self.postal()
        provider = next(r for r in rows if 'PostTrackingInquiry' in r['CallPath'])
        provider['message'] = 'Output:{"Status":{"Code":"G00000","Description":"<script>bad()</script>"}}'
        self.publish(rows)
        key = self.db.lookup_request('postal')['request_key']
        html = create_viewer_app(self.opts).test_client().get('/request/' + key).get_data(as_text=True)
        self.assertNotIn('<script>bad()', html)
        self.assertIn('&lt;script&gt;bad()', html)
        from p24_foundation.viewer_execution_detail import _provider_body
        import zlib
        body = _provider_body(zlib.compress(json.dumps(dict(message='Output:{"Status":{"Code":"G00000","Code":"GD2076"}}')).encode()))
        self.assertEqual(body['output'], {})

    def test_missing_or_oversized_raw_payload_does_not_promote_transport_to_business_result(self):
        self.publish(self.postal())
        with patch('p24_foundation.viewer_execution_detail.RAW_LIMIT', 20):
            detail = self.detail('postal')
        provider = next(s for s in detail['steps'] if s['kind'] == 'provider')
        self.assertEqual(provider['status'], 'unknown')
        self.assertIsNone(provider['code'])
        self.assertEqual(detail['highlights'], [])
        self.assertEqual(detail['result_codes'], ['G00000'])  # Independent SQL report.

    def test_direct_api_also_shows_indexed_inquiry_failure_separately_from_http(self):
        rows = self.postal()
        rows[0]['CallPath'] = 'Services.v1/PostPackagesStatus Line:1'
        result = next(r for r in rows if r['CallPath'].endswith('inquiryInvoiceResult2'))
        result['message'] = sql('ud_prc_inquiryInvoiceResult2', invoiceUniqueID='F' * 32, statusCode='GD2076')
        self.publish(rows)
        self.assertIsNone(self.db.lookup_request('postal').get('service_context'))
        detail = self.detail('postal')
        self.assertEqual(detail['result_basis'], 'نتیجهٔ استعلام')
        self.assertEqual(detail['result_status'], 'failure')
        self.assertEqual(detail['result_codes'], ['GD2076'])

    def test_otp_prerequisite_is_not_presented_as_a_completed_successful_service(self):
        self.publish(self.flow('otp-only', 'D' * 32, 'otp'))
        detail = self.detail('otp-only')
        self.assertEqual(detail['result_status'], 'observed')
        self.assertEqual(detail['result_label'], 'نیاز به OTP')
        self.assertEqual(detail['result_codes'], [])


if __name__ == '__main__':
    unittest.main()
