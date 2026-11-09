"""LC1B: bounded evidence diagnostics must sample *each* typed kind.

Source-index presence != a confirmed payment bridge or financial outcome.
"""
from __future__ import annotations
import unittest
from tests.test_viewer_r6_s1b_quality import S1BBehaviorEvidenceTests
from tests.test_viewer_r6_service_journey import log, sql
from p24_foundation.service_journey import VERSION


class LC1BGapSamplingTests(unittest.TestCase):
    setUp=S1BBehaviorEvidenceTests.setUp
    ingest=S1BBehaviorEvidenceTests.ingest
    key=S1BBehaviorEvidenceTests.key

    def test_index_witnesses_from_each_kind_even_when_first_50_are_invoices(self):
        logs=[log(i,'invoice_pay',
               'DBPath.pishkhan24.application.ud_prc_invoiceInfo',
               sql('ud_prc_invoiceInfo',invoiceUniqueID='I-'+str(i)),second=1)
              for i in range(1,61)]
        logs.extend([
            log(61,'invoice_pay','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',
                sql('ud_prc_paymentGetInfo',paymentKey='K'),second=2),
            log(62,'invoice_pay','Core.v1/InvoicePayment Line:1329',
                'POST (G00000 | successful)',second=2),
            log(63,'wallet','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',
                sql('ud_prc_paymentGetInfo',paymentKey='K'),second=3),
            log(64,'wallet','Core.v1/WalletPayment Line:1084',
                'POST (G00000 | successful)',second=3),
        ])
        self.ingest(logs)
        result=self.db.service_journey(self.key('invoice_pay'))
        self.assertEqual(result['version'],VERSION)
        self.assertEqual(result['entry_request_key'],self.key('invoice_pay'))
        self.assertEqual(2,len(result['steps']))
        gap=next(x for x in result['bridge_diagnostics'] if x['name']=='invoice_to_payment_execution')
        self.assertEqual(gap['status'],'linked')
        self.assertEqual(gap['indexed_kinds'],['internal_payment','invoice'])
        self.assertEqual(gap['missing_indexed_kinds'],[])
        kinds={e['kind'] for e in gap['evidence_refs']}
        self.assertEqual(kinds,{'invoice','internal_payment'})
        self.assertTrue(all(e['origin_key'] and e['version_key'] and e['field_path'] for e in gap['evidence_refs']))
        self.assertEqual(gap['precision'],'component_relation_not_payment_for_exact_inquiry')
        self.assertIsNone(result['confirmed_manual_action_count'])
        self.assertEqual(result['financial_confirmation'],'unverified')

    def test_missing_internal_payment_is_explicit_and_scoped(self):
        self.ingest([
            log(1,'invoice_pay','DBPath.pishkhan24.application.ud_prc_invoiceInfo',
                sql('ud_prc_invoiceInfo',invoiceUniqueID='I'),second=1),
            log(2,'invoice_pay','Core.v1/InvoicePayment Line:1329',
                'POST (G00000 | successful)',second=1),
        ])
        result=self.db.service_journey(self.key('invoice_pay'))
        gap=result['bridge_diagnostics'][0]
        self.assertEqual(gap['status'],'evidence_not_observed')
        self.assertEqual(gap['indexed_kinds'],['invoice'])
        self.assertEqual(gap['missing_indexed_kinds'],['internal_payment'])
        self.assertEqual(gap['scope'],'indexed_viewer_capture_component')
        self.assertEqual(gap['edge_stage'],'unproven')
        self.assertEqual(result['observed_product_reservation_execution_count'],0)
        self.assertEqual(result['observed_wallet_funding_execution_count'],0)

    def test_payment_callbacks_remain_provisional_and_not_service_counts(self):
        self.ingest([
            log(1,'cb','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',
                sql('ud_prc_paymentGetInfo',paymentKey='K'),second=1),
            log(2,'cb','PaymentCallback.PaymentCallback Line:18',
                'POST (G00000 | successful)',second=1),
        ])
        result=self.db.service_journey(self.key('cb'))
        self.assertEqual(result['identity_status'],'provisional_technical')
        self.assertEqual(result['observed_service_execution_count'],0)
        self.assertEqual(result['observed_wallet_funding_execution_count'],0)
        self.assertEqual(result['observed_product_reservation_execution_count'],0)
        self.assertIsNone(result['confirmed_manual_action_count'])

if __name__=='__main__':unittest.main()
