"""R6.2 S1C: behavior-kind evidence and honest graph coverage.

Synthetic-only; never use amount/session/time as a relationship edge.
"""
from __future__ import annotations
import unittest
from tests.test_viewer_r6_s1b_quality import S1BBehaviorEvidenceTests
from tests.test_viewer_r6_service_journey import log, sql


class S1CBehaviorEvidenceTests(unittest.TestCase):
    setUp = S1BBehaviorEvidenceTests.setUp
    ingest = S1BBehaviorEvidenceTests.ingest
    key = S1BBehaviorEvidenceTests.key

    def test_topup_reservation_plus_payment_is_candidate_not_manual_count(self):
        rows=[
            log(1,'invoice','DBPath.pishkhan24.application.ud_prc_invoiceRegister',
                sql('ud_prc_invoiceRegister', invoiceUniqueID='INV-1'),second=1),
            log(2,'invoice','ClientAyanCoTopUp.ProductReserve Line:25',
                'Input:[{}]\nOutput:[{"Parameters":{"PurchaseKey":"RES-1"},"Status":{"Code":"G00000"}}]',second=1),
            log(3,'invoice','Services.v1/InvoiceRegister Line:17','POST (G00000 | successful)',second=1),
            log(4,'payment','DBPath.pishkhan24.application.ud_prc_paymentRequestForInvoiceSettlement',
                sql('ud_prc_paymentRequestForInvoiceSettlement',invoiceUniqueID='INV-1',paymentKey='PAY-1'),second=2),
            log(5,'payment','Core.v1/InvoicePayment Line:1329','POST (G00000 | successful)',second=2),
            log(6,'wallet','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',
                sql('ud_prc_paymentGetInfo',paymentKey='PAY-1'),second=3),
            log(7,'wallet','Core.v1/WalletPayment Line:1084','POST (G00000 | successful)',second=3),
            log(8,'notify','DBPath.pishkhan24.application.ud_prc_webhooksInformPurchaseStatus',
                sql('ud_prc_webhooksInformPurchaseStatus',paymentKey='PAY-1',status='Finalized'),session='N/A',second=4),
            log(9,'notify','Webhook.v1/InformPurchaseStatus Line:79','POST (G00000 | successful)',session='N/A',second=4),
        ]
        self.ingest(rows)
        j=self.db.service_journey(self.key('wallet'))
        self.assertEqual(j['behavior_kind'],'product_purchase_journey_candidate')
        self.assertEqual(j['behavior_evidence'],'topup_provider_product_reserve_observed')
        self.assertEqual(j['fulfillment_statuses_observed'],['Finalized'])
        self.assertFalse(j['fulfillment_history_complete'])
        self.assertIsNone(j['customer_action_count'])
        self.assertEqual(j['financial_confirmation'],'unverified')

    def test_gateway_payment_without_product_reservation_is_not_purchase(self):
        rows=[
            log(1,'gateway','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',
                sql('ud_prc_paymentGetInfo',paymentKey='K-1'),second=1),
            log(2,'gateway','ClientAyanCoPaymentGateway.ReportNewPurchase Line:9',
                'Input:[{}]\nOutput:[{"Status":{"Code":"G00000"}}]',second=1),
            log(3,'gateway','PaymentRedirect.PaymentRedirect Line:19',
                'POST (G00000 | successful)',second=1),
        ]
        self.ingest(rows)
        j=self.db.service_journey(self.key('gateway'))
        self.assertEqual(j['behavior_kind'],'technical_steps_only')
        self.assertEqual(j['fulfillment_statuses_observed'],[])
        self.assertFalse(j['fulfillment_history_complete'])
        self.assertIsNone(j['customer_action_count'])

    def test_chain_closure_is_not_limited_to_two_hops(self):
        rows=[
            log(1,'anchor','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',sql('ud_prc_paymentGetInfo',paymentKey='K1'),second=1),
            log(2,'r2','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',sql('ud_prc_paymentGetInfo',paymentKey='K1'),second=2),
            log(3,'r2','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',sql('ud_prc_paymentGetInfo',paymentKey='K2'),second=2),
            log(4,'r3','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',sql('ud_prc_paymentGetInfo',paymentKey='K2'),second=3),
            log(5,'r3','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',sql('ud_prc_paymentGetInfo',paymentKey='K3'),second=3),
            log(6,'r4','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',sql('ud_prc_paymentGetInfo',paymentKey='K3'),second=4),
        ]
        self.ingest(rows)
        j=self.db.service_journey(self.key('anchor'))
        self.assertEqual(len(j['steps']),4)
        self.assertFalse(j['truncated'])
        self.assertEqual(j['truncation_reasons'],[])
        self.assertEqual([],j['coverage_caveats'])
        self.assertIn(self.key('r4'),{r['request_key'] for r in j['steps']})

    def test_exhausted_anchor_component_has_no_hop_ceiling_warning(self):
        rows=[log(1,'alone','PaymentCallback.PaymentCallback Line:18','POST (G00000 | successful)',session='N/A')]
        self.ingest(rows)
        j=self.db.service_journey(self.key('alone'))
        self.assertEqual(j['steps'][0]['role'],'system_followup')
        self.assertEqual(j['coverage_caveats'],[])
        self.assertFalse(j['truncated'])
        self.assertEqual(j['truncation_reasons'],[])
        self.assertIsNone(j['customer_action_count'])



if __name__ == '__main__':
    unittest.main()
