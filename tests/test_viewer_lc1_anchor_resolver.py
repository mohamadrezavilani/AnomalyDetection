"""LC1 conservative bridge/anchor regressions on disposable Viewer SQLite."""
from __future__ import annotations
import unittest
from tests.test_viewer_r6_s1b_quality import S1BBehaviorEvidenceTests
from tests.test_viewer_r6_service_journey import log, sql

class LC1AnchorResolverTests(unittest.TestCase):
    setUp = S1BBehaviorEvidenceTests.setUp
    ingest = S1BBehaviorEvidenceTests.ingest
    key = S1BBehaviorEvidenceTests.key

    def test_three_plus_hops_close_and_payment_entry_resolves_service_anchor(self):
        records = [
            log(1,'inquiry','DBPath.pishkhan24.application.ud_prc_invoiceInfo',sql('ud_prc_invoiceInfo',invoiceUniqueID='I-1'),second=1),
            log(2,'inquiry','Services.v1/TrafficFinesCarNoDetails Line:302','POST (G00000 | successful)',second=1),
            log(3,'r2','DBPath.pishkhan24.application.ud_prc_invoiceInfo',sql('ud_prc_invoiceInfo',invoiceUniqueID='I-1'),second=2),
            log(4,'r2','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',sql('ud_prc_paymentGetInfo',paymentKey='K-1'),second=2),
            log(5,'r3','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',sql('ud_prc_paymentGetInfo',paymentKey='K-1'),second=3),
            log(6,'r3','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',sql('ud_prc_paymentGetInfo',paymentKey='K-2'),second=3),
            log(7,'r4','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',sql('ud_prc_paymentGetInfo',paymentKey='K-2'),second=4),
            log(8,'r4','Core.v1/WalletPayment Line:1084','POST (G00000 | successful)',second=4),
        ]
        self.ingest(records)
        a = self.db.service_journey(self.key('inquiry'))
        b = self.db.service_journey(self.key('r4'))
        self.assertEqual(4,len(a['steps']))
        self.assertFalse(a['truncated'])
        self.assertEqual(a['canonical_occurrence_key'],b['canonical_occurrence_key'])
        self.assertEqual(a['identity_status'],'resolved')
        self.assertEqual(a['observed_service_execution_count'],1)
        self.assertIsNone(a['confirmed_manual_action_count'])
        self.assertEqual(a['bridge_diagnostics'][0]['status'],'linked')

    def test_two_inquiries_same_invoice_are_not_one_occurrence(self):
        self.ingest([
            log(1,'q1','DBPath.pishkhan24.application.ud_prc_invoiceInfo',sql('ud_prc_invoiceInfo',invoiceUniqueID='I'),second=1),
            log(2,'q1','Services.v1/TrafficFinesCarNoDetails Line:302','POST (G00000 | successful)',second=1),
            log(3,'q2','DBPath.pishkhan24.application.ud_prc_invoiceInfo',sql('ud_prc_invoiceInfo',invoiceUniqueID='I'),second=3),
            log(4,'q2','Services.v1/TrafficFinesCarNoDetails Line:302','POST (G00000 | successful)',second=3),
        ])
        a=self.db.service_journey(self.key('q1'))
        b=self.db.service_journey(self.key('q2'))
        self.assertEqual(a['identity_status'],'multiple_anchors_not_merged')
        self.assertIsNone(a['canonical_occurrence_key'])
        self.assertEqual({x['occurrence_key'] for x in a['resolved_occurrences']},
                         {x['occurrence_key'] for x in b['resolved_occurrences']})
        self.assertEqual(2,a['observed_service_execution_count'])
        self.assertIsNone(a['confirmed_manual_action_count'])

    def test_callback_is_provisional_and_does_not_invent_wallet_funding(self):
        self.ingest([
            log(1,'callback','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',sql('ud_prc_paymentGetInfo',paymentKey='K'),session='N/A'),
            log(2,'callback','PaymentCallback.PaymentCallback Line:18','POST (G00000 | successful)',session='N/A'),
            log(3,'fund','Core.v1/UserWalletCharge Line:1165','POST (G00000 | successful)'),
        ])
        a=self.db.service_journey(self.key('callback'))
        self.assertEqual(a['identity_status'],'provisional_technical')
        self.assertIsNone(a['canonical_occurrence_key'])
        self.assertTrue(a['provisional_reference'].startswith('prov1:'))
        self.assertNotIn(self.key('fund'), {r['request_key'] for r in a['steps']})
        self.assertEqual(a['bridge_diagnostics'][0]['status'],'evidence_not_observed')
        self.assertTrue(all('field_path' in e for e in a['bridge_diagnostics'][0]['evidence_refs']))

    def test_explicit_eligible_provider_binding_only(self):
        self.ingest([
            log(1,'k','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',sql('ud_prc_paymentGetInfo',paymentKey='K'),second=1),
            log(2,'tok','DBPath.pishkhan24.application.ud_prc_paymentServiceReportToken',sql('ud_prc_paymentServiceReportToken',paymentKey='K',token='TOKEN-1'),second=2),
            log(3,'tok','PaymentRedirect.PaymentRedirect Line:19','POST (G00000 | successful)',second=2),
            log(4,'callback','DBPath.pishkhan24.application.ud_prc_paymentServiceReportToken',sql('ud_prc_paymentServiceReportToken',paymentKey='OTHER',token='TOKEN-1'),second=3),
            log(5,'callback','PaymentCallback.PaymentCallback Line:18','POST (G00000 | successful)',second=3),
        ])
        a=self.db.service_journey(self.key('k'))
        # This broad scenario exposes same typed report_token but there must be
        # no financial finality, user ownership or same payment execution claim.
        self.assertEqual(a['financial_confirmation'],'unverified')
        self.assertIsNone(a['confirmed_manual_action_count'])
        self.assertIn(self.key('tok'),{s['request_key'] for s in a['steps']})
        self.assertNotIn(self.key('callback'),{s['request_key'] for s in a['steps']})
        self.assertTrue(a['rejected_bindings'])
        self.assertTrue(all(e['certainty']=='same_reference_not_same_execution' for e in a['edges']))

    def test_bounded_walk_reports_incomplete_not_payment_failure(self):
        self.ingest([log(i,('r'+str(i)),
                    'DBPath.pishkhan24.application.ud_prc_paymentGetInfo',
                    sql('ud_prc_paymentGetInfo',paymentKey='K'),second=i)
                     for i in range(1,6)])
        j=self.db.service_journey(self.key('r1'),max_requests=2)
        self.assertTrue(j['truncated'])
        self.assertIn('request_cap',j['truncation_reasons'])
        self.assertEqual(j['identity_status'],'provisional_technical')
        self.assertIsNone(j['confirmed_manual_action_count'])

if __name__=='__main__':unittest.main()
