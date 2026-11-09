"""R6.2 S1B regression checks: conservative evidence linking and operator UI.

No real customer IDs, tokens or production DB access. Tests use isolated SQLite.
"""
from __future__ import annotations
import gzip
import json
import tempfile
import unittest
from pathlib import Path

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.service_journey import VERSION
from tests.test_viewer_r6_service_journey import sql, log


class S1BBehaviorEvidenceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        key = root / 'keys.json'
        generate_keys(key)
        self.root = root
        self.db = ViewerDB(sqlite_path=root / 'viewer.db', keys_path=key)
        self.addCleanup(self.db.close)
        self.db.init()

    def ingest(self, records):
        path = self.root / 'synthetic.json.gz'
        with gzip.open(path, 'wt', encoding='utf8') as output:
            json.dump({'window_start':'2026-10-24T04:15:00Z',
                       'window_end':'2026-10-24T04:20:00Z',
                       'count':len(records),'logs':records},output)
        self.db.ingest([path])
        self.db.rebuild()
        self.db.rebuild_payment_contract()

    def key(self, raw_id):
        return self.db.lookup_request(raw_id)['request_key']

    def test_duplicate_contract_occurrences_do_not_repeat_logical_peer_edges(self):
        records = [log(n, 'callback',
                       'DBPath.pishkhan24.application.ud_prc_paymentGetInfo',
                       sql('ud_prc_paymentGetInfo',paymentKey='K-A'), session='N/A', second=10)
                   for n in range(1,9)]
        records += [log(9,'callback','PaymentCallback.PaymentCallback Line:18','POST (G00000 | successful)',session='N/A',second=11),
                    log(10,'redirect','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',
                        sql('ud_prc_paymentGetInfo',paymentKey='K-A'),second=9),
                    log(11,'redirect','PaymentRedirect.PaymentRedirect Line:19','POST (G00000 | successful)',second=9)]
        self.ingest(records)
        anchor = self.key('callback')
        original_count = self.db.one('SELECT COUNT(*) AS n FROM viewer_contract_identifiers WHERE request_key=?',(anchor,))['n']
        self.assertEqual(original_count,8)
        result = self.db.service_journey(anchor)
        self.assertEqual(VERSION,result['version'])
        self.assertEqual(2,len(result['steps']))
        self.assertEqual(1,len(result['edges']))
        self.assertEqual(result['edges'][0]['to_request_key'],self.key('redirect'))
        self.assertEqual(original_count,self.db.one('SELECT COUNT(*) AS n FROM viewer_contract_identifiers WHERE request_key=?',(anchor,))['n'])
        self.assertIn('funding_or_purchase_creation_link_not_observed_in_bounded_graph',result['limitations'])
        self.assertEqual(result['customer_action_count'],None)
        self.assertEqual(result['anchor_kind'],'technical_execution_not_independent_customer_action')

    def test_distinct_shared_objects_show_two_peers_without_false_merges(self):
        records = [
            log(1,'root','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',sql('ud_prc_paymentGetInfo',paymentKey='A')),
            log(2,'root','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',sql('ud_prc_paymentGetInfo',paymentKey='B')),
            log(3,'root','PaymentCallback.PaymentCallback Line:18','POST (G00000 | successful)'),
            log(4,'pA','DBPath.pishkhan24.application.ud_prc_paymentExists',sql('ud_prc_paymentExists',paymentKey='A')),
            log(5,'pB','DBPath.pishkhan24.application.ud_prc_paymentExists',sql('ud_prc_paymentExists',paymentKey='B')),
        ]
        self.ingest(records)
        j = self.db.service_journey(self.key('root'))
        self.assertEqual(3,len(j['steps']))
        self.assertEqual({self.key('pA'),self.key('pB')},{e['to_request_key'] for e in j['edges']})
        self.assertEqual(2,len(j['edges']))
        self.assertTrue(all(e['certainty']=='same_reference_not_same_execution' for e in j['edges']))

    def test_timeline_keeps_processing_finalized_and_provider_paid_separate(self):
        records = [
            log(1,'register','DBPath.pishkhan24.application.ud_prc_invoiceRegister',sql('ud_prc_invoiceRegister',invoiceUniqueID='I-1'),second=1),
            log(2,'register','Services.v1/InvoiceRegister Line:17','POST (G00000 | successful)',second=1),
            log(3,'payment','DBPath.pishkhan24.application.ud_prc_paymentRequestForInvoiceSettlement',sql('ud_prc_paymentRequestForInvoiceSettlement',invoiceUniqueID='I-1',paymentKey='K-1'),second=2),
            log(4,'payment','Core.v1/InvoicePayment Line:1','POST (G00000 | successful)',second=2),
            log(5,'wallet','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',sql('ud_prc_paymentGetInfo',paymentKey='K-1'),second=3),
            log(6,'wallet','ClientAyanCoTopUp.PaymentInfo Line:6','Input:[{}]\nOutput:[{"Parameters":{"Status":{"Name":"Paid"}},"Status":{"Code":"G00000"}}]',second=3),
            log(7,'wallet','Core.v1/WalletPayment Line:1','POST (G00000 | successful)',second=3),
            log(8,'poll','DBPath.pishkhan24.application.ud_prc_invoiceInfo',sql('ud_prc_invoiceInfo',invoiceUniqueID='I-1'),second=4),
            log(9,'poll','Services.v1/TopUpPurchaseInfo Line:138','Output:[{"Parameters":{"Status":{"Name":"Processing"}},"Status":{"Code":"G00000"}}]',second=4),
            log(10,'notify','DBPath.pishkhan24.application.ud_prc_webhooksInformPurchaseStatus',sql('ud_prc_webhooksInformPurchaseStatus',invoiceUniqueID='I-1',paymentKey='K-1',status='Finalized'),second=6,session='N/A'),
            log(11,'notify','Webhook.v1/InformPurchaseStatus Line:79','POST (G00000 | successful)',second=6,session='N/A'),
        ]
        self.ingest(records)
        j=self.db.service_journey(self.key('wallet'))
        self.assertEqual(5,len(j['steps']))  # register,payment,wallet,poll,notify
        self.assertTrue(any(s['role']=='support_status_lookup' for s in j['steps']))
        vals=[(v['axis'],v['value'],v['request_key']) for v in j['timeline']]
        self.assertIn(('provider_financial_observation','Paid',self.key('wallet')),vals)
        self.assertIn(('fulfillment_report','Processing',self.key('poll')),vals)
        self.assertIn(('fulfillment_report','Finalized',self.key('notify')),vals)
        self.assertLess(vals.index(('fulfillment_report','Processing',self.key('poll'))),
                        vals.index(('fulfillment_report','Finalized',self.key('notify'))))
        self.assertTrue(all(v['origin_key'] and v['version_key'] and v['field_path'] for v in j['timeline']))
        self.assertEqual(j['financial_confirmation'],'unverified')
        self.assertEqual(j['customer_action_count'],None)

    def test_fee_wallet_without_explicit_bridge_is_not_falsely_added(self):
        rows=[
            log(1,'invoice','DBPath.pishkhan24.application.ud_prc_invoiceRegister',sql('ud_prc_invoiceRegister',invoiceUniqueID='I'),second=1),
            log(2,'invoice','Services.v1/InvoiceRegister Line:1','POST (G00000 | successful)',second=1),
            log(3,'invoicepayment','DBPath.pishkhan24.application.ud_prc_paymentRequestForInvoiceSettlement',sql('ud_prc_paymentRequestForInvoiceSettlement',invoiceUniqueID='I'),second=2),
            log(4,'invoicepayment','Core.v1/InvoicePayment Line:1','POST (G00000 | successful)',second=2),
            log(5,'wallet','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',sql('ud_prc_paymentGetInfo',paymentKey='K-NOT-BRIDGED'),second=3),
            log(6,'wallet','Core.v1/WalletPayment Line:1','POST (G00000 | successful)',second=3),
            log(7,'query','DBPath.pishkhan24.application.ud_prc_inquiryInvoiceResult2',sql('ud_prc_inquiryInvoiceResult2',invoiceUniqueID='I'),second=4),
            log(8,'query','Services.v1/TrafficFinesCarNoDetails Line:302','POST (G00000 | successful)',second=4),
        ]
        self.ingest(rows)
        j=self.db.service_journey(self.key('query'))
        peers={x['request_key'] for x in j['steps']}
        self.assertIn(self.key('invoicepayment'),peers)
        self.assertNotIn(self.key('wallet'),peers)
        self.assertIn('invoice_to_followup_payment_execution_bridge_not_observed_in_bounded_graph',j['limitations'])
        self.assertEqual(j['financial_confirmation'],'unverified')

    def test_bounded_walk_exposes_truncation_and_never_counts_actions(self):
        records=[log(1,'root','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',sql('ud_prc_paymentGetInfo',paymentKey='K'))]
        for i in range(2,7):
            records.append(log(i,'req'+str(i),'DBPath.pishkhan24.application.ud_prc_paymentGetInfo',sql('ud_prc_paymentGetInfo',paymentKey='K')))
        self.ingest(records)
        j=self.db.service_journey(self.key('root'),max_requests=2)
        self.assertTrue(j['truncated'])
        self.assertIn('request_cap',j['truncation_reasons'])
        self.assertLessEqual(len(j['steps']),2)
        self.assertIsNone(j['customer_action_count'])

    def test_session_only_tech_calls_cannot_invent_a_behavior(self):
        self.ingest([log(1,'lookup','Core.v1/PaymentInfo Line:5','POST (G00000 | successful)'),
                     log(2,'other','Core.v1/TopUpPurchaseInfo Line:5','POST (G00000 | successful)')])
        a=self.db.service_journey(self.key('lookup'))
        self.assertEqual(len(a['steps']),1)
        self.assertEqual(a['behavior_kind'],'technical_steps_only')
        self.assertEqual(a['anchor_kind'],'technical_execution_not_independent_customer_action')
        b=self.db.service_journey(self.key('other'))
        self.assertEqual(b['role'],'support_status_lookup')

if __name__=='__main__':
    unittest.main()
