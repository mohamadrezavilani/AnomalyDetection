"""R6.2 S1A fixture regressions; no operator secrets or real customer data."""
from __future__ import annotations
import gzip
import json
import tempfile
import unittest
from pathlib import Path

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.viewer_contract import observed_states, extract_identifiers


def sql(name, **kwargs):
    return f'(Command Text: {name})(Code: 1)(Result: Ok)(SQL Parameters: '+ ' '.join('@'+k+'='+str(v) for k,v in kwargs.items())+')'


def log(number, request_id, path, message, *, session='a'*32, second=1):
    return {'_source_id': 'synthetic-index:'+str(number),
            '@timestamp':f'2026-10-24T04:15:{second:02d}Z',
            'RequestID':request_id,'Session':session,'IP':'192.0.2.40',
            'CallPath':path,'message':message,'level':'Info'}


class R6JourneyTest(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        key=self.root/'keys.json';generate_keys(key)
        self.db=ViewerDB(sqlite_path=self.root/'viewer.db',keys_path=key)
        self.addCleanup(self.db.close)
        self.db.init()

    def load(self, rows):
        gz=self.root/'fixture.json.gz'
        with gzip.open(gz,'wt',encoding='utf8') as handle:
            json.dump({'window_start':'2026-10-24T04:15:00Z',
                       'window_end':'2026-10-24T04:20:00Z',
                       'count':len(rows),'logs':rows},handle)
        self.db.ingest([gz]);self.db.rebuild();self.db.rebuild_payment_contract()

    def key(self, r):
        return self.db.lookup_request(r)['request_key']

    def test_invoice_fee_journey_non_bill_and_no_session_only_join(self):
        rows=[
          log(1,'registration','DBPath.pishkhan24.application.ud_prc_invoiceRegister',
              sql('ud_prc_invoiceRegister',invoiceUniqueID='INV-A'),second=2),
          log(2,'registration','Services.v1/InvoiceRegister Line:27','POST (G00000 | successful)',second=2),
          log(3,'payment','DBPath.pishkhan24.application.ud_prc_paymentRequestForInvoiceSettlement',
              sql('ud_prc_paymentRequestForInvoiceSettlement',invoiceUniqueID='INV-A',paymentKey='PAY-A'),second=4),
          log(4,'payment','Core.v1/InvoicePayment Line:23','POST (G00000 | successful)',second=4),
          log(5,'execution','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',
              sql('ud_prc_paymentGetInfo',paymentKey='PAY-A'),second=5),
          log(6,'execution','Core.v1/WalletPayment Line:23','POST (G00000 | successful)',second=5),
          log(7,'inquiry','DBPath.pishkhan24.application.ud_prc_inquiryInvoiceResult2',
              sql('ud_prc_inquiryInvoiceResult2',invoiceUniqueID='INV-A'),second=6),
          log(8,'inquiry','Services.v1/TrafficFinesCarNoDetails Line:302',
              'POST (G00000 | successful)',second=6),
          log(9,'unrelated','Services.v1/TrafficFinesCarNoDetails Line:302',
              'POST (G00000 | successful)',second=6),
        ]
        self.load(rows)
        anchor=self.key('inquiry');result=self.db.service_journey(anchor)
        linked={x['request_key'] for x in result['steps']}
        self.assertEqual(linked,{self.key(x) for x in ('registration','payment','execution','inquiry')})
        self.assertNotIn(self.key('unrelated'), linked)
        self.assertEqual(result['role'],'service_operation')
        self.assertEqual(result['financial_confirmation'],'unverified')
        self.assertEqual(result['occurrence_key'],anchor)
        self.assertEqual(self.db.request(anchor)['service_journey']['occurrence_key'],anchor)
        self.assertEqual(self.db.action(anchor)['service_journey']['occurrence_key'],anchor)
        listing=self.db.requests_page(10,0,request_id='inquiry')
        self.assertEqual(listing['items'][0]['service_journey']['occurrence_key'],anchor)

    def test_invoice_reused_does_not_merge_distinct_occurrences(self):
        rows=[
          log(1,'q1','DBPath.pishkhan24.application.ud_prc_invoiceInfo',sql('ud_prc_invoiceInfo',invoiceUniqueID='INV-A')),
          log(2,'q1','Services.v1/BankIbanInfo Line:8','POST (G00000 | successful)'),
          log(3,'q2','DBPath.pishkhan24.application.ud_prc_invoiceInfo',sql('ud_prc_invoiceInfo',invoiceUniqueID='INV-A')),
          log(4,'q2','Services.v1/BankIbanInfo Line:8','POST (G00000 | successful)'),
        ]
        self.load(rows)
        a=self.db.service_journey(self.key('q1'))
        b=self.db.service_journey(self.key('q2'))
        self.assertNotEqual(a['occurrence_key'],b['occurrence_key'])
        self.assertIn(self.key('q2'), {s['request_key'] for s in a['steps']})
        self.assertTrue(all(e['certainty']=='same_reference_not_same_execution' for e in a['edges']))

    def test_basket_and_same_session_do_not_join_different_attempts(self):
        rows=[
          log(1,'basket1','DBPath.pishkhan24.application.ud_prc_basketAddItems',sql('ud_prc_basketAddItems',basketID='42')),
          log(2,'basket1','Core.v1/UserBasketAddBills Line:1','POST (G00000 | successful)'),
          log(3,'basket2','DBPath.pishkhan24.application.ud_prc_basketAddItems',sql('ud_prc_basketAddItems',basketID='42')),
          log(4,'basket2','Core.v1/UserBasketAddBills Line:1','POST (G00000 | successful)'),
        ]
        self.load(rows)
        j=self.db.service_journey(self.key('basket1'))
        self.assertEqual(len(j['steps']),1)
        self.assertEqual(j['status'],'no_explicit_peer_observed')

    def test_shared_payment_object_not_one_execution(self):
        rows=[
          log(1,'payment1','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',sql('ud_prc_paymentGetInfo',paymentKey='same-K')),
          log(2,'payment1','Core.v1/WalletPayment Line:1','POST (G00000 | successful)'),
          log(3,'payment2','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',sql('ud_prc_paymentGetInfo',paymentKey='same-K')),
          log(4,'payment2','Core.v1/WalletPayment Line:1','POST (G00000 | successful)'),
        ]
        self.load(rows)
        a=self.db.service_journey(self.key('payment1'))
        self.assertEqual(len(a['steps']),2)
        self.assertNotEqual(a['occurrence_key'],self.db.service_journey(self.key('payment2'))['occurrence_key'])
        self.assertTrue(all(e['financial_confirmation']=='unverified' for e in a['edges']))

    def test_source_safe_provider_adapters(self):
        get_purchase=dict(CallPath='ClientAyanCoPaymentGateway.GetPurchaseInfo Line:5',
            message='Output:[{"Parameters":{"StatusName":"Paid"},"Status":{"Code":"G00000"}}]')
        self.assertIn(('provider_purchase_financial_observation','Paid','provider.Parameters.StatusName'), observed_states(get_purchase))
        self.assertFalse(any('confirmed' in x[0] for x in observed_states(get_purchase)))
        car_tax=dict(CallPath='DBPath.application.ud_prc_invoiceRegister',
            message=sql('ud_prc_invoiceRegister',externalPurchaseKey='R',invoiceUniqueID='I'))
        ids=extract_identifiers(car_tax)
        self.assertIn('external_reference_unresolved',[v[1] for v in ids])
        self.assertNotIn('product_reservation',[v[1] for v in ids])
        product=dict(CallPath='ClientAyanCoTopUp.ProductReserve Line:8',
            message='Input:[{}]\nOutput:[{"Parameters":{"PurchaseKey":"R"}}]')
        self.assertIn('product_reservation',[v[1] for v in extract_identifiers(product)])

    def test_wallet_funding_does_not_join_create_by_time_or_session(self):
        rows=[
          log(1,'fund','Core.v1/UserWalletCharge Line:16','POST (G00000 | successful)',second=2),
          log(2,'gateway','DBPath.pishkhan24.application.ud_prc_paymentServiceReportToken',
              sql('ud_prc_paymentServiceReportToken',paymentKey='F-K',token='provider-T'),second=2),
          log(3,'gateway','PaymentRedirect.PaymentRedirect Line:5','POST (G00000 | successful)',second=2),
          log(4,'lookup','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',
              sql('ud_prc_paymentGetInfo',paymentKey='F-K'),session='N/A',second=3),
        ]
        self.load(rows)
        creation=self.db.service_journey(self.key('fund'))
        self.assertEqual(len(creation['steps']),1)
        self.assertEqual(creation['role'],'wallet_funding')
        gateway=self.db.service_journey(self.key('gateway'))
        self.assertIn(self.key('lookup'),{r['request_key'] for r in gateway['steps']})
        self.assertNotIn(self.key('fund'),{r['request_key'] for r in gateway['steps']})
        self.assertEqual(creation['catalog']['family_id'],'wallet')

    def test_topup_separate_invoice_funds_and_fulfillment_report(self):
        rows=[
          log(1,'reserve','DBPath.pishkhan24.application.ud_prc_invoiceRegister',
              sql('ud_prc_invoiceRegister',invoiceUniqueID='TOPUP-I',externalPurchaseKey='RES-R')),
          log(2,'reserve','Services.v1/InvoiceRegister Line:1','POST (G00000 | successful)'),
          log(3,'invoicepayment','DBPath.pishkhan24.application.ud_prc_paymentRequestForInvoiceSettlement',
              sql('ud_prc_paymentRequestForInvoiceSettlement',invoiceUniqueID='TOPUP-I',paymentKey='K')),
          log(4,'invoicepayment','Core.v1/InvoicePayment Line:1','POST (G00000 | successful)'),
          log(5,'wallet','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',
              sql('ud_prc_paymentGetInfo',paymentKey='K')),
          log(6,'wallet','Core.v1/WalletPayment Line:1','POST (G00000 | successful)'),
          log(7,'notify','DBPath.pishkhan24.application.ud_prc_webhooksInformPurchaseStatus',
              sql('ud_prc_webhooksInformPurchaseStatus',invoiceUniqueID='TOPUP-I',
                  externalPurchaseKey='RES-R',paymentKey='K',status='Finalized'),session='N/A'),
          log(8,'notify','Webhook.v1/InformPurchaseStatus Line:1','POST (G00000 | successful)',session='N/A'),
        ]
        self.load(rows)
        j=self.db.service_journey(self.key('reserve'))
        self.assertEqual({x['request_key'] for x in j['steps']},
            {self.key(k) for k in ('reserve','invoicepayment','wallet','notify')})
        self.assertEqual(j['financial_confirmation'],'unverified')
        observed=self.db.payment_contract_card(self.key('notify'))
        self.assertIn('Finalized',[x['value'] for x in observed['observations']])
        self.assertFalse(any(x['kind']=='product_reservation' for x in observed['identifiers']))

    def test_family_catalog_is_proposal_not_availability_or_user_click(self):
        from p24_foundation.service_journey import source_family
        self.assertEqual(source_family('Services.v1/TrafficFinesCarNoDetails Line:302')['family_id'],'traffic_fines')
        self.assertEqual(source_family('Services.v1/BankIbanInfo')['family_id'],'bank_iban')
        self.assertEqual(source_family('Services.v1/TrafficFinesCarNoDetails')['authority'],
                         'source_proposal_only_runtime_unverified')
        self.assertEqual(source_family('Services.v1/NotExisting')['authority'],'unmapped')

    def test_conflicted_root_unresolved(self):
        self.load([log(1,'one','Core.v1/WalletPayment Line:1','POST (G00000 | successful)')])
        key=self.key('one')
        self.db.sql('UPDATE viewer_requests SET conflicted=1 WHERE request_key=?',(key,))
        j=self.db.service_journey(key)
        self.assertEqual(j['status'],'unresolved_conflicting_origin')
        self.assertEqual(j['steps'],[])

if __name__=='__main__':unittest.main()
