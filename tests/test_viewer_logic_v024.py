"""v0.2.4 financial integrity + legacy backfill contracts (synthetic only)."""
import gzip
import json
import tempfile
import unittest
from pathlib import Path
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.privacy import generate_keys

P = '11111111-1111-4111-8111-111111111111'
H = '22222222-2222-4222-8222-222222222222'
S = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
KEY = '12345678-aaaa-4aaa-8aaa-123456789012'


def event(n, rid, path, message, session=S):
    return {'_source_id': 'synthetic-v024:'+str(n), '@timestamp': '2026-10-24T04:15:%02dZ' % n,
            'RequestID': rid, 'Session': session, 'IP': '192.0.2.50',
            'CallPath': path, 'message': message, 'level': 'Info'}


def proc(name, params):
    return '(Command Text: '+name+')(Code: 1)(Result: Ok)(SQL Parameters: '+params+')'


def provider(bill='111111111111', payment='22222222', amount=1000, paid=False):
    return 'Output:'+json.dumps([{'Parameters':{'Bills':[{'BillID':bill,'PaymentID':payment,
                                            'Amount':amount,'Paid':paid}]}}])


class FinancialSafetyV024(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.base=Path(temp.name);self.keys=self.base/'keys';generate_keys(self.keys)
        self.db=ViewerDB(sqlite_path=self.base/'model.sqlite',keys_path=self.keys)
        self.addCleanup(self.db.close);self.db.init()

    def ingest(self, rows, verification=None):
        path=self.base/'evidence.json.gz'
        with gzip.open(path,'wt',encoding='utf-8') as stream:
            doc={'window_start':'2026-10-24T04:15:00Z','window_end':'2026-10-24T04:20:00Z',
                 'count':len(rows),'logs':rows}
            if verification is not None:doc['verification']=verification
            json.dump(doc,stream,ensure_ascii=False)
        return self.db.ingest([path])

    def make_payment(self, amount=1000, include_identity=True):
        return [event(1,P,'DBPath.app.ud_prc_paymentExists',proc('ud_prc_paymentExists','@paymentKey='+KEY)),
                event(2,P,'ClientAyanCoPaymentGateway.GetPaymentInfo Line:54',
                      provider(amount=amount) if include_identity else 'Output:[{"Paid":false}]'),
                event(3,P,'Core.v1/WalletPayment Line:7','POST test (G00000 | successful)')]

    def webhook(self, amount=1000, bill='111111111111'):
        return [event(4,H,'DBPath.app.ud_prc_webhooksInformBillPaymentStatus_v1',
                       proc('ud_prc_webhooksInformBillPaymentStatus_v1',
                            f'@paymentKey={KEY} @billID={bill} @paymentID=22222222 @amount={amount} @description=پرداخت با موفقیت انجام شد'),session='N/A'),
                event(5,H,'Webhook.v1/InformBillsPaymentStatus Line:10','POST (G00000 | successful)',session='N/A')]

    def outcome(self):
        return self.db.action(self.db.lookup_request(P)['request_key'])

    def test_mismatched_amount_is_not_financially_confirmed(self):
        self.ingest(self.make_payment()+self.webhook(amount=2000))
        self.db.rebuild()
        self.assertNotIn(self.outcome()['current_outcome'],('confirmed_success','confirmed_after_webhook'))

    def test_unscoped_initial_request_cannot_claim_callback_bill(self):
        self.ingest(self.make_payment(include_identity=False)+self.webhook())
        self.db.rebuild()
        self.assertEqual(self.outcome()['current_outcome'],'success')
        self.assertFalse(any(x['status']=='webhook_payment_success' for x in self.outcome()['outcome_history']))

    def test_upgrading_session_assertions_from_stored_raw(self):
        rows=[event(1,P,'DBPath.app.ud_prc_userSessionHasAccess',
                    proc('ud_prc_userSessionHasAccess','@session='+S+' @action=v1/WalletPayment')),
              event(2,P,'Core.v1/WalletPayment Line:12','POST (G00000 | successful)')]
        self.ingest(rows);self.db.rebuild()
        initial=self.db.lookup_request(P)['request_key']
        self.db.sql("DELETE FROM viewer_links WHERE link_domain='access_session'")
        self.db.conn.commit()
        result=self.db.backfill_identity_assertions()
        self.assertEqual(result['assertions_written'],1)
        self.db.rebuild()
        self.assertEqual(self.db.request(initial)['identity_state'],'assigned')
        self.assertEqual(self.db.backfill_identity_assertions()['assertions_written'],0)

    def test_unresolved_conflicting_request_is_in_default_list(self):
        first=event(1,P,'Core.v1/WalletPayment Line:1','POST (G00000 | success)')
        other=dict(first,message='POST (GD2016 | failed)')
        self.ingest([first])
        second=self.base/'second.json.gz'
        with gzip.open(second,'wt',encoding='utf-8') as f:
            json.dump({'window_start':'2026-10-24T04:15:00Z',
                       'window_end':'2026-10-24T04:20:00Z','count':1,'logs':[other]},f)
        self.db.ingest([second]);self.db.rebuild()
        self.assertEqual(self.db.requests_page(30)['total'],1)
        request=self.db.lookup_request(P)
        self.assertTrue(request['conflicted'])
        self.assertEqual(self.db.evidence(request['request_key'])['total'],2)

    def test_snapshot_assertion_is_not_source_finality(self):
        metadata={'counts_match':True,'query_snapshot_complete':True,
                  'reached_empty_page':True,'source_finality':'not_established'}
        self.ingest([event(1,P,'Core.v1/WalletPayment Line:1','POST (G00000 | success)')],metadata)
        state=self.db.one('SELECT source_claim FROM viewer_files')
        self.assertEqual(state['source_claim'],'verified_snapshot_export')
        self.assertNotIn('source_finality',state['source_claim'])

if __name__=='__main__':unittest.main()
