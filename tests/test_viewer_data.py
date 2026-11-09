"""Offline viewer contracts: private synthetic rows; no PostgreSQL needed."""
from __future__ import annotations
import gzip,json,tempfile,unittest
from pathlib import Path
from p24_foundation.viewer_data import ViewerDB,utc_ns
from p24_foundation.privacy import generate_keys

SESSION='F4D2A39FE77E450DAB67FA56A2E8B99D'
A='aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa'
B='bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb'
C='cccccccc-cccc-4ccc-cccc-cccccccccccc'
PAY='1234ABCD9090ABCDEF00000000001111'


def row(i,t,rid,call,session=SESSION,message='',ip='1.2.3.4',oid=None):
    return {'@timestamp':t,'RequestID':rid,'Session':session,'IP':ip,'CallPath':call,'level':'Info',
            'message':message,'_source_id':'logs-test-20261024:'+str(oid or i)}


def dump(path,start,end,items):
    with gzip.open(path,'wt',encoding='utf8') as f:
        json.dump({'window_start':start,'window_end':end,'count':len(items),'logs':items},f,ensure_ascii=False)


class ViewerReadModelTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name);self.path=root
        keys=root/'keys.json';generate_keys(keys)
        self.db=ViewerDB(sqlite_path=root/'test.db',keys_path=keys)
        self.addCleanup(self.db.close);self.db.init()
        self.a=root/'first.json.gz';self.b=root/'second.json.gz'
        self.sqlpay=f'(Command Text: ud_prc_paymentExists)(Code: 1)(Result: Ok)(SQL Parameters: @paymentKey={PAY})'
        self.webhook=f'(Command Text: ud_prc_webhooksInformBillPaymentStatus_v1)(Code: 1)(Result: Ok)(SQL Parameters: @paymentKey={PAY} @billID=111 @paymentID=222 @amount=333 @description=پرداخت با موفقیت انجام شد)'
        dump(self.a,'2026-10-24T04:15:00Z','2026-10-24T04:20:00Z',[
            row(1,'2026-10-24T04:19:59.9999999Z',A,'DBPath.pishkhan24.application.ud_prc_paymentExists',message=self.sqlpay),
            row(2,'2026-10-24T04:19:59.9999998Z',A,'ClientAyanCoPaymentGateway.GetPaymentInfo Line:54',message='Output:[{"Parameters":{"Bills":[{"BillID":"111","PaymentID":"222","Paid":false}]}}]')])
        dump(self.b,'2026-10-24T04:20:00Z','2026-10-24T04:25:00Z',[
            row(3,'2026-10-24T04:20:01.0000001Z',A,'Core.v1/WalletPayment Line:1084',message='POST http://example (G00000 | successful)'),
            row(4,'2026-10-24T04:20:05.0000000Z',B,'DBPath.pishkhan24.application.ud_prc_webhooksInformBillPaymentStatus_v1',session='N/A',ip='N/A',message=self.webhook),
            row(5,'2026-10-24T04:20:05.1000000Z',B,'Webhook.v1/InformBillsPaymentStatus Line:15',session='N/A',ip='N/A',message='POST http://example (G00000 | successful)')])

    def test_nanosecond_order_7_digits(self):
        self.assertEqual(utc_ns('2026-10-24T04:19:59.9999999Z')-utc_ns('2026-10-24T04:19:59.9999998Z'),100)

    def test_boundary_and_webhook(self):
        self.db.ingest([self.a,self.b]);metrics=self.db.rebuild()
        self.assertEqual(metrics['origins'],5)
        self.assertEqual(metrics['requests'],2)
        self.assertEqual(metrics['session_ids'],1)
        main=self.db.lookup_request(A);self.assertEqual(main['event_count'],3)
        action=self.db.action(main['request_key'])
        self.assertEqual(action['current_outcome'],'success')
        self.assertEqual([x['status'] for x in action['outcome_history']],['paid_false','webhook_payment_success'])
        self.assertEqual(len(action['related']),2)
        self.assertEqual(self.db.evidence(main['request_key'])['total'],3)
        self.assertEqual(self.db.lookup_request(B)['identity_state'],'missing')
        self.assertNotIn('1.2.3.4',str(self.db.evidence(main['request_key'])))
        self.assertNotIn(PAY,str(action))

    def test_duplicate_and_reverse_order(self):
        self.db.ingest([self.b,self.a]);self.db.rebuild()
        first=self.db.metrics()
        result=self.db.ingest([self.a]);self.db.rebuild()
        self.assertEqual(result[0]['status'],'ALREADY_IMPORTED')
        self.assertEqual(first,self.db.metrics())

    def test_same_message_different_origins_retained(self):
        third=self.path/'third.json.gz'
        duplicate_content=row(55,'2026-10-24T04:22:00Z',C,'Core.v1/ConfigBasic Line:42',message='message')
        other=dict(duplicate_content);other['_source_id']='logs-test-20261024:new-unique'
        dump(third,'2026-10-24T04:20:00Z','2026-10-24T04:25:00Z',[duplicate_content,other])
        self.db.ingest([third]);m=self.db.rebuild()
        self.assertEqual(m['events'],2)
        self.assertEqual(m['requests'],1)

    def test_conflicting_same_origin_not_last_writer(self):
        changed=row(50,'2026-10-24T04:20:02Z',A,'Core.v1/WalletPayment Line:1084',message='POST (GD2016 | Fail)',oid=3)
        third=self.path/'conflicting.json.gz';dump(third,'2026-10-24T04:20:00Z','2026-10-24T04:25:00Z',[changed])
        self.db.ingest([self.a,self.b,third]);self.db.rebuild()
        main=self.db.lookup_request(A)
        self.assertEqual(main['identity_state'],'conflicting')
        self.assertEqual(main['conflicted'],1)

if __name__=='__main__':unittest.main()
