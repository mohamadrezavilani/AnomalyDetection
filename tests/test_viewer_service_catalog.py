"""Behavior Viewer editable service taxonomy: offline SQLite, no private data."""
from __future__ import annotations
import gzip
import json
import tempfile
import unittest
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB,initial_service_role

S='ABCD1234EFAB1234EFAB1234EFAB1234'
Q1='aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa'
Q2='bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb'
C1='cccccccc-cccc-4ccc-cccc-cccccccccccc'
P='dddddddd-dddd-4ddd-dddd-dddddddddddd'
W='eeeeeeee-eeee-4eee-eeee-eeeeeeeeeeee'
PAY='ABCDEF12345F12345ABCDEF908172345'

def row(i,t,rid,path,message='',session=S):
    return {'@timestamp':t,'RequestID':rid,'Session':session,'IP':'1.2.3.4',
            'CallPath':path,'message':message,'_source_id':'test-index:'+str(i)}

class ServiceCatalogTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        root=Path(tmp.name)
        keys=root/'secret.json';generate_keys(keys)
        self.db=ViewerDB(sqlite_path=root/'model.db',keys_path=keys)
        self.addCleanup(self.db.close);self.db.init()
        self.dump=root/'events.json.gz'
        events=[
         row(1,'2026-10-24T04:00:00Z',Q1,'Services.v1/ElectricBills Line:100', 'POST (G00000 | successful)'),
         row(2,'2026-10-24T04:00:01Z',Q1,'DBPath.a.ud_prc_inquiryInvoiceResult2',
             '(Command Text: ud_prc_inquiryInvoiceResult2)(Code: 1)(Result: Ok)(SQL Parameters: @queryIndex=0012345 @statusCode=G00000)'),
         row(3,'2026-10-24T06:00:00Z',Q2,'Services.v1/ElectricBills Line:100', 'POST (G00000 | successful)'),
         row(4,'2026-10-24T06:00:01Z',Q2,'DBPath.a.ud_prc_inquiryInvoiceResult2',
             '(Command Text: ud_prc_inquiryInvoiceResult2)(Code: 1)(Result: Ok)(SQL Parameters: @queryIndex=0012345 @statusCode=G00000)'),
         row(5,'2026-10-24T06:01:00Z',C1,'Services.v1/GetUserData Line:50', 'POST (G00000 | successful)'),
         row(6,'2026-10-24T06:01:01Z',P,'Core.v1/UncatalogedRoute Line:23', 'POST (G00000 | successful)'),
         row(7,'2026-10-24T06:02:00Z',W,'Core.v1/WalletPayment Line:18', 'POST (G00000 | successful)'),
         row(8,'2026-10-24T06:01:59Z',W,'DBPath.a.ud_prc_paymentExists',
             f'(Command Text: ud_prc_paymentExists)(Code: 1)(Result: Ok)(SQL Parameters: @paymentKey={PAY})'),
         row(9,'2026-10-24T06:02:00Z',W,'ClientAyanCoPaymentGateway.GetPaymentInfo Line:54',
             'Output:[{"Parameters":{"Bills":[{"BillID":"111","PaymentID":"222","Paid":false}]}}]'),
         row(10,'2026-10-24T06:04:00Z','ffffffff-ffff-4fff-ffff-ffffffffffff',
             'DBPath.a.ud_prc_webhooksInformBillPaymentStatus_v1',
             f'(Command Text: ud_prc_webhooksInformBillPaymentStatus_v1)(Code: 1)(Result: Ok)(SQL Parameters: @paymentKey={PAY} @billID=111 @paymentID=222 @description=پرداخت با موفقیت انجام شد)',session='N/A'),
         row(11,'2026-10-24T06:04:01Z','ffffffff-ffff-4fff-ffff-ffffffffffff',
             'Webhook.v1/InformBillsPaymentStatus Line:15', 'POST (G00000 | successful)',session='N/A'),
        ]
        with gzip.open(self.dump,'wt',encoding='utf8') as f:
            json.dump({'window_start':'2026-10-24T04:00:00Z','window_end':'2026-10-24T07:00:00Z',
                       'count':len(events),'logs':events},f,ensure_ascii=False)
        self.db.ingest([self.dump]);self.db.rebuild()

    def test_old_database_schema_is_migrated_non_destructively(self):
        before=self.db.metrics()
        self.db.sql('DROP TABLE viewer_service_roles')
        self.db.sql('DROP TABLE viewer_service_role_history')
        self.db.conn.commit()
        self.db.init()
        after=self.db.rebuild()
        self.assertEqual(after['events'],before['events'])
        self.assertEqual(after['requests'],before['requests'])
        self.assertGreater(self.db.service_roles(100)['total'],0)

    def test_unknown_is_default_and_known_owner_auto(self):
        rows=self.db.service_roles(100)['items'];by_path={v['service_path']:v for v in rows}
        self.assertEqual(by_path['Core.v1/UncatalogedRoute']['role'],'unknown')
        self.assertEqual(by_path['Services.v1/GetUserData']['role'],'support')
        self.assertEqual(by_path['Services.v1/GetUserData']['initiation'],'confirmed_automatic')
        self.assertEqual(by_path['Services.v1/ElectricBills']['role'],'business')
        self.assertEqual(by_path['Services.v1/ElectricBills']['source'],'inferred')
        self.assertEqual(by_path['Webhook.v1/InformBillsPaymentStatus']['role'],'system')

    def test_independent_same_target_two_hours_apart(self):
        sk=self.db.lookup_request(Q1)['session_key'];main=self.db.actions(sk,100,category='main')
        electric=[x for x in main['items'] if x['name']=='ElectricBills']
        self.assertEqual(len(electric),2)
        self.assertNotEqual(electric[0]['action_key'],electric[1]['action_key'])
        self.assertEqual(electric[0]['target_key'],electric[1]['target_key'])
        self.assertEqual(electric[0]['label'],'ElectricBills')
        self.assertEqual(self.db.actions(sk,100,category='unknown')['total'],1)
        self.assertEqual(self.db.actions(sk,100,category='support')['total'],1)

    def test_edit_immediately_persists_rebuild_and_preserves_requests(self):
        sk=self.db.lookup_request(Q1)['session_key']
        before=self.db.metrics().copy()
        self.db.update_service_role('Core.v1/UncatalogedRoute','user_management','confirmed_manual','reviewed')
        self.assertEqual(self.db.actions(sk,100,category='user_management')['total'],1)
        self.assertEqual(self.db.actions(sk,100,category='unknown')['total'],0)
        self.assertEqual(self.db.metrics()['requests'],before['requests'])
        self.db.rebuild()
        self.assertEqual(self.db.actions(sk,100,category='user_management')['total'],1)
        entry=next(x for x in self.db.service_roles(100)['items'] if x['service_path']=='Core.v1/UncatalogedRoute')
        self.assertEqual((entry['reviewed'],entry['source'],entry['initiation']), (1,'operator','confirmed_manual'))
        h=self.db.all('SELECT * FROM viewer_service_role_history WHERE service_path=?',('Core.v1/UncatalogedRoute',))
        self.assertEqual(len(h),1)
        self.assertEqual(h[0]['old_role'],'unknown')
        with self.assertRaises(ValueError):self.db.update_service_role('Missing.route','business','unknown')

    def test_payment_separate_from_inquiry_and_keyed_webhook(self):
        sk=self.db.lookup_request(Q1)['session_key']
        main=self.db.actions(sk,100,category='main')
        self.assertEqual(len([a for a in main['items'] if a['name']=='WalletPayment']),1)
        act=self.db.action(self.db.lookup_request(W)['request_key'])
        self.assertEqual(act['link_basis'],'platform_payment')
        # R5: a webhook is an item/object-scope report, not finality of this execution.
        self.assertEqual(act['current_outcome'],'success')
        self.assertEqual([h['status'] for h in act['outcome_history']],['paid_false','webhook_payment_success'])
        self.assertTrue(any(x['name']=='InformBillsPaymentStatus' for x in act['related']))
        self.assertEqual(self.db.actions(sk,100,category='system')['total'],0)  # webhook has no session

    def test_callback_is_not_another_user_action_but_can_update_bill_payment(self):
        payment='12345678-1234-4234-8234-123456789012'
        callback='12345678-1234-4234-8234-123456789013'
        webhook='12345678-1234-4234-8234-123456789014'
        key='F0123ABC9876ABCDEFFEE01234567890'
        events=[
           row(101,'2026-10-24T06:10:00Z',payment,'Core.v1/BillsPayment Line:18','POST (G00000 | successful)'),
           row(102,'2026-10-24T06:09:59Z',payment,'DBPath.a.ud_prc_paymentExists',
               f'(Command Text: ud_prc_paymentExists)(Code: 1)(Result: Ok)(SQL Parameters: @paymentKey={key})'),
           row(103,'2026-10-24T06:12:00Z',callback,'PaymentCallback.PaymentCallback Line:18',
               'POST (G00000 | successful)',session='N/A'),
           row(104,'2026-10-24T06:11:59Z',callback,'DBPath.a.ud_prc_paymentExists',
               f'(Command Text: ud_prc_paymentExists)(Code: 1)(Result: Ok)(SQL Parameters: @paymentKey={key})',session='N/A'),
           row(105,'2026-10-24T06:12:00Z',callback,'ClientAyanCoPaymentGateway.GetPaymentInfo Line:54',
               'Output:[{"Parameters":{"Bills":[{"BillID":"111","PaymentID":"222","Paid":true}]}}]',session='N/A'),
           row(106,'2026-10-24T06:13:00Z',webhook,'Webhook.v1/InformBillsPaymentStatus Line:15',
               'POST (G00000 | successful)',session='N/A'),
           row(107,'2026-10-24T06:13:00Z',webhook,'DBPath.a.ud_prc_webhooksInformBillPaymentStatus_v1',
               f'(Command Text: ud_prc_webhooksInformBillPaymentStatus_v1)(Code: 1)(Result: Ok)(SQL Parameters: @paymentKey={key} @billID=111 @paymentID=222 @description=پرداخت با موفقیت انجام شد)',session='N/A')]
        extra=self.dump.parent/'payment_cases.json.gz'
        with gzip.open(extra,'wt',encoding='utf8') as f:
            json.dump({'window_start':'2026-10-24T06:00:00Z','window_end':'2026-10-24T07:00:00Z',
                       'count':len(events),'logs':events},f,ensure_ascii=False)
        self.db.ingest([extra]);self.db.rebuild()
        bill=self.db.action(self.db.lookup_request(payment)['request_key'])
        # Missing item identity on the initiating payment forbids financial certification.
        self.assertEqual(bill['current_outcome'],'success')
        self.assertEqual([x['status'] for x in bill['outcome_history']],['paid_true'])
        sk=self.db.lookup_request(payment)['session_key']
        main=self.db.actions(sk,100,category='main')['items']
        self.assertEqual(len([a for a in main if a['name']=='BillsPayment']),1)
        self.assertFalse(any(a['name']=='PaymentCallback' for a in main))
        self.assertTrue(any(a['name']=='PaymentCallback' for a in bill['related']))

    def test_jinja_catalog_and_main_filter_template_compile(self):
        path=Path(__file__).resolve().parents[1]/'review_ui/templates'
        env=Environment(loader=FileSystemLoader(str(path)),autoescape=select_autoescape(['html']))
        from p24_foundation.viewer_display_time import tehran_time
        env.filters['tehran_time']=tehran_time
        env.globals['url_for']=lambda endpoint,**kw: '/'+endpoint
        item=next(x for x in self.db.service_roles(100)['items'] if x['service_path']=='Services.v1/ElectricBills')
        item['csrf']='0'*64
        html=env.get_template('viewer_services.html').render(result={'items':[item],'total':1},search='',role='',page=1,limit=25,version='test')
        self.assertIn('Services.v1/ElectricBills',html)
        self.assertIn('مدیریت سرویس‌ها',html)
        self.assertIn('name="csrf"',html)
        self.assertIn('value="business" selected',html)
        session=env.get_template('viewer_session.html').render(result={'items':[],'total':0},
            key='0'*64,info={'requests':5,'from_fa':'start','to_fa':'end'},page=1,limit=25,
            category='main',service='',outcome='',version='test')
        self.assertIn('value="business" selected',session)
        self.assertNotIn('value="main"',session)

if __name__=='__main__':unittest.main()
