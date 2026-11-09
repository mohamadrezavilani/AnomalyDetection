"""Offline regression for exact inquiry -> basket -> payment lineage.

Fixtures are wholly synthetic, no customer data or financial credentials.
"""
import gzip
import json
import tempfile
import unittest
from pathlib import Path

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB

SESSION='8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F'
OLD_ITEM='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
NEW_ITEM='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
EXTRA_ITEM='cccccccccccccccccccccccccccccccc'


def record(i,minute,request_id,call,message):
    return dict(_source_id='logs-synthetic-20261024:'+str(i),
         **{'@timestamp':f'2026-10-24T04:{minute:02d}:00Z'},
         Session=SESSION,RequestID=request_id,CallPath=call,message=message,
         IP='192.0.2.1',level='Info')


def cache_add(uid):
    content=json.dumps([{'UniqueID':uid}],separators=(',',':'))
    payload=json.dumps([{'Parameters':{'CacheContent':content}}],separators=(',',':'))
    return 'https://cachecore.example/api/Cache/Add (G00000 | successful)\nInput:'+payload


def cache_get(*items):
    content=json.dumps([{'UniqueID':x} for x in items],separators=(',',':'))
    payload=json.dumps([{'Parameters':{'CacheContent':content}}],separators=(',',':'))
    return 'https://cachecore.example/api/Cache/Get (G00000 | successful)\nOutput:'+payload


class InquiryPaymentJourneyTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        key=root/'keys.json';generate_keys(key)
        self.db=ViewerDB(sqlite_path=root/'viewer.db',keys_path=key)
        self.addCleanup(self.db.close);self.db.init()
        self.gz=root/'synthetic.json.gz'

    def prepare(self,conflict=False):
        rows=[
            record(1,1,'old','CacheCoreApi.HandleRequest Line:56',cache_add(OLD_ITEM)),
            record(2,1,'old','Services.v1/CellPhoneBills Line:1991','POST (G00000 | successful)'),
            record(3,2,'new','CacheCoreApi.HandleRequest Line:56',cache_add(NEW_ITEM)),
            record(4,2,'new','Services.v1/CellPhoneBills Line:1991','POST (G00000 | successful)'),
            record(5,3,'basket','DBPath.pishkhan24.application.ud_prc_billsBelongs',
                        '(Command Text: ud_prc_billsBelongs)(SQL Parameters: @bills='+NEW_ITEM+')'),
            record(6,3,'basket','Core.v1/UserBasketAddBills Line:42','POST (G00000 | successful)'),
            record(7,4,'payment','CacheCoreApi.HandleRequest Line:56',cache_get(NEW_ITEM,EXTRA_ITEM)),
            record(8,4,'payment','DBPath.pishkhan24.application.ud_prc_walletPaymentReportRequest',
                        '(Command Text: ud_prc_walletPaymentReportRequest)(SQL Parameters: @paymentKey=payment-synthetic-001)'),
            record(9,4,'payment','Core.v1/UserBasketPayment Line:4','POST (G00000 | successful)'),
        ]
        if conflict:
            alternate=record(3,2,'new','CacheCoreApi.HandleRequest Line:56',cache_add(EXTRA_ITEM))
            rows.append(alternate)
        with gzip.open(self.gz,'wt',encoding='utf-8') as f:
            json.dump({'window_start':'2026-10-24T04:00:00Z','window_end':'2026-10-24T04:05:00Z',
                       'count':len(rows),'logs':rows},f)
        self.db.ingest([self.gz]);self.db.rebuild()

    def test_second_inquiry_links_to_basket_and_wallet_first_does_not(self):
        self.prepare()
        old=self.db.inquiry_payment_journey(self.db.lookup_request('old')['request_key'])
        new=self.db.inquiry_payment_journey(self.db.lookup_request('new')['request_key'])
        self.assertEqual(old['status'],'no_downstream_step_observed')
        self.assertEqual(len(old['payment_attempts']),0)
        self.assertEqual(new['status'],'payment_stage_reference_observed')
        self.assertEqual(len(new['basket_additions']),1)
        self.assertEqual(len(new['payment_attempts']),1)
        self.assertEqual(new['payment_attempts'][0]['method'],'unknown')
        self.assertEqual(new['payment_attempts'][0]['provider_rail'],'unknown')
        self.assertFalse(new['payment_attempts'][0]['financial_confirmed'])
        self.assertEqual(new['payment_attempts'][0]['linked_items'],1)

    def test_origin_conflict_does_not_create_payment_association(self):
        self.prepare(conflict=True)
        new=self.db.inquiry_payment_journey(self.db.lookup_request('new')['request_key'])
        self.assertEqual(new['status'],'unresolved')
        self.assertEqual(new['payment_attempts'],[])

    def test_action_request_and_target_filter_return_consistent_journey(self):
        self.prepare()
        key=self.db.lookup_request('new')['request_key']
        self.assertEqual(self.db.request(key)['inquiry_journey']['status'],'payment_stage_reference_observed')
        self.assertEqual(self.db.action(key)['inquiry_journey']['status'],'payment_stage_reference_observed')


if __name__=='__main__':unittest.main()
