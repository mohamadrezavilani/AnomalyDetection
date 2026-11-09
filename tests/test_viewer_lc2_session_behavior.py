"""LC2A acceptance-focused Session execution reconstruction tests (synthetic)."""
from __future__ import annotations
import gzip
import json
import unittest
from tests.test_viewer_r6_service_journey import log, sql
import tempfile
from pathlib import Path
from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.session_behavior import VERSION


class LC2SessionBehaviorTests(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup)
        self.root=Path(folder.name)
        key_file=self.root/'keys.json';generate_keys(key_file)
        self.db=ViewerDB(sqlite_path=self.root/'viewer.db',keys_path=key_file)
        self.addCleanup(self.db.close)
        self.db.init()

    def load(self, rows):
        path=self.root/'test.json.gz'
        with gzip.open(path,'wt',encoding='utf8') as output:
            json.dump({'window_start':'2026-10-24T04:15:00Z',
                       'window_end':'2026-10-24T04:20:00Z',
                       'count':len(rows),'logs':rows},output)
        self.db.ingest([path]);self.db.rebuild();self.db.rebuild_payment_contract()

    def key(self, raw):
        return self.db.lookup_request(raw)['request_key']
    def session(self, raw='a'*32):
        return self.db.one('SELECT session_key FROM viewer_requests WHERE session_key IS NOT NULL LIMIT 1')['session_key']

    def test_separate_repeated_inquiries_are_stable_and_not_merged_by_invoice(self):
        rows=[
            log(1,'q1','DBPath.application.ud_prc_invoiceInfo',sql('ud_prc_invoiceInfo',invoiceUniqueID='INV'),second=1),
            log(2,'q1','Services.v1/TrafficFinesCarNoDetails Line:302','POST (G00000 | successful)',second=1),
            log(3,'q2','DBPath.application.ud_prc_invoiceInfo',sql('ud_prc_invoiceInfo',invoiceUniqueID='INV'),second=4),
            log(4,'q2','Services.v1/TrafficFinesCarNoDetails Line:302','POST (G00000 | successful)',second=4),
        ]
        self.load(rows)
        session=self.session()
        projection=self.db.session_behavior(session)
        self.assertEqual(projection['version'],VERSION)
        self.assertFalse(projection['has_more'])
        self.assertTrue(projection['candidate_scan_complete'])
        self.assertFalse(projection['all_session_history_loaded'])
        self.assertEqual(2,len(projection['observed_occurrences']))
        keys={i['occurrence_key'] for i in projection['observed_occurrences']}
        self.assertEqual(2,len(keys))
        self.assertEqual({i['anchor_request_key'] for i in projection['observed_occurrences']}, {self.key('q1'),self.key('q2')})
        for occurrence in projection['observed_occurrences']:
            graph=self.db.service_journey(occurrence['anchor_request_key'])
            self.assertIn(occurrence['occurrence_key'],{x['occurrence_key'] for x in graph['resolved_occurrences']})
            self.assertEqual(occurrence['kind'],'service_execution')
        self.assertIsNone(projection['confirmed_manual_action_count'])

    def test_callback_and_status_read_never_become_manual_service_behaviors(self):
        self.load([
            log(1,'redirect','DBPath.application.ud_prc_paymentGetInfo',sql('ud_prc_paymentGetInfo',paymentKey='K'),second=1),
            log(2,'redirect','PaymentRedirect.PaymentRedirect Line:5','POST (G00000 | successful)',second=1),
            log(3,'callback','PaymentCallback.PaymentCallback Line:5','POST (G00000 | successful)',second=2,session='N/A'),
            log(4,'info','Core.v1/PaymentInfo Line:5','POST (G00000 | successful)',second=3),
            log(5,'wallet','Core.v1/WalletPayment Line:5','POST (G00000 | successful)',second=4),
        ])
        projection=self.db.session_behavior(self.session())
        self.assertEqual([],projection['observed_occurrences'])
        self.assertEqual(0,projection['observed_semantic_execution_count'])
        self.assertIsNone(projection['confirmed_manual_action_count'])

    def test_funding_independent_of_callback_ownership_by_time(self):
        self.load([
            log(1,'fund1','Core.v1/UserWalletCharge Line:5','POST (G00000 | successful)',second=1),
            log(2,'fund2','Core.v1/UserWalletCharge Line:5','POST (G00000 | successful)',second=2),
            log(3,'callback','PaymentCallback.PaymentCallback Line:5','POST (G00000 | successful)',second=3,session='N/A'),
        ])
        result=self.db.session_behavior(self.session())
        self.assertEqual(2,len(result['observed_occurrences']))
        self.assertTrue(all(x['kind']=='wallet_funding_execution' for x in result['observed_occurrences']))
        self.assertNotEqual(result['observed_occurrences'][0]['occurrence_key'],result['observed_occurrences'][1]['occurrence_key'])
        self.assertTrue(all(not x['customer_initiation_confirmed'] for x in result['observed_occurrences']))

    def test_product_reservation_in_payment_request_counts_once(self):
        self.load([
            log(1,'wallet','ClientAyanCoTopUp.ProductReserve Line:10','Output:[{"Parameters":{"PurchaseKey":"RES"},"Status":{"Code":"G00000"}}]',second=1),
            log(2,'wallet','Core.v1/WalletPayment Line:5','POST (G00000 | successful)',second=1),
        ])
        result=self.db.session_behavior(self.session())
        self.assertEqual(1,len(result['observed_occurrences']))
        self.assertEqual('product_reservation_execution',result['observed_occurrences'][0]['kind'])
        graph=self.db.service_journey(self.key('wallet'))
        self.assertEqual(graph['canonical_occurrence_key'],result['observed_occurrences'][0]['occurrence_key'])
        self.assertEqual('NOT_INFERRED',result['observed_occurrences'][0]['financial_finality'])

    def test_cursor_pagination_and_identical_timestamps(self):
        self.load([log(i, 'q'+str(i),'Services.v1/TrafficFinesCarNoDetails Line:302',
                       'POST (G00000 | successful)',second=1) for i in range(1,6)])
        session=self.session()
        seen=[]
        after={}
        for _ in range(6):
            p=self.db.session_behavior(session,scan_limit=2,**after)
            seen.extend(x['occurrence_key'] for x in p['observed_occurrences'])
            if not p['next_cursor']:break
            after=p['next_cursor']
        self.assertEqual(5,len(seen))
        self.assertEqual(5,len(set(seen)))
        self.assertFalse(p['has_more'])
        self.assertEqual(sorted(seen), sorted({x['occurrence_key'] for x in self.db.session_behavior(session)['observed_occurrences']}))

    def test_session_scope_not_ip_and_no_join_across_sessions(self):
        a=log(1,'q1','Services.v1/TrafficFinesCarNoDetails Line:302','POST (G00000 | successful)',session='a'*32,second=1)
        b=log(2,'q2','Services.v1/TrafficFinesCarNoDetails Line:302','POST (G00000 | successful)',session='a'*32,second=2)
        b['IP']='192.0.2.48'
        c=log(3,'q3','Services.v1/TrafficFinesCarNoDetails Line:302','POST (G00000 | successful)',session='b'*32,second=3)
        self.load([a,b,c])
        a_key=self.db.one('SELECT session_key FROM viewer_requests WHERE request_key=?',(self.key('q1'),))['session_key']
        b_key=self.db.one('SELECT session_key FROM viewer_requests WHERE request_key=?',(self.key('q3'),))['session_key']
        self.assertEqual(2,len(self.db.session_behavior(a_key)['observed_occurrences']))
        self.assertEqual(1,len(self.db.session_behavior(b_key)['observed_occurrences']))

    def test_range_does_not_prove_absence_and_bad_cursors_are_rejected(self):
        self.load([log(1,'q','Services.v1/TrafficFinesCarNoDetails Line:302','POST (G00000 | successful)',second=2)])
        key=self.session()
        self.assertFalse(self.db.session_behavior(key,to_ns=1)['all_session_history_loaded'])
        for kw in ({'scan_limit':501},{'after_ns':1},{'after_key':'a'*64},
                   {'from_ns':20,'to_ns':10},{'after_ns':1,'after_key':'bad'}):
            with self.subTest(kw=kw),self.assertRaises(ValueError):
                self.db.session_behavior(key,**kw)
        with self.assertRaises(ValueError):self.db.session_behavior('secret')

    def test_two_five_minute_windows_stitch_one_request_execution(self):
        first=log(1,'shared','Services.v1/TrafficFinesCarNoDetails Line:302',
                  'POST (G00000 | successful)',second=1)
        first['@timestamp']='2026-10-24T04:19:59Z'
        late=log(2,'shared','DBPath.application.ud_prc_invoiceInfo',
                  sql('ud_prc_invoiceInfo',invoiceUniqueID='INV'),second=1)
        late['@timestamp']='2026-10-24T04:20:01Z'
        def ingest_file(name,rows,start,end):
            path=self.root/name
            with gzip.open(path,'wt',encoding='utf8') as stream:
                json.dump({'window_start':start,'window_end':end,
                           'count':len(rows),'logs':rows},stream)
            self.db.ingest([path]);self.db.rebuild();self.db.rebuild_payment_contract()
        ingest_file('first.json.gz',[first],
                    '2026-10-24T04:15:00Z','2026-10-24T04:20:00Z')
        key=self.session()
        first_view=self.db.session_behavior(key)
        self.assertEqual(1,len(first_view['observed_occurrences']))
        stable=first_view['observed_occurrences'][0]['occurrence_key']
        ingest_file('second.json.gz',[late],
                    '2026-10-24T04:20:00Z','2026-10-24T04:25:00Z')
        later=self.db.session_behavior(key)
        self.assertEqual([stable],[x['occurrence_key'] for x in later['observed_occurrences']])
        self.assertEqual(1,self.db.one('SELECT COUNT(*) AS n FROM viewer_requests')['n'])
        self.assertEqual(2,self.db.one('SELECT COUNT(*) AS n FROM viewer_events')['n'])
        # Re-importing an already verified file must not multiply a behavior.
        self.db.ingest([self.root/'second.json.gz'])
        self.db.rebuild();self.db.rebuild_payment_contract()
        self.assertEqual([stable],[x['occurrence_key'] for x in
                                   self.db.session_behavior(key)['observed_occurrences']])

    def test_owner_confirmed_automatic_roots_never_counted_even_if_misclassified(self):
        self.load([
            log(1,'auto','Services.v1/InvoiceRegister Line:17',
                'POST (G00000 | successful)',second=1),
            log(2,'q','Services.v1/TrafficFinesCarNoDetails Line:302',
                'POST (G00000 | successful)',second=2),
        ])
        # An operator's bad category edit cannot override owner-confirmed
        # automatic behavior semantics for countable service occurrences.
        self.db.sql("UPDATE viewer_actions SET category='business' WHERE action_key=?",(self.key('auto'),))
        result=self.db.session_behavior(self.session())
        self.assertEqual(1,len(result['observed_occurrences']))
        self.assertEqual(self.key('q'),result['observed_occurrences'][0]['anchor_request_key'])

    def test_session_result_is_read_only_and_can_be_recomputed(self):
        self.load([log(1,'q','Services.v1/TrafficFinesCarNoDetails Line:302','POST (G00000 | successful)')])
        key=self.session()
        before=self.db.one('SELECT COUNT(*) AS n FROM viewer_requests')['n']
        result1=self.db.session_behavior(key)
        result2=self.db.session_behavior(key)
        self.assertEqual(result1,result2)
        self.assertTrue(result1['read_only'])
        self.assertEqual(before,self.db.one('SELECT COUNT(*) AS n FROM viewer_requests')['n'])

if __name__=='__main__':unittest.main()
