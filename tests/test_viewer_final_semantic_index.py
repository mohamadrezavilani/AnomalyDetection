"""Evaluator A/B release guards for semantic homepage and anchor lifecycle.

Synthetic, isolated SQLite, no private PostgreSQL/Elasticsearch touched.
"""
from __future__ import annotations
import gzip
import json
import tempfile
import unittest
from pathlib import Path
from tests.test_viewer_r6_service_journey import log
from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB


class FinalSemanticIndexTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        root=Path(tmp.name)
        keys=root/'keys.json';generate_keys(keys)
        self.db=ViewerDB(sqlite_path=root/'s.db',keys_path=keys)
        self.addCleanup(self.db.close)
        self.db.init()
        self.root=root

    def load(self,rows,fileno=1):
        path=self.root/f'window{fileno}.json.gz'
        with gzip.open(path,'wt',encoding='utf8') as f:
            json.dump(dict(window_start='2026-10-24T04:15:00Z',
              window_end='2026-10-24T04:20:00Z',count=len(rows),logs=rows),f)
        imp=self.db.ingest([path]);self.assertEqual(imp[0]['status'],'IMPORTED')
        self.db.rebuild();self.db.rebuild_payment_contract()

    def key(self,raw):return self.db.lookup_request(raw)['request_key']

    def test_home_latest_semantic_not_later_wallet_or_callback(self):
        rows=[
            log(1,'ask1','Services.v2/GasBills Line:5','POST (G00000 | successful)',second=1,session='a'*32),
            log(2,'old','Services.v1/WaterBills Line:7','POST (G00000 | successful)',second=2,session='b'*32),
            log(3,'ask2','Services.v1/TrafficFinesCarNoDetails Line:7','POST (G00000 | successful)',second=3,session='a'*32),
            log(4,'payment','Core.v1/WalletPayment Line:3','POST (G00000 | successful)',second=5,session='b'*32),
            log(5,'callback','PaymentCallback.PaymentCallback Line:8','POST (G00000 | successful)',second=6,session='b'*32),
        ]
        self.load(rows)
        summary=self.db.build_semantic_index()
        self.assertEqual(summary['changed_anchors'],3)
        home=self.db.semantic_sessions(10)
        self.assertEqual(home['total'],2)
        self.assertEqual(home['items'][0]['request_key'],self.key('ask2'))
        self.assertEqual(home['items'][1]['request_key'],self.key('old'))
        self.assertEqual(home['items'][0]['occurrence_key'],
                         self.db.service_journey(self.key('ask2'))['canonical_occurrence_key'])

    def test_product_reservation_late_root_replaces_not_adds(self):
        self.load([
            log(1,'mixed','ClientAyanCoTopUp.ProductReserve Line:8',
                'Output:[{"Parameters":{"PurchaseKey":"T"},"Status":{"Code":"G00000"}}]',second=1)
        ])
        self.db.build_semantic_index()
        rid=self.key('mixed')
        before=self.db.one('SELECT * FROM viewer_semantic_occurrences WHERE request_key=?',(rid,))
        self.assertEqual(before['kind'],'product_reservation_execution')
        self.db.sql('''UPDATE viewer_requests SET root_call=?,root_ns=started_ns
                       WHERE request_key=?''',('Services.v1/TopUpProductPurchase Line:5',rid))
        self.db.sql("UPDATE viewer_actions SET category='business' WHERE action_key=?",(rid,))
        self.db.conn.commit()
        after_result=self.db.reconcile_semantic_requests([rid])
        after=self.db.one('SELECT * FROM viewer_semantic_occurrences WHERE request_key=?',(rid,))
        self.assertEqual(after_result['added'],0)
        self.assertEqual(after_result['changed'],1)
        self.assertEqual(before['anchor_key'],after['anchor_key'])
        self.assertNotEqual(before['occurrence_key'],after['occurrence_key'])
        self.assertEqual(after['kind'],'service_execution')
        self.assertEqual(self.db.one("SELECT COUNT(*) AS n FROM viewer_semantic_occurrences WHERE state='active'")['n'],1)
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_semantic_transitions')['n'],2)

    def test_withdrawal_and_stale_cursor_rejected(self):
        self.load([log(1,'a','Services.v2/GasBills Line:1','POST (G00000 | successful)',second=1),
                   log(2,'b','Services.v2/GasBills Line:1','POST (G00000 | successful)',second=2)])
        self.db.build_semantic_index()
        session=self.db.one('SELECT session_key FROM viewer_requests LIMIT 1')['session_key']
        page=self.db.indexed_session_behavior(session,scan_limit=1)
        self.assertTrue(page['next_cursor'])
        rid=self.key('b')
        self.db.sql("UPDATE viewer_actions SET category='support' WHERE action_key=?",(rid,))
        self.db.conn.commit()
        info=self.db.reconcile_semantic_requests([rid]);self.assertEqual(info['withdrawn'],1)
        self.assertEqual(self.db.one("SELECT COUNT(*) AS n FROM viewer_semantic_occurrences WHERE state='active'")['n'],1)
        cursor=page['next_cursor']
        with self.assertRaisesRegex(ValueError,'stale_generation'):
            self.db.indexed_session_behavior(session,scan_limit=1,after_ns=cursor['after_ns'],
                  after_key=cursor['after_key'],generation=cursor['generation'])

    def test_operator_role_change_updates_anchor_atomically(self):
        self.load([log(1,'a','Services.v2/GasBills Line:3',
                       'POST (G00000 | successful)',second=1)])
        self.db.build_semantic_index()
        rid=self.key('a')
        previous=self.db.one('SELECT * FROM viewer_semantic_occurrences WHERE request_key=?',(rid,))
        self.assertEqual(previous['state'],'active')
        self.db.update_service_role('Services.v2/GasBills','support','unknown','technical review')
        updated=self.db.one('SELECT * FROM viewer_semantic_occurrences WHERE request_key=?',(rid,))
        self.assertEqual(updated['state'],'withdrawn')
        self.assertEqual(self.db.semantic_checkpoint()['state'],'ready')
        self.assertEqual(self.db.semantic_sessions(10)['total'],0)

    def test_old_batch_rebuild_marks_materialized_view_stale(self):
        self.load([log(1,'a','Services.v2/GasBills Line:3',
                       'POST (G00000 | successful)',second=1)])
        self.db.build_semantic_index()
        self.db.rebuild()
        self.assertEqual(self.db.semantic_checkpoint()['state'],'stale')
        self.assertFalse(self.db.semantic_sessions(10)['index_ready'])
        self.db.build_semantic_index()
        self.assertTrue(self.db.semantic_sessions(10)['index_ready'])

    def test_latest_above_500_and_independent_same_target(self):
        # Direct isolated read-model fixture: 551 independent request anchors.
        session='a'*64
        self.db.init_semantic_index()
        rows=[]
        for n in range(551):
            rid=f'{n:064x}'
            rows.append((rid,'ba1:'+rid,session,n,'service_execution','bo1:'+rid,
                        'Services.v2/GasBills Line:5','G00000','gas_bill','قبض گاز',
                        'business','unknown','active',1,'2026-10-24T00:00:00Z'))
        self.db.conn.executemany('INSERT INTO viewer_semantic_occurrences VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',rows)
        self.db.sql("INSERT INTO viewer_semantic_checkpoint VALUES(1,1,'2026-10-24T00:00:00Z',551,'ready')")
        self.db._refresh_semantic_session_heads()
        self.db.conn.commit()
        # Avoid irrelevant raw ID lookup for this manufactured performance fixture.
        self.db.raw_session_id=lambda key: None
        home=self.db.semantic_sessions(10)
        self.assertEqual(home['items'][0]['request_key'],f'{550:064x}')
        first=self.db.indexed_session_behavior(session,scan_limit=500)
        self.assertEqual(len(first['observed_occurrences']),500)
        self.assertTrue(first['has_more'])
        cursor=first['next_cursor']
        second=self.db.indexed_session_behavior(session,scan_limit=500,
                    after_ns=cursor['after_ns'],after_key=cursor['after_key'],
                    generation=cursor['generation'])
        self.assertEqual(len(second['observed_occurrences']),51)
        self.assertFalse(second['has_more'])
        all_keys={row['anchor_key'] for row in first['observed_occurrences']+second['observed_occurrences']}
        self.assertEqual(len(all_keys),551)

if __name__=='__main__':unittest.main()
