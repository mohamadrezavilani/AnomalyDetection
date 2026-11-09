"""LC2B: observed behavior coverage with negative human-attribution guards.

All inputs synthetic. No customer data, financial claims or Core mutations.
"""
from __future__ import annotations
import gzip
import json
from pathlib import Path
import tempfile
import unittest

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.session_behavior import VERSION
from p24_foundation.service_journey import semantic_execution_kind
from tests.test_viewer_r6_service_journey import log


class LC2BSemanticCoverageTests(unittest.TestCase):
    def setUp(self):
        holder=tempfile.TemporaryDirectory(); self.addCleanup(holder.cleanup)
        self.root=Path(holder.name)
        key_file=self.root/'keys.json'; generate_keys(key_file)
        self.db=ViewerDB(sqlite_path=self.root/'viewer.db',keys_path=key_file)
        self.addCleanup(self.db.close); self.db.init()

    def load(self, records):
        path=self.root/'sample.json.gz'
        with gzip.open(path,'wt',encoding='utf8') as f:
            json.dump({'window_start':'2026-10-24T04:15:00Z',
                       'window_end':'2026-10-24T04:20:00Z',
                       'count':len(records),'logs':records},f)
        self.db.ingest([path]);self.db.rebuild();self.db.rebuild_payment_contract()

    def session(self):
        return self.db.one('SELECT session_key FROM viewer_requests WHERE session_key IS NOT NULL LIMIT 1')['session_key']

    def key(self, name):
        return self.db.lookup_request(name)['request_key']

    def test_user_management_is_observed_not_claimed_manual(self):
        self.load([
            log(1,'profile','Core.v1/UserProfileUpdatePersonalInfo Line:10','POST (G00000 | successful)',second=2),
            log(2,'bookmark','Core.v1/UserServiceQueryBookmark Line:3','POST (G00000 | successful)',second=3),
            log(3,'read','Core.v1/UserProfile Line:4','POST (G00000 | successful)',second=4),
        ])
        data=self.db.session_behavior(self.session())
        self.assertEqual(VERSION,data['version'])
        self.assertEqual(2,data['observed_user_management_execution_count'])
        self.assertEqual(0,data['observed_service_execution_count'])
        self.assertEqual(2,data['observed_semantic_execution_count'])
        self.assertIsNone(data['confirmed_manual_action_count'])
        for o in data['observed_occurrences']:
            self.assertEqual('user_management_execution',o['kind'])
            self.assertFalse(o['customer_initiation_confirmed'])
            graph=self.db.service_journey(o['anchor_request_key'])
            self.assertIn(o['occurrence_key'],[s['occurrence_key'] for s in graph['resolved_occurrences']])
            self.assertEqual(graph['behavior_kind'],'user_management_execution_candidate')

    def test_same_basket_context_remains_two_user_management_executions(self):
        self.load([
            log(1,'add1','Core.v1/UserBasketAddBills Line:1','POST (G00000 | successful)',second=2),
            log(2,'add2','Core.v1/UserBasketAddBills Line:1','POST (G00000 | successful)',second=3),
        ])
        data=self.db.session_behavior(self.session())
        self.assertEqual(2,data['observed_user_management_execution_count'])
        self.assertEqual(2,len({x['occurrence_key'] for x in data['observed_occurrences']}))

    def test_source_registry_facade_explicitly_marked_proposal(self):
        self.load([log(1,'facility','Services.v1/Facility Line:15','POST (G00000 | successful)',second=2)])
        data=self.db.session_behavior(self.session())
        self.assertEqual(1,data['observed_service_execution_count'])
        o=data['observed_occurrences'][0]
        self.assertEqual('service_execution',o['kind'])
        self.assertEqual('bank_facilities',o['family_id'])
        self.assertEqual('source_proposal_only_runtime_unverified',o['root_classification_authority'])
        self.assertFalse(o['customer_initiation_confirmed'])
        graph=self.db.service_journey(self.key('facility'))
        self.assertEqual(o['occurrence_key'],graph['canonical_occurrence_key'])

    def test_unknown_facade_is_not_silently_promoted(self):
        self.load([log(1,'new','Services.v9/InventedAction Line:5','POST (G00000 | successful)')])
        data=self.db.session_behavior(self.session())
        self.assertEqual(0,data['observed_semantic_execution_count'])
        self.assertEqual(1,data['unclassified_facade_candidates'])
        self.assertIsNone(data['confirmed_manual_action_count'])

    def test_source_owner_automatic_not_promoted_from_catalog(self):
        self.load([log(1,'auto','Services.v1/InvoiceRegister Line:5','POST (G00000 | successful)')])
        data=self.db.session_behavior(self.session())
        self.assertEqual([],data['observed_occurrences'])
        self.assertEqual('support',self.db.service_journey(self.key('auto'))['role'])

    def test_multiple_technical_facets_do_not_duplicate_service_execution(self):
        self.load([
            log(1,'mixed','ClientAyanCoTopUp.ProductReserve Line:6',
                'Output:[{"Parameters":{"PurchaseKey":"KEY-A"},"Status":{"Code":"G00000"}}]',second=2),
            log(2,'mixed','Services.v1/TrafficFinesCarNoDetails Line:302',
                'POST (G00000 | successful)',second=2),
        ])
        data=self.db.session_behavior(self.session())
        self.assertEqual(1,data['observed_semantic_execution_count'])
        self.assertEqual(1,data['observed_service_execution_count'])
        self.assertEqual(0,data['observed_product_reservation_execution_count'])
        anchor=data['observed_occurrences'][0]
        self.assertTrue(anchor['product_reservation_in_request'])
        graph=self.db.service_journey(self.key('mixed'))
        self.assertEqual(1,len(graph['resolved_occurrences']))
        self.assertEqual(anchor['occurrence_key'],graph['canonical_occurrence_key'])
        self.assertIsNone(data['confirmed_manual_action_count'])

    def test_payment_reservation_remains_one_semantic_anchor(self):
        self.load([
            log(1,'pay','ClientAyanCoTopUp.ProductReserve Line:10',
                'Output:[{"Parameters":{"PurchaseKey":"PURCHASE-A"}}]',second=2),
            log(2,'pay','Core.v1/WalletPayment Line:5','POST (G00000 | successful)',second=2),
        ])
        data=self.db.session_behavior(self.session())
        self.assertEqual(1,data['observed_product_reservation_execution_count'])
        self.assertEqual(1,data['observed_semantic_execution_count'])
        self.assertEqual(self.db.service_journey(self.key('pay'))['canonical_occurrence_key'],
                         data['observed_occurrences'][0]['occurrence_key'])

    def test_payment_callback_not_promoted_even_with_shared_session(self):
        self.load([
            log(1,'callback','PaymentCallback.PaymentCallback Line:5','POST (G00000 | successful)',second=2),
            log(2,'status','Core.v1/PaymentInfo Line:5','POST (G00000 | successful)',second=3),
        ])
        self.assertEqual([],self.db.session_behavior(self.session())['observed_occurrences'])

    def test_pagination_preserves_mixed_kind_occurrences(self):
        self.load([
            log(1,'one','Core.v1/UserServiceQueryBookmark Line:5','POST (G00000 | successful)',second=1),
            log(2,'two','Services.v1/TrafficFinesCarNoDetails Line:10','POST (G00000 | successful)',second=2),
            log(3,'three','Core.v1/UserWalletCharge Line:10','POST (G00000 | successful)',second=3),
            log(4,'four','Services.v1/Facility Line:10','POST (G00000 | successful)',second=4),
        ])
        seen=[];cursor={}
        for _ in range(5):
            data=self.db.session_behavior(self.session(),scan_limit=2,**cursor)
            seen.extend(x['occurrence_key'] for x in data['observed_occurrences'])
            if not data['next_cursor']:break
            cursor=data['next_cursor']
        self.assertEqual(4,len(seen))
        self.assertEqual(4,len(set(seen)))

    def test_bad_operator_override_cannot_promote_system_or_status_roots(self):
        self.load([
            log(1,'callback','PaymentCallback.PaymentCallback Line:5','POST (G00000 | successful)',second=1),
            log(2,'status','Core.v1/PaymentInfo Line:5','POST (G00000 | successful)',second=2),
        ])
        for name in ('callback','status'):
            self.db.sql("UPDATE viewer_actions SET category='user_management' WHERE action_key=?",
                        (self.key(name),))
        self.assertEqual([],self.db.session_behavior(self.session())['observed_occurrences'])
        for name in ('callback','status'):
            graph=self.db.service_journey(self.key(name))
            self.assertEqual([],graph['resolved_occurrences'])

    def test_semantic_helper_never_manually_infers_ownership(self):
        self.assertIsNone(semantic_execution_kind('PaymentCallback.PaymentCallback Line:3','system'))
        self.assertIsNone(semantic_execution_kind('Services.v1/InvoiceRegister Line:3','business'))
        self.assertEqual('user_management_execution', semantic_execution_kind(
                         'Core.v1/LoginByOTP Line:17','user_management'))

if __name__=='__main__': unittest.main()
