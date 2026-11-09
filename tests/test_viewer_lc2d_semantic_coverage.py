"""LC2D: catalog/API coverage must never inflate observed customer behaviors."""
from __future__ import annotations
import unittest
import tempfile
import gzip
import json
from pathlib import Path
from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.service_journey import (
    _root_role, semantic_execution_kind, source_family,
    TOPUP_CATALOG_LOOKUP_ROOT_PATHS,
)
from tests.test_viewer_r6_service_journey import log


class LC2DTechnicalClassificationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        keys = self.root/'keys.json'
        generate_keys(keys)
        self.db = ViewerDB(sqlite_path=self.root/'viewer.db',keys_path=keys)
        self.addCleanup(self.db.close)
        self.db.init()

    def load(self, rows):
        target = self.root/'test.json.gz'
        with gzip.open(target,'wt',encoding='utf-8') as out:
            json.dump(dict(window_start='2026-10-24T04:15:00Z',
                           window_end='2026-10-24T04:20:00Z',
                           count=len(rows),logs=rows),out)
        self.db.ingest([target]); self.db.rebuild(); self.db.rebuild_payment_contract()

    def session(self):
        return self.db.one('SELECT session_key FROM viewer_requests WHERE session_key IS NOT NULL LIMIT 1')['session_key']
    def test_catalog_family_is_context_and_never_purchase_anchor(self):
        for route in sorted(TOPUP_CATALOG_LOOKUP_ROOT_PATHS):
            with self.subTest(route=route):
                self.assertEqual('topup', source_family(route)['family_id'])
                self.assertEqual('support_catalog_lookup',_root_role(route+' Line:3','business'))
                self.assertIsNone(semantic_execution_kind(route,'business'))
                self.assertIsNone(semantic_execution_kind(route,'user_management'))
                self.assertIsNone(semantic_execution_kind(route,'unresolved',
                                                          product_reservation_observed=True))

    def test_order_poll_is_status_lookup_even_with_role_override_and_reservation(self):
        route='Services.v1/TopUpPurchaseInfo'
        self.assertEqual('topup',source_family(route)['family_id'])
        self.assertEqual('support_status_lookup',_root_role(route,'business'))
        self.assertIsNone(semantic_execution_kind(route,'business',product_reservation_observed=True))

    def test_catalog_and_status_are_mapped_without_becoming_behavior(self):
        routes=sorted(TOPUP_CATALOG_LOOKUP_ROOT_PATHS)+['Services.v1/TopUpPurchaseInfo']
        self.load([log(i,'c'+str(i),root+' Line:17','POST (G00000 | successful)',second=i)
                   for i,root in enumerate(routes,1)])
        audit=self.db.behavior_coverage(top=40)
        self.assertEqual('p24-behavior-coverage-LC2E',audit['version'])
        self.assertEqual(5,audit['counts']['service_facade_requests'])
        self.assertEqual(5,audit['counts']['source_catalog_mapped_facade_requests'])
        self.assertEqual(0,audit['counts'].get('source_catalog_unmapped_facade_requests',0))
        self.assertEqual(5,audit['counts']['facade_without_semantic_anchor'])
        self.assertEqual(5,audit['counts']['known_technical_facade_requests'])
        self.assertEqual(0,audit['counts'].get('root_semantic_execution_candidates',0))
        self.assertEqual([],audit['unmapped_or_ambiguous_facades'])
        self.assertEqual(1.0,audit['facade_mapping_fraction'])
        self.assertEqual(0,len(self.db.session_behavior(self.session())['observed_occurrences']))
        self.assertEqual(5,sum(x['request_executions'] for x in audit['mapped_technical_facade_roots']))

    def test_unknown_service_maintains_review_queue_and_separate_counts(self):
        self.load([
            log(1,'unknown','Services.v42/UnlistedCustomerService Line:17','POST (G00000 | successful)'),
            log(2,'known','Services.v1/TopUpProductsCharge Line:17','POST (G00000 | successful)'),
            log(3,'status','Services.v1/TopUpPurchaseInfo Line:17','POST (G00000 | successful)'),
        ])
        a=self.db.behavior_coverage(top=40)
        self.assertEqual(1,a['counts']['source_catalog_unmapped_facade_requests'])
        self.assertEqual('Services.v42/UnlistedCustomerService',a['unmapped_or_ambiguous_facades'][0]['api'])
        self.assertEqual(2,a['counts']['known_technical_facade_requests'])
        self.assertEqual(1,a['counts']['unresolved_nonsemantic_facade_requests'])

    def test_payments_and_valid_service_remain_separate(self):
        self.load([
            log(1,'real','Services.v1/TrafficFinesCarNoDetails Line:17','POST (G00000 | successful)'),
            log(2,'catalog','Services.v1/TopUpOperatorsInternetPackage Line:17','POST (G00000 | successful)'),
            log(3,'payment','Core.v1/WalletPayment Line:17','POST (G00000 | successful)'),
        ])
        a=self.db.behavior_coverage(top=30)
        self.assertEqual(1,a['counts']['semantic_service_execution'])
        self.assertEqual(1,a['counts']['known_technical_facade_requests'])
        self.assertEqual(1,len(self.db.session_behavior(self.session())['observed_occurrences']))

    def test_technical_coverage_does_not_claim_automatic_user_initiation(self):
        self.load([log(1,'lookup','Services.v1/TopUpProductsInternetPackage Line:17',
                       'POST (G00000 | successful)')])
        a=self.db.behavior_coverage()
        self.assertEqual(0,a['counts'].get('owner_confirmed_automatic_facade_requests',0))
        self.assertEqual(1,a['counts']['known_technical_facade_requests'])
        self.assertIsNone(a['manual_actions_confirmed'])
        self.assertIsNone(a['fully_reconstructed_behaviors'])
        self.assertIn('catalog_mapping_does_not_prove_semantic_behavior_recognition',a['notes'])

    def test_unknown_role_rankings_have_safe_labels_and_exact_omission_totals(self):
        self.load([log(i,'r'+str(i),name+' Line:17','POST (G00000 | successful)',second=i)
                   for i,name in enumerate((
                     'Services.v42/FutureUnknownA','Services.v42/FutureUnknownB',
                     'Services.v42/FutureUnknownB','Services.v1/TopUpProductsCharge'),1)])
        a=self.db.behavior_coverage(top=1)
        self.assertEqual(a['counts'].get('unknown_viewer_role_requests',0),
            sum(x['request_executions'] for x in a['unknown_viewer_role_roots'])+
            a['unknown_role_roots_omitted'])
        self.assertEqual(a['counts'].get('unknown_role_without_semantic_anchor_requests',0),
            sum(x['request_executions'] for x in a['unknown_role_without_semantic_anchor_roots'])+
            a['unknown_role_without_semantic_anchor_omitted'])


if __name__=='__main__': unittest.main()
