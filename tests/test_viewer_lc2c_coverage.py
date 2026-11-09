"""LC2C synthetic privacy-safe population coverage and suboperation regressions."""
from __future__ import annotations
import gzip
import json
from pathlib import Path
import tempfile
import unittest
from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.behavior_coverage import safe_api_root
from tests.test_viewer_r6_service_journey import log


class LC2CCoverageTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        keys=self.root/'keys.json';generate_keys(keys)
        self.db=ViewerDB(sqlite_path=self.root/'viewer.db',keys_path=keys)
        self.addCleanup(self.db.close)
        self.db.init()

    def load(self, rows):
        target=self.root/'test.json.gz'
        with gzip.open(target,'wt',encoding='utf-8') as out:
            json.dump(dict(window_start='2026-10-24T04:15:00Z',
                           window_end='2026-10-24T04:20:00Z',
                           count=len(rows),logs=rows),out)
        self.db.ingest([target]);self.db.rebuild();self.db.rebuild_payment_contract()

    def session(self):
        return self.db.one('SELECT session_key FROM viewer_requests WHERE session_key IS NOT NULL LIMIT 1')['session_key']

    def test_full_population_not_limited_to_one_session_page(self):
        self.load([log(i,'q'+str(i),'Services.v1/TrafficFinesCarNoDetails Line:302',
                       'POST (G00000 | successful)',second=i) for i in range(1,9)])
        p=self.db.session_behavior(self.session(),scan_limit=2)
        audit=self.db.behavior_coverage(top=1)
        self.assertEqual(2,p['candidate_requests_scanned'])
        self.assertEqual(8,audit['indexed_requests'])
        self.assertEqual(8,audit['counts']['service_facade_requests'])
        self.assertEqual(8,audit['counts']['semantic_service_execution'])
        self.assertEqual(8,audit['counts']['source_catalog_mapped_facade_requests'])
        self.assertIsNone(audit['manual_actions_confirmed'])
        self.assertTrue(audit['read_only'])

    def test_two_identical_targets_are_distinct_executions_in_audit(self):
        self.load([log(1,'q1','Services.v1/TrafficFinesCarNoDetails Line:302','POST (G00000 | successful)'),
                   log(2,'q2','Services.v1/TrafficFinesCarNoDetails Line:302','POST (G00000 | successful)')])
        self.assertEqual(2,self.db.behavior_coverage()['counts']['semantic_service_execution'])
        self.assertEqual(2,len(self.db.session_behavior(self.session())['observed_occurrences']))

    def test_callback_payment_info_not_manual_or_service(self):
        self.load([log(1,'callback','PaymentCallback.PaymentCallback Line:18','POST (G00000 | successful)',session='N/A'),
                   log(2,'info','Core.v1/PaymentInfo Line:30','POST (G00000 | successful)')])
        audit=self.db.behavior_coverage()
        self.assertEqual(2,audit['indexed_requests'])
        self.assertEqual(0,audit['counts'].get('root_semantic_execution_candidates',0))
        self.assertIsNone(audit['fully_reconstructed_behaviors'])

    def test_unmapped_facade_is_retained_for_review_without_authority(self):
        self.load([log(1,'unknown','Services.v99/UnknownServiceA Line:3','POST (G00000 | successful)')])
        audit=self.db.behavior_coverage()
        self.assertEqual(1,audit['counts']['source_catalog_unmapped_facade_requests'])
        self.assertEqual('Services.v99/UnknownServiceA',audit['unmapped_or_ambiguous_facades'][0]['api'])
        self.assertEqual(0,audit['counts'].get('semantic_service_execution',0))

    def test_multiple_client_roots_remain_ambiguous_not_two_actions(self):
        self.load([
            log(1,'one','Services.v1/TrafficFinesCarNoDetails Line:302','POST (G00000 | successful)'),
            log(2,'one','Services.v1/WaterBills Line:14','POST (G00000 | successful)'),
        ])
        result=self.db.session_behavior(self.session())
        self.assertEqual(0,result['observed_semantic_execution_count'])
        self.assertEqual(1,result['candidate_requests_scanned'])
        self.assertEqual(1,result['ambiguous_multi_root_count'])
        self.assertEqual(['Services.v1/TrafficFinesCarNoDetails','Services.v1/WaterBills'],
            result['ambiguous_multi_root_requests'][0]['observed_service_roots'])
        self.assertFalse(result['ambiguous_multi_root_requests'][0]['counted_as_behavior'])
        raw_journey=self.db.service_journey(result['ambiguous_multi_root_requests'][0]['request_key'])
        self.assertEqual('unresolved_ambiguous_http_root',raw_journey['status'])
        self.assertIsNone(result['confirmed_manual_action_count'])

    def test_suboperation_evidence_is_facet_without_count_increase(self):
        self.load([
            log(1,'one','Services.v1/WaterBills Line:14','POST (G00000 | successful)'),
            log(2,'one','ClientAyanCoTopUp.ProductReserve Line:10',
                'Output:[{"Parameters":{"PurchaseKey":"R"},"Status":{"Code":"G00000"}}]'),
        ])
        result=self.db.session_behavior(self.session())
        self.assertEqual(1,result['observed_semantic_execution_count'])
        item=result['observed_occurrences'][0]
        self.assertTrue(item['product_reservation_in_request'])
        self.assertEqual('service_execution',item['kind'])
        self.assertEqual(1,len(item['observed_secondary_operations']))
        self.assertEqual('ClientAyanCoTopUp.ProductReserve',item['observed_secondary_operations'][0]['api'])
        self.assertIsNone(result['confirmed_manual_action_count'])

    def test_product_reservation_inside_payment_is_not_double_counted(self):
        self.load([
            log(1,'wallet','ClientAyanCoTopUp.ProductReserve Line:10',
                'Output:[{"Parameters":{"PurchaseKey":"R"},"Status":{"Code":"G00000"}}]'),
            log(2,'wallet','Core.v1/WalletPayment Line:5','POST (G00000 | successful)'),
        ])
        session=self.db.session_behavior(self.session())
        self.assertEqual(1,session['observed_semantic_execution_count'])
        self.assertEqual('product_reservation_execution',session['observed_occurrences'][0]['kind'])
        self.assertEqual(1,self.db.behavior_coverage()['indexed_requests'])
        self.assertEqual(0,self.db.behavior_coverage()['counts'].get('root_semantic_execution_candidates',0))
        # A root-only audit explicitly does not infer provider facets.
        self.assertIn('payment_and_provider_facets_not_in_root_aggregation',
                      self.db.behavior_coverage()['notes'])

    def test_rebuild_is_idempotent_for_coverage_and_execution_identity(self):
        self.load([log(1,'q','Services.v1/TrafficFinesCarNoDetails Line:302','POST (G00000 | successful)')])
        a=self.db.behavior_coverage()
        occurrence=self.db.session_behavior(self.session())['observed_occurrences'][0]['occurrence_key']
        self.db.rebuild()
        b=self.db.behavior_coverage()
        self.assertEqual(a,b)
        self.assertEqual(occurrence,self.db.session_behavior(self.session())['observed_occurrences'][0]['occurrence_key'])

    def test_missing_session_does_not_invent_ownership(self):
        self.load([log(1,'no_session','Services.v1/TrafficFinesCarNoDetails Line:302',
                       'POST (G00000 | successful)',session='N/A')])
        a=self.db.behavior_coverage()
        self.assertEqual(1,a['counts']['semantic_service_execution'])
        self.assertEqual(0,a['counts'].get('session_scoped_root_semantic_candidates',0))
        self.assertEqual(0,a['rooted_with_session_request_keys'])

    def test_owner_automatic_service_facades_not_false_unknowns(self):
        self.load([
            log(1,'invoice','Services.v1/InvoiceRegister Line:17','POST (G00000 | successful)'),
            log(2,'read','Services.v1/GetUserData Line:17','POST (G00000 | successful)'),
            log(3,'query','Services.v1/TrafficFinesCarNoDetails Line:302','POST (G00000 | successful)'),
        ])
        a=self.db.behavior_coverage()
        self.assertEqual(2,a['counts']['owner_confirmed_automatic_facade_requests'])
        self.assertEqual(1,a['counts']['nonautomatic_facade_candidate_requests'])
        self.assertEqual(1,a['counts']['source_catalog_mapped_facade_requests'])
        self.assertEqual([],a['unmapped_or_ambiguous_facades'])
        self.assertEqual(1.0,a['facade_mapping_fraction'])

    def test_defensive_api_labels_and_bounds(self):
        self.assertEqual('[unrecognized_or_missing_root]',safe_api_root('Services.v1/Evil<script>'))
        self.assertEqual('[unrecognized_or_missing_root]',safe_api_root('Session=secret'))
        self.assertEqual('Core.v1/UserWalletCharge',safe_api_root('Core.v1/UserWalletCharge Line:114'))
        with self.assertRaises(ValueError):self.db.behavior_coverage(top=0)
        with self.assertRaises(ValueError):self.db.behavior_coverage(top=201)


if __name__=='__main__':unittest.main()
