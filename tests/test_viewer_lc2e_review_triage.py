"""LC2E checks: review queues partition unknowns, not customers."""
from __future__ import annotations
import unittest
import tempfile
import gzip
import json
from pathlib import Path
from p24_foundation.coverage_triage import unanchored_review_queue, REVIEW_TYPES
from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from tests.test_viewer_r6_service_journey import log


class ReviewQueueTests(unittest.TestCase):
    def test_technical_payment_is_not_human_inference(self):
        self.assertEqual('known_payment_or_system_step',
            unanchored_review_queue('PaymentRedirect.PaymentRedirect'))
        self.assertEqual('known_technical_support_step',
            unanchored_review_queue('Services.v1/TopUpPurchaseInfo'))

    def test_content_download_and_account_are_separate_unverified_queues(self):
        cases={
            'Files.Download':'file_delivery_api_unverified',
            'Public.v1/Weather':'public_information_api_unverified',
            'Core.v1/UserWidgetsSetDefault':'account_or_app_api_unverified',
            'Core.v1/UserTransactions':'account_or_app_api_unverified',
            'Core.v1/CnpgPayment':'known_payment_or_system_step',
            'Ewano.v1/EwanoPayment':'known_payment_or_system_step',
            'Services.v42/FutureService':'service_auxiliary_api_unverified',
            '[unrecognized_or_missing_root]':'root_missing_or_unrecognized',
        }
        for name,expected in cases.items():
            with self.subTest(name=name):
                self.assertEqual(expected,unanchored_review_queue(name))
                self.assertIn(expected,REVIEW_TYPES)

    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        root=Path(temp.name)
        keys=root/'keys.json';generate_keys(keys)
        self.db=ViewerDB(sqlite_path=root/'db.sqlite',keys_path=keys)
        self.addCleanup(self.db.close);self.db.init()
        self.root=root

    def load(self,rows):
        path=self.root/'synthetic.json.gz'
        with gzip.open(path,'wt',encoding='utf-8') as out:
            json.dump({'window_start':'2026-10-24T04:15:00Z',
                       'window_end':'2026-10-24T04:20:00Z',
                       'count':len(rows),'logs':rows},out)
        self.db.ingest([path]);self.db.rebuild()

    def test_disjoint_partition_and_not_promoted_to_behavior(self):
        routes=[
            'Files.Download','Files.Download',
            'PaymentRedirect.PaymentRedirect',
            'Public.v1/Weather',
            'Core.v1/UserWidgetsSetDefault',
            'Ewano.v1/EwanoCreateOrder',
            'Services.v1/TopUpProductsCharge',
            'Services.v42/UnlistedService',
            'Services.v1/TrafficFinesCarNoDetails',
        ]
        self.load([log(i,'r'+str(i),root+' Line:17',
                       'POST (G00000 | successful)',second=i)
                   for i,root in enumerate(routes,1)])
        audit=self.db.behavior_coverage(top=1)
        self.assertEqual('p24-behavior-coverage-LC2E',audit['version'])
        self.assertEqual(1,audit['counts']['semantic_service_execution'])
        self.assertEqual(1,audit['counts']['known_technical_facade_requests'])
        self.assertEqual(1,audit['counts']['source_catalog_unmapped_facade_requests'])
        queues=audit['unanchored_unknown_review_queues']
        self.assertEqual(audit['counts']['unknown_role_without_semantic_anchor_requests'],
                         audit['unanchored_unknown_triage_total'])
        self.assertEqual(audit['unanchored_unknown_triage_total'],
                         sum(x['request_executions'] for x in queues))
        self.assertEqual(len(queues),len({x['queue'] for x in queues}))
        for q in queues:
            self.assertEqual(q['request_executions'],
              sum(x['request_executions'] for x in q['api_roots'])+
              q['api_roots_omitted_request_executions'])
        self.assertIsNone(audit['manual_actions_confirmed'])
        self.assertIsNone(audit['fully_reconstructed_behaviors'])
        self.assertTrue(audit['read_only'])

    def test_triage_never_contains_source_identifiers_or_raw_payload(self):
        # Download itself now has an exact source-backed support role. Keep
        # this privacy test on a genuinely unclassified delivery API.
        self.load([log(1,'private','Files.UncatalogedDownload Line:17',
            'POST (G00000 | successful)')])
        report=self.db.behavior_coverage(top=10)
        serialized=json.dumps(report)
        self.assertNotIn('private',serialized)
        self.assertNotIn('session_key',serialized)
        self.assertNotIn('paymentKey',serialized)
        self.assertEqual(1,report['unanchored_unknown_triage_total'])

    def test_repeatability_and_read_only(self):
        self.load([log(1,'once','Public.v1/CalendarToday Line:9',
            'POST (G00000 | successful)')])
        before=self.db.one('SELECT COUNT(*) AS n FROM viewer_events')['n']
        a=self.db.behavior_coverage(top=20)
        b=self.db.behavior_coverage(top=20)
        self.assertEqual(a,b)
        self.assertEqual(before,self.db.one('SELECT COUNT(*) AS n FROM viewer_events')['n'])

if __name__=='__main__': unittest.main()
