"""LC3C synthetic replay safety witness; no live database connection."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from p24_foundation.lc3_replay_audit import VERSION, replay_witness, conflict_witness
from tools.run_lc3c_replay import main


class LC3COrderReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = replay_witness()

    def test_three_orders_identical_derived_graph(self):
        result=self.report
        self.assertEqual(VERSION,result['version'])
        self.assertEqual(['chronological','reverse','out_of_order'],result['orders_tested'])
        self.assertTrue(result['order_independent_derived_snapshot'])
        self.assertEqual(64,len(result['canonical_snapshot_sha256']))
        self.assertEqual(18,result['derived_counts']['events'])

    def test_duplicate_full_file_has_no_new_canonical_occurrence(self):
        self.assertTrue(self.report['repeated_file_import_idempotent'])
        self.assertEqual(3,self.report['observed_semantic_occurrence_count'])
        self.assertTrue(self.report['independent_inquiries_not_merged'])

    def test_one_invoice_two_payment_objects_and_no_merged_debit(self):
        self.assertEqual(2,self.report['derived_counts']['payment_objects'])
        self.assertTrue(self.report['different_internal_payments_preserved'])
        self.assertFalse(self.report['financial_settlement_inferred'])

    def test_callback_and_wallet_funding_not_inferred_by_session_or_clock(self):
        self.assertTrue(self.report['callback_stayed_provisional'])
        self.assertTrue(self.report['wallet_funding_not_joined_by_time_or_session'])
        self.assertFalse(self.report['confirmed_manual_actions_inferred'])

    def test_conflicting_origin_versions_do_not_become_action(self):
        case=self.report['conflict_witness']
        self.assertEqual(2,case['conflicted_origin_versions'])
        self.assertTrue(case['conflict_quarantined_from_action_count'])
        self.assertTrue(case['conflict_order_independent'])

    def test_scope_prohibits_false_r5_acceptance(self):
        self.assertEqual(0,self.report['full_r5_end_to_end_accepted_cases'])
        self.assertTrue(self.report['synthetic_only'])
        self.assertTrue(self.report['did_not_connect_to_live_viewer_database'])
        self.assertIn('real_PostgreSQL_projection_replay',self.report['not_proven'])
        self.assertIn('authoritative_payment_capture_or_refund',self.report['not_proven'])

    def test_command_writes_safe_json_without_database_config(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'result.json'
            self.assertEqual(0,main(['--out',str(path)]))
            data=json.loads(path.read_text(encoding='utf-8'))
            self.assertEqual(3,len(data['orders_tested']))
            self.assertEqual(0,data['full_r5_end_to_end_accepted_cases'])
            text=path.read_text(encoding='utf-8')
            self.assertNotIn('192.0.2.',text)
            self.assertNotIn('INV-LC3C',text)
            self.assertNotIn('password',text.lower())


if __name__=='__main__':unittest.main()
