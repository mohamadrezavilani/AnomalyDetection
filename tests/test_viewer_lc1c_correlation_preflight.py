"""LC1C non-authoritative, non-mutating correlation marker preflight."""
from __future__ import annotations

import gzip
import json
import tempfile
import unittest
from pathlib import Path

from p24_foundation.correlation_preflight import inspect_record, scan_files, MARKER


class CorrelationPreflightTests(unittest.TestCase):
    def test_plain_old_log_does_not_generate_candidate(self):
        self.assertEqual(inspect_record({'RequestID': 'R1', 'message': 'Payment Completed'}), [])

    def test_marker_in_text_is_not_promoted_to_identifier_or_edge(self):
        result = inspect_record({'message': 'value=' + MARKER + ' {"paymentKey":"K"}'})
        self.assertEqual([x['path'] for x in result], ['message'])
        self.assertEqual(result[0]['status'], 'unsupported_schema')
        self.assertNotIn('paymentKey', json.dumps(result))

    def test_structured_candidate_without_contract_is_unsupported(self):
        result = inspect_record({'correlation': {'version': MARKER, 'paymentKey': 'secret'}})
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['source'], 'structured_candidate')
        self.assertNotIn('secret', json.dumps(result))
        self.assertEqual(result[0]['status'], 'unsupported_schema')

    def test_unrelated_word_correlation_does_not_trigger(self):
        self.assertEqual(inspect_record({'message': 'correlation analysis'}), [])

    def test_raw_evidence_unchanged_and_identity_replay_checked(self):
        with tempfile.TemporaryDirectory() as root:
            a = Path(root)/'a.json.gz'
            b = Path(root)/'b.json.gz'
            e = {'_source_id': 'idx:abc', '@timestamp': '2026-10-25T00:00:00Z',
                 'message': 'P24_CORRELATION_V1 {"x": "secret"}'}
            e2 = dict(e, message='P24_CORRELATION_V1 {"x": "different"}')
            for path, rows in ((a,[e,e]), (b,[e2])):
                with gzip.open(path,'wt', encoding='utf-8') as out:
                    json.dump({'complete': True, 'count': len(rows), 'logs': rows}, out)
            before = (a.read_bytes(), b.read_bytes())
            result = scan_files([a,b],sample_limit=2)
            self.assertEqual(result['scanned_records'],3)
            self.assertEqual(result['duplicated_origin_captures'],1)
            self.assertEqual(result['divergent_origin_captures_for_review'],1)
            self.assertEqual(result['candidate_records'],3)
            self.assertEqual(result['unsupported_schema'],3)
            self.assertTrue(result['completed'])
            self.assertEqual(before,(a.read_bytes(),b.read_bytes()))
            self.assertNotIn('secret',json.dumps(result))

    def test_bounded_scan_cannot_claim_complete_coverage(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'logs.json'
            path.write_text(json.dumps([{'message': MARKER}, {'message': MARKER}]))
            report = scan_files([path],max_records=1)
            self.assertEqual(report['scanned_records'],1)
            self.assertFalse(report['completed'])

    def test_count_mismatch_is_reported_not_silently_ignored(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'logs.json.gz'
            with gzip.open(path,'wt',encoding='utf-8') as f:
                json.dump({'logs':[{'message': 'x'}], 'count': 2, 'complete': True},f)
            report=scan_files([path])
            self.assertFalse(report['files'][0]['count_matches'])
            self.assertEqual(report['candidate_records'],0)

    def test_bad_input_is_not_silently_accepted(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'wrong.json'
            path.write_text('{"not_logs": []}')
            with self.assertRaises(ValueError): scan_files([path])


if __name__=='__main__': unittest.main()
