"""LC3A: full acceptance MUST NOT be confused with synthetic unit guards."""
from __future__ import annotations
import csv
import json
import tempfile
from pathlib import Path
import unittest
from tools.run_lc3_acceptance import (
    MATRIX, EXPECTED_CASES, GUARDS, read_matrix, build_report, main,
)


class LC3AcceptanceAuditTests(unittest.TestCase):
    def test_all_original_86_rows_preserved_and_expected_assertions_unmodified(self):
        cases=read_matrix(MATRIX)
        self.assertEqual(EXPECTED_CASES,len(cases))
        self.assertEqual(EXPECTED_CASES,len(set(c['id'] for c in cases)))
        self.assertTrue(all(c.get('expected_json') for c in cases))
        self.assertTrue(all(isinstance(json.loads(c['expected_json']),dict) for c in cases))

    def test_report_only_never_claims_tests_or_full_case_passed(self):
        report=build_report(MATRIX,execute=False)
        self.assertEqual(0,report['counts']['fully_accepted_end_to_end_cases'])
        self.assertEqual(86,report['counts']['full_acceptance_not_executed_cases'])
        self.assertEqual(0,report['counts']['synthetic_guard_passed_cases'])
        self.assertEqual(86,len(report['cases']))
        self.assertTrue(all(c['full_end_to_end_acceptance']=='NOT_EXECUTED' for c in report['cases']))
        self.assertTrue(all('original_expected_json' in c for c in report['cases']))
        self.assertTrue(report['read_only'])

    def test_case_guard_mapping_cannot_invent_full_acceptance(self):
        report=build_report(MATRIX,execute=False)
        guarded=[c for c in report['cases'] if c['case_id'] in GUARDS]
        self.assertEqual(len(GUARDS),len(guarded))
        self.assertTrue(all(c['full_end_to_end_acceptance']=='NOT_EXECUTED' for c in guarded))
        self.assertEqual(61,report['counts']['synthetic_guard_unmapped_cases'])

    def test_missing_row_and_duplicate_case_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'matrix.csv'
            with MATRIX.open(encoding='utf-8-sig',newline='') as f:
                rows=list(csv.DictReader(f)); fields=list(rows[0])
            for data in (rows[:-1],rows[:-1]+[rows[0]]):
                with target.open('w',encoding='utf-8',newline='') as f:
                    writer=csv.DictWriter(f,fieldnames=fields)
                    writer.writeheader(); writer.writerows(data)
                with self.assertRaises(ValueError):read_matrix(target)

    def test_cli_report_only_writes_deterministic_case_mapping_without_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'report.json'
            self.assertEqual(0,main(['--out',str(path),'--report-only']))
            report=json.loads(path.read_text(encoding='utf-8'))
            self.assertEqual('NOT_EXECUTED',report['cases'][0]['full_end_to_end_acceptance'])
            self.assertEqual('p24-lc3a-r5-acceptance-guard-audit-v1',report['version'])
            self.assertEqual(0,report['counts']['fully_accepted_end_to_end_cases'])

    def test_synthetic_guard_status_is_not_full_acceptance_even_when_passed(self):
        # Exercises the actual runnable guard, not merely the report-only mode.
        report=build_report(MATRIX,execute=True)
        self.assertEqual(0,report['counts']['synthetic_guard_error_cases'])
        self.assertEqual(len(GUARDS),report['counts']['synthetic_guard_passed_cases'])
        self.assertEqual(0,report['counts']['fully_accepted_end_to_end_cases'])
        self.assertTrue(all(c['full_end_to_end_acceptance']=='NOT_EXECUTED' for c in report['cases']))


if __name__=='__main__':unittest.main()
