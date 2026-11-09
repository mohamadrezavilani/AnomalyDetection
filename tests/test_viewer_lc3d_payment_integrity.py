"""LC3D: real schema, synthetic evidence; never touches user's PostgreSQL."""
from __future__ import annotations
from contextlib import closing
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from p24_foundation.lc3_replay_audit import _fixture_windows
from p24_foundation.lc3_payment_integrity_audit import audit_payment_evidence
from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from tools.run_lc3b_readmodel import ReadOnlyDB,read_options
from tools.run_lc3d_payment_audit import execute_audit,main


class LC3DPaymentIntegrityTests(unittest.TestCase):
    def setUp(self):
        ctx=tempfile.TemporaryDirectory();self.addCleanup(ctx.cleanup)
        self.root=Path(ctx.name)
        keys=self.root/'keys.json';generate_keys(keys)
        self.path=self.root/'isolated.sqlite'
        self.db=ViewerDB(sqlite_path=self.path,keys_path=keys)
        self.addCleanup(self.db.close)
        self.db.init()
        self.files=_fixture_windows(self.root)
        for path in self.files:
            self.db.ingest([path])
            self.db.rebuild();self.db.rebuild_payment_contract()
        self.config=self.root/'viewer_config.local.py'
        self.config.write_text('SQLITE_OFFLINE_PATH = '+repr(str(self.path))+'\n',encoding='utf8')

    def test_invoice_can_cooccur_with_two_separate_payment_objects_not_two_debits(self):
        result=execute_audit(self.config)
        ident={r['kind']:r for r in result['inventory']['identifier_kinds']}
        self.assertGreaterEqual(ident['internal_payment']['distinct_objects'],2)
        rows=result['cardinality_witnesses']['multi_k_invoice_contexts_sampled']
        self.assertEqual(1,len(rows))
        self.assertEqual(2,rows[0]['distinct_k_coobserved_in_requests'])
        self.assertEqual('same_request_context_only_NOT_payment_allocation',rows[0]['relationship_claim'])
        self.assertEqual('unverified',result['assessment']['financial_confirmation'])
        self.assertIsNone(result['assessment']['confirmed_manual_action_count'])
        self.assertEqual(0,result['assessment']['fully_accepted_end_to_end_cases'])

    def test_independent_status_axes_and_provenance_all_valid(self):
        result=execute_audit(self.config)
        axes={r['axis'] for r in result['inventory']['independent_status_axes']}
        self.assertIn('fulfillment_report',axes)
        self.assertTrue(result['evidence_integrity']['all_checked_references_consistent'])
        self.assertTrue(all(n==0 for n in result['evidence_integrity']['checks'].values()))
        self.assertTrue(result['read_only'])
        self.assertEqual('p24-lc3d-payment-evidence-audit-v1',result['version'])

    def test_read_only_input_is_not_modified_and_reader_closes_connection(self):
        before=self.db.one('SELECT COUNT(*) AS n FROM viewer_contract_edges')['n']
        self.assertEqual(0,main(['--config',str(self.config),'--out',str(self.root/'report.json')]))
        self.assertEqual(before,self.db.one('SELECT COUNT(*) AS n FROM viewer_contract_edges')['n'])
        report=json.loads((self.root/'report.json').read_text(encoding='utf8'))
        self.assertTrue(report['read_only'])
        self.assertNotIn('raw_value',json.dumps(report))
        with closing(sqlite3.connect(self.path.as_uri()+'?mode=ro',uri=True)) as conn:
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute('DELETE FROM viewer_contract_edges')

    def test_orphan_provenance_is_reported_not_silently_accepted(self):
        self.db.sql('DELETE FROM viewer_events WHERE origin_key IN (SELECT evidence_origin FROM viewer_contract_edges LIMIT 1)')
        self.db.conn.commit()
        result=execute_audit(self.config)
        self.assertFalse(result['evidence_integrity']['all_checked_references_consistent'])
        self.assertIn('indexed_evidence_provenance_inconsistency_requires_review',result['warnings'])
        self.assertGreater(result['evidence_integrity']['checks']['edges_missing_raw_event'],0)

    def test_optional_sample_limit_zero_and_bounds(self):
        result=execute_audit(self.config,sample_limit=0)
        self.assertEqual([],result['cardinality_witnesses']['multi_k_invoice_contexts_sampled'])
        for invalid in (-1,13,True,'8'):
            with self.subTest(invalid=invalid),self.assertRaises(ValueError):
                audit_payment_evidence(ReadOnlyDB(self.db.conn),sample_limit=invalid)

    def test_psycopg_marker_safety_against_strict_sql_placeholder_parser(self):
        class StrictPostgres:
            def __init__(self,handle):self.handle=handle
            def execute(self,sql,values=()):
                out=[];i=0;slots=0
                while i<len(sql):
                    if sql[i]!='%':out.append(sql[i]);i+=1;continue
                    if i+1>=len(sql):raise AssertionError('unpaired_percent')
                    if sql[i+1]=='s':out.append('?');slots+=1
                    elif sql[i+1]=='%':out.append('%')
                    else:raise AssertionError('invalid_postgres_percent_marker')
                    i+=2
                if slots!=len(values):raise AssertionError('placeholder_count_mismatch')
                return self.handle.execute(''.join(out),values)
        with closing(sqlite3.connect(self.path)) as conn:
            conn.row_factory=sqlite3.Row
            result=audit_payment_evidence(ReadOnlyDB(StrictPostgres(conn),postgres=True),sample_limit=3)
        self.assertTrue(result['evidence_integrity']['all_checked_references_consistent'])

    def test_configuration_rejects_operational_database_and_tool_does_not_output_sensitive_data(self):
        config=self.root/'bad.py'
        config.write_text('DATABASE = '+repr({'dbname':'pishkhan24_shadow','user':'postgres'})+'\n')
        with self.assertRaises(ValueError):read_options(config)
        self.assertEqual(2,main(['--config',str(config),'--out',str(self.root/'bad-result.json')]))
        self.assertFalse((self.root/'bad-result.json').exists())


if __name__=='__main__':unittest.main()
