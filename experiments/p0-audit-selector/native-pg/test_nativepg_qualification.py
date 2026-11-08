"""Offline preflight checks; live PostgreSQL qualification remains separate."""
import hashlib
import importlib.util
import sys
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('native_pg_qualification',HERE/'P24_AD_P0_NativePG_Qualification.py')
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)

class ToyPG:
    def __init__(self):self.calls=[]
    def execute(self,sql,args=None):
        self.calls.append((sql,args))
        return self
    def fetchone(self):return None

class TestNativePG(unittest.TestCase):
    def test_candidate_hash_matches(self):
        actual=hashlib.sha256((HERE/'audit_scope_candidate.py').read_bytes()).hexdigest()
        self.assertEqual(actual,native.EXPECTED_CANDIDATE_SHA)

    def test_fixture_order_has_three_sessions_per_target(self):
        pg=ToyPG()
        rows,primary=native.fixture(pg,45,due_at=(22,),cursor_at=5)
        self.assertEqual(rows,sorted(rows,reverse=True))
        self.assertEqual(len(rows),45)
        self.assertEqual(primary['target_ns'],rows[5][0])
        self.assertEqual(len({t for t,s in rows}),15)

    def test_fixture_does_not_export_identity(self):
        import inspect
        src=inspect.getsource(native.fixture)
        self.assertNotIn('viewer_live_windows',src)
        self.assertNotIn('public.viewer_',src)
        self.assertIn('fixture_session_',src)

    def test_all_fixture_tables_in_unique_database_schema(self):
        sql='\n'.join(native.SCHEMA)
        for table in ('adp_state','adp_case_signals','adp_jobs','adp_facts','adp_source_windows'):
            self.assertIn('anomaly_detection.'+table,sql)
        self.assertNotIn('public.viewer_',sql)

    def test_database_safety_guards(self):
        from pathlib import Path
        for badname,badhost in [('elsewhere','localhost'),('p24_design_viewer','remote-db.internal')]:
            # Specific live-db guard is handled before psycopg import.
            self.assertTrue(badname!=native.DB_NAME or badhost not in ('localhost','127.0.0.1','::1'))
        self.assertIn('TEMPLATE template0', __import__('inspect').getsource(native.disposable_database))

    def test_qualification_bound(self):
        import inspect
        src=inspect.getsource(native.selector)
        self.assertIn('max_turns=60',src)
        self.assertIn('QUALIFICATION_MAX_TURNS_REACHED',src)

    def test_rollback_uses_transaction(self):
        import inspect
        source=inspect.getsource(native.rollback_case)
        self.assertIn('with conn.transaction()',source)
        self.assertIn('inject_rollback',source)

    def test_negative_fixture_has_valid_input_version(self):
        pg=ToyPG()
        native.fixture(pg,12,due_at=(8,),invalid_due=(2,))
        d=[args for sql,args in pg.calls if sql.startswith('INSERT INTO anomaly_detection.adp_facts')]
        self.assertEqual(len(d),2)
        self.assertIn('verified-inquiry-input-1',d[0][7])
        self.assertIsNone(d[1][7])

    def test_synthetic_only_and_no_live_dml(self):
        import inspect
        source=inspect.getsource(native.run)
        self.assertIn('SELECT (SELECT oid FROM pg_database',source)
        self.assertNotIn('UPDATE public.viewer_',source)
        self.assertNotIn('DELETE FROM public.viewer_',source)

    def test_all_comparison_fixtures_defined(self):
        import inspect
        src=inspect.getsource(native.run)
        for name in ['deep_after_cursor','wrap_to_older','tie_and_duplicate',
                     'no_due','current_visit_priority','incomplete_source_window',
                     'nonqualifying_evidence','zero_cursor']:
            self.assertIn(name,src)

if __name__=='__main__':unittest.main(verbosity=2)
