"""Native tests use disposable databases on the explicitly configured test cluster."""
import os
import importlib.util
import json
from pathlib import Path
import unittest
import uuid
from unittest.mock import patch

from anomaly_detection import FIVE_NS
from anomaly_detection import model_queue
from anomaly_detection.product_store import ProductStore


LEGACY_SELECT = (
    'SELECT j.* FROM anomaly_detection.adp_model_queue r '
    'JOIN anomaly_detection.adp_jobs j USING(session_key,target_ns) '
    'WHERE r.due_ns<=%s AND r.expected_version=j.version AND j.dirty=FALSE '
    'AND j.processed_version=j.version '
    'ORDER BY r.due_ns,r.target_ns,r.session_key LIMIT 1'
)
TARGET = 100 * FIVE_NS


def shadow_collector():
    path = Path(__file__).resolve().parents[1] / 'validation/qualify_model_queue_readonly.py'
    spec = importlib.util.spec_from_file_location('secondary_shadow', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'), 'native AD test cluster not configured')
class NativeModelQueueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.rows import dict_row
        cls.psycopg = psycopg
        cls.sql = sql
        cls.dict_row = staticmethod(dict_row)
        cls.params = {
            'host': os.environ['P24_DELTA_PG_HOST'],
            'port': int(os.environ.get('P24_DELTA_PG_PORT', '5432')),
            'user': os.environ.get('P24_DELTA_PG_USER', 'postgres'),
            'connect_timeout': 3,
        }
        cls.admin = psycopg.connect(**cls.params, dbname='postgres', autocommit=True)

    @classmethod
    def tearDownClass(cls):
        cls.admin.close()

    def setUp(self):
        self.name = 'p24_design_modeltest_' + uuid.uuid4().hex
        self.admin.execute(self.sql.SQL('CREATE DATABASE {}').format(self.sql.Identifier(self.name)))
        self.addCleanup(lambda: self.admin.execute(self.sql.SQL('DROP DATABASE {}').format(self.sql.Identifier(self.name))))
        self.raw = self.connect()
        self.addCleanup(self.raw.close)
        self.raw.execute('CREATE SCHEMA anomaly_detection')
        self.store = ProductStore(self.raw)
        self.store.initialize()

    def connect(self):
        return self.psycopg.connect(**self.params, dbname=self.name, autocommit=True, row_factory=self.dict_row)

    def job(self, number, *, target=TARGET, due=0, version=1, expected=1, processed=1, dirty=False):
        actor = format(number, '064x')
        self.raw.execute(
            'INSERT INTO anomaly_detection.adp_jobs'
            '(session_key,target_ns,version,processed_version,dirty) VALUES(%s,%s,%s,%s,%s)',
            (actor, target, version, processed, dirty),
        )
        self.raw.execute(
            'INSERT INTO anomaly_detection.adp_model_queue VALUES(%s,%s,%s,%s,%s,0)',
            (actor, target, expected, due, '["rate_5m"]'),
        )
        return actor

    def test_legacy_order_is_preserved_after_more_than_one_invalid_head_page(self):
        for number in range(1, 193):
            self.job(number, due=number, dirty=number % 3 == 0,
                     version=2 if number % 3 == 1 else 1,
                     processed=0 if number % 3 == 2 else 1)
        self.job(300, due=300, target=TARGET+FIVE_NS)
        self.job(301, due=300)
        self.job(302, due=300)
        self.job(303, due=400)
        self.raw.execute(
            'INSERT INTO anomaly_detection.adp_model_queue VALUES(%s,%s,1,0,%s,0)',
            ('f'*64, TARGET, '["rate_5m"]'),
        )
        before = self.raw.execute('SELECT * FROM anomaly_detection.adp_model_queue ORDER BY session_key,target_ns').fetchall()
        for now in (0, 192, 299, 300, 400):
            expected = self.raw.execute(LEGACY_SELECT, (now,)).fetchone()
            self.assertEqual(self.store.next_model_job(now), expected)
        self.assertEqual(self.store.next_model_job(300)['session_key'], format(301, '064x'))
        self.assertEqual(before, self.raw.execute('SELECT * FROM anomaly_detection.adp_model_queue ORDER BY session_key,target_ns').fetchall())

    def test_backoff_and_primary_version_refresh_preserve_pending_work(self):
        actor = self.job(1)
        selected = self.store.next_model_job(TARGET)
        model_queue.defer(self.store, selected, TARGET)
        self.assertIsNone(self.store.next_model_job(TARGET+1))
        self.assertEqual(self.store.next_model_job(TARGET+30_000_000_000)['session_key'], actor)
        with self.connect() as other:
            other.execute('UPDATE anomaly_detection.adp_jobs SET version=2,dirty=TRUE WHERE session_key=%s', (actor,))
        self.assertIsNone(self.store.next_model_job(TARGET+FIVE_NS))
        self.assertEqual(self.store.complete(selected, {}, [], TARGET+FIVE_NS),
                         {'status': 'INPUT_CHANGED_RETRY'})
        self.assertEqual(self.raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_model_queue').fetchone()['n'], 1)
        with self.raw.transaction():
            self.raw.execute('UPDATE anomaly_detection.adp_jobs SET processed_version=2,dirty=FALSE WHERE session_key=%s', (actor,))
            model_queue.schedule(self.store, dict(selected, version=2), ['rate_5m'], TARGET+FIVE_NS)
        self.assertEqual(self.store.next_model_job(TARGET+FIVE_NS)['version'], 2)
        self.assertEqual(self.raw.execute('SELECT attempts FROM anomaly_detection.adp_model_queue').fetchone()['attempts'], 1)

    def test_full_fallback_reaches_ready_work_beyond_bounded_prefix_and_empty_is_exact(self):
        for number in range(1, 601):
            self.job(number, due=number, dirty=True)
        actor = self.job(700, due=700)
        self.assertEqual(self.store.next_model_job(1000), self.raw.execute(LEGACY_SELECT, (1000,)).fetchone())
        self.assertEqual(self.store.next_model_job(1000)['session_key'], actor)
        self.raw.execute('UPDATE anomaly_detection.adp_jobs SET dirty=TRUE WHERE session_key=%s', (actor,))
        self.assertIsNone(self.store.next_model_job(1000))
        self.assertEqual(self.raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_model_queue').fetchone()['n'], 601)

    def test_connection_loss_after_selection_does_not_claim_or_remove_work(self):
        actor = self.job(1)
        reader = self.connect()
        reader.execute('BEGIN')
        self.assertEqual(ProductStore(reader).next_model_job(TARGET)['session_key'], actor)
        reader.close()
        self.assertEqual(self.store.next_model_job(TARGET)['session_key'], actor)
        row = self.raw.execute('SELECT expected_version,attempts FROM anomaly_detection.adp_model_queue').fetchone()
        self.assertEqual(row, {'expected_version': 1, 'attempts': 0})

    def test_selection_is_allowed_in_read_only_repeatable_read_snapshot(self):
        actor = self.job(1)
        with self.raw.transaction():
            self.raw.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            self.assertEqual(self.store.next_model_job(TARGET)['session_key'], actor)
            self.assertEqual(self.raw.execute("SELECT current_setting('transaction_read_only') AS ro").fetchone()['ro'], 'on')

    def test_shadow_collects_real_read_only_comparisons_without_exporting_rows_or_changing_work(self):
        actor = self.job(1)
        before = self.raw.execute('SELECT * FROM anomaly_detection.adp_model_queue').fetchall()
        result = shadow_collector().collect(self.raw, pairs=2)
        self.assertEqual(result['status'], 'PASS_READ_ONLY_EQUIVALENCE')
        self.assertEqual(result['snapshot']['read_only'], 'on')
        self.assertEqual(result['snapshot']['isolation'], 'repeatable read')
        self.assertTrue(all(t['equal_full_rows'] and t['candidate']['selected'] for t in result['trials']))
        self.assertEqual(result['plans']['candidate']['status'], 'COMPLETE')
        self.assertNotIn(actor, json.dumps(result))
        self.assertEqual(before, self.raw.execute('SELECT * FROM anomaly_detection.adp_model_queue').fetchall())

    def test_shadow_timeout_is_partial_and_savepoint_keeps_other_selector_readable(self):
        self.job(1)
        self.raw.execute("SET statement_timeout='20ms'")
        collector = shadow_collector()
        with patch.object(collector, 'LEGACY_SELECT', 'SELECT pg_sleep(0.1),%s'):
            result = collector.collect(self.raw, pairs=2)
        self.assertEqual(result['status'], 'PARTIAL')
        self.assertTrue(all(t['equal_full_rows'] is None for t in result['trials']))
        self.assertTrue(all(t['legacy']['sqlstate']=='57014' for t in result['trials']))
        self.assertTrue(all(t['candidate']['status']=='COMPLETE' for t in result['trials']))
        self.assertEqual(self.raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_model_queue').fetchone()['n'], 1)

    def test_large_queue_plan_reads_ordered_keys_before_fetching_one_parent(self):
        self.raw.execute('''INSERT INTO anomaly_detection.adp_jobs
            (session_key,target_ns,version,processed_version,dirty,evaluation)
            SELECT lpad(n::text,64,'0'),%s,1,
                   CASE WHEN n>128 AND mod(n,4)=0 THEN 1 ELSE 0 END,
                   NOT(n>128 AND mod(n,4)=0),repeat('synthetic fixture ',80)
            FROM generate_series(1,50000) n''', (TARGET,))
        self.raw.execute('''INSERT INTO anomaly_detection.adp_model_queue
            SELECT session_key,target_ns,version,session_key::numeric::bigint,'["rate_5m"]',0
            FROM anomaly_detection.adp_jobs''')
        self.raw.execute('ANALYZE anomaly_detection.adp_jobs')
        self.raw.execute('ANALYZE anomaly_detection.adp_model_queue')
        original = self.raw.execute(LEGACY_SELECT, (100000,)).fetchone()
        self.assertEqual(self.store.next_model_job(100000), original)
        queries = []
        class Capture:
            def execute(_, query, params):
                queries.append((query, params))
                return self.raw.execute(query, params)
        model_queue.next_job(type('Store', (), {'raw':Capture()})(), 100000)
        plan = self.raw.execute('EXPLAIN (ANALYZE, FORMAT JSON) '+queries[0][0], queries[0][1]).fetchone()['QUERY PLAN'][0]['Plan']
        def nodes(node):
            yield node
            for child in node.get('Plans', []):
                yield from nodes(child)
        parts = list(nodes(plan))
        active = [node for node in parts if node.get('Actual Loops', 0)]
        self.assertFalse(any(node['Node Type']=='Bitmap Heap Scan' for node in active))
        for node in active:
            if node['Node Type']=='Sort':
                self.assertLessEqual(sum(child['Actual Rows'] for child in node.get('Plans', [])), 256)
        indexes = {node.get('Index Name') for node in active}
        self.assertIn('adp_model_due', indexes)
        self.assertTrue(indexes & {'adp_jobs_pkey','adp_job_time'})


if __name__ == '__main__':
    unittest.main()
