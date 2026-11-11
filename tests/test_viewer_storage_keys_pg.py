"""Native migration, storage working-set, delta and recovery qualification.

Only disposable p24_design_delta_* databases on the opt-in PG18 cluster.
Fixtures contain synthetic hashes and no imported customer data.
"""
import hashlib
import json
import os
import time
import unittest

from p24_foundation.viewer_storage_keys import BODY, INDEXES, KEYS, ensure, exact_origin_join, conflict_clause, restore_original_keys
from tests import test_viewer_minimal_pg as native
from tests.test_viewer_online import START, FIVE_NS, snapshot, iso
from tests.test_viewer_r6_service_journey import log, sql


def key(value):
    return hashlib.sha256(str(value).encode()).hexdigest()


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'), 'native PG18 cluster not configured')
class NativeStorageKeysTests(unittest.TestCase):
    setUpClass = classmethod(native.NativeMinimalPublicationTests.setUpClass.__func__)
    tearDownClass = classmethod(native.NativeMinimalPublicationTests.tearDownClass.__func__)
    publish = native.NativeMinimalPublicationTests.publish

    def setUp(self):
        # Exercise an actual old installation, not only a fresh compact schema.
        original = native.ViewerDB.init
        def legacy(db):
            db._qualification_storage_layout = 'legacy'
            return original(db)
        from unittest.mock import patch
        with patch.object(native.ViewerDB, 'init', legacy):
            native.NativeMinimalPublicationTests.setUp(self)

    def upgrade(self):
        self.db.conn.commit()
        ensure(self.db)

    def fixture(self, count=6000):
        for table in KEYS:
            self.db.sql('DELETE FROM ' + table)
        links = []
        identifiers = []
        observations = []
        for n in range(count):
            origin, version, request = key('o' + str(n)), key('v' + str(n)), key('r' + str(n))
            links.append((origin, version, request, 'platform_payment', key('p' + str(n))))
            identifiers.append((origin, version, request, 'pishkhan24', 'internal_payment',
                'synthetic_source', 'sql.Parameters.paymentKey', 'r5:' + key('i' + str(n)), 'synthetic-' + str(n)))
            observations.append((origin, version, request, n, 'Core.v1/Synthetic',
                'reported_status', 'synthetic', 'sql.Parameters.statusName', 'reported'))
        for table, values in (('viewer_links', links), ('viewer_contract_identifiers', identifiers),
                              ('viewer_contract_observations', observations)):
            self.db.many('INSERT INTO ' + table + ' VALUES(' + ','.join('?' for _ in values[0]) + ')', values)
        self.db.conn.commit()

    def rows(self):
        return {table: self.db.all('SELECT * FROM ' + table + ' ORDER BY ' + ','.join(keys))
                for table, keys in KEYS.items()}

    def test_online_upgrade_retains_all_original_values_and_reduces_index_working_set(self):
        self.fixture()
        before = self.rows()
        old_bytes = {table: self.db.one('SELECT pg_relation_size(CAST(? AS regclass)) AS n',
                     (table + '_pkey',))['n'] for table in KEYS}
        began = time.monotonic()
        self.upgrade()
        self.assertEqual(before, self.rows())
        sizes = {}
        for table in KEYS:
            names = [name for name, spec in INDEXES.items() if spec[0] == table]
            sizes[table] = sum(self.db.one('SELECT pg_relation_size(CAST(? AS regclass)) AS n', (name,))['n'] for name in names)
            self.assertLess(sizes[table], old_bytes[table])
            self.assertFalse(self.db.one('SELECT to_regclass(?) IS NOT NULL AS present', (table + '_pkey',))['present'])
        for name in INDEXES:
            self.assertEqual(self.db.one('SELECT indisvalid,indisready FROM pg_index WHERE indexrelid=CAST(? AS regclass)',
                (name,)), {'indisvalid': True, 'indisready': True})
        print('STORAGE_NATIVE_RESULT=' + json.dumps({'rows_per_table': 6000, 'old_primary_index_bytes': old_bytes,
            'new_unique_and_origin_index_bytes': sizes, 'upgrade_seconds': round(time.monotonic() - began, 3),
            'all_original_rows_equal': True, 'production_capacity': 'NOT_MEASURED'}))
        self.db.conn.commit()
        ensure(self.db)  # restart is idempotent and validates every definition.

    def test_digest_is_exact_length_delimited_unicode_and_handles_null_distinctly(self):
        self.upgrade()
        pairs = [('ab', 'c'), ('a', 'bc'), ('', 'x'), ('x', ''), ('', ''),
                 ('آب', 'ی'), ('آ', 'بی'), ('\\', '"'), (None, 'x')]
        seen = set()
        for parts in pairs:
            encoded = ''.join('-:' if value is None else str(len(value)) + ':' + value for value in parts).encode('utf-8')
            value = bytes(self.db.one('SELECT public.viewer_key_digest_v1(?,?) AS k', parts)['k'])
            self.assertEqual(value, hashlib.sha256(encoded).digest())
            self.assertNotIn(value, seen)
            seen.add(value)

    def test_original_conflict_targets_can_be_restored_without_moving_evidence(self):
        self.fixture(count=100)
        before = self.rows()
        self.upgrade()
        self.db.conn.commit()
        restore_original_keys(self.db)
        self.assertEqual(before, self.rows())
        for table, keys in KEYS.items():
            row = before[table][0]
            columns = list(row)
            self.db.sql('INSERT INTO ' + table + '(' + ','.join(columns) + ') VALUES(' +
                ','.join('?' for _ in columns) + ') ON CONFLICT(' + ','.join(keys) + ') DO NOTHING',
                [row[c] for c in columns])
        self.db.conn.commit()
        self.assertEqual(before, self.rows())

    def test_interrupted_concurrent_build_preserves_old_primary_keys_and_resumes(self):
        seen = []
        def interrupt(event):
            if event['stage'] == 'storage_index_ready':
                seen.append(event['index'])
                if len(seen) == 2:
                    raise RuntimeError('stop_during_index_build')
        self.db.progress_callback = interrupt
        with self.assertRaisesRegex(RuntimeError, 'stop_during_index_build'):
            self.upgrade()
        for table in KEYS:
            self.assertTrue(self.db.one('SELECT to_regclass(?) IS NOT NULL AS present', (table + '_pkey',))['present'])
        self.db.progress_callback = None
        self.upgrade()
        self.assertEqual(self.db.one('SELECT layout FROM viewer_storage_layout')['layout'], 'compact_evidence_keys_v1')

    def test_reader_lock_timeout_rolls_back_whole_cutover_and_restart_finishes(self):
        import psycopg
        reader = psycopg.connect(**self.config)
        self.addCleanup(reader.close)
        def hold(event):
            if event['stage'] == 'storage_index_ready' and event['index'] == list(INDEXES)[-1]:
                reader.execute('SELECT 1 FROM viewer_contract_identifiers LIMIT 1')
        self.db.progress_callback = hold
        with self.assertRaises(psycopg.errors.LockNotAvailable):
            self.upgrade()
        for table in KEYS:
            self.assertTrue(self.db.one('SELECT to_regclass(?) IS NOT NULL AS present', (table + '_pkey',))['present'])
        reader.rollback()
        self.db.progress_callback = None
        self.upgrade()

    def test_unrecognized_digest_function_is_rejected_before_cutover(self):
        self.db.sql('CREATE FUNCTION public.viewer_key_digest_v1(VARIADIC parts text[]) RETURNS bytea '
                    "LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE SET search_path=pg_catalog AS $$SELECT '\\x00'::bytea$$")
        with self.assertRaisesRegex(ValueError, 'storage_digest_definition_mismatch'):
            self.upgrade()
        self.assertTrue(self.db.one("SELECT to_regclass('viewer_links_pkey') IS NOT NULL AS present")['present'])

    def test_origin_lookup_uses_compact_index_and_keeps_exact_comparison(self):
        self.fixture()
        self.upgrade()
        self.db.sql('ANALYZE viewer_links')
        join = exact_origin_join(self.db, 'l', 'e')
        query = 'SELECT l.* FROM (VALUES(?,?)) e(origin_key,version_key) JOIN viewer_links l ON ' + join
        rows = self.db.all(query, (key('o1'), key('v1')))
        self.assertEqual(len(rows), 1)
        plan = self.db.one('EXPLAIN (ANALYZE,FORMAT JSON) ' + query, (key('o1'), key('v1')))['QUERY PLAN'][0]['Plan']
        serialized = json.dumps(plan)
        self.assertIn('vli_origin_version_v1', serialized)
        self.assertIn('origin_key', serialized)
        self.assertIn('version_key', serialized)

    def test_fresh_requests_skip_old_projection_probes_and_existing_noop_keeps_tids(self):
        self.upgrade()
        self.publish([log(1, 'first', 'Services.v1/WaterBills Line:1', 'POST (G00000 | successful)')])
        row = log(2, 'pay', 'DBPath.x.ud_prc_paymentExists', sql('ud_prc_paymentExists', paymentKey='K'))
        row['@timestamp'] = iso(START + FIVE_NS + 1_000_000_000)
        events = []
        self.db.progress_callback = events.append
        self.publish([row], START + FIVE_NS)
        merges = [e for e in events if e['stage'] == 'projection_publish_complete']
        self.assertEqual(len(merges), 6)
        self.assertTrue(all(e['method'] == 'scoped_delta_copy' and e['historical_request_probes'] == 0 for e in merges))
        tables = tuple(KEYS) + ('viewer_requests', 'viewer_actions', 'viewer_contract_edges')
        tids = lambda: {table: self.db.all('SELECT ctid::text,* FROM ' + table + ' ORDER BY 1') for table in tables}
        before = tids()
        request = self.db.lookup_request('pay')['request_key']
        self.db.rebuild(request_keys=[request], commit=False)
        self.db.rebuild_payment_contract(request_keys=[request], commit=False)
        self.db.conn.commit()
        self.assertEqual(before, tids())

    def test_collision_or_inconsistent_orphan_cannot_be_silently_merged_by_append(self):
        import psycopg
        self.upgrade()
        self.db.sql("INSERT INTO viewer_links VALUES('o','v','r','platform_payment','p')")
        self.db.conn.commit()
        with self.assertRaises(psycopg.errors.UniqueViolation):
            self.db.sql("INSERT INTO viewer_links VALUES('o','v','other-r','platform_payment','p')")
        self.db.conn.rollback()
        self.assertEqual(self.db.one("SELECT request_key FROM viewer_links WHERE origin_key='o'")['request_key'], 'r')

    def test_injected_digest_collision_is_rejected_even_by_idempotent_maintenance_insert(self):
        import psycopg
        self.upgrade()
        # Deliberately break the digest only in this empty disposable database.
        # This makes two different exact identities hit one unique index entry.
        self.db.sql("CREATE OR REPLACE FUNCTION public.viewer_key_digest_v1(VARIADIC parts text[]) RETURNS bytea LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE SET search_path=pg_catalog AS $$SELECT decode(repeat('00',32),'hex')$$")
        query = 'INSERT INTO viewer_links VALUES(?,?,?,?,?)' + conflict_clause(self.db, 'viewer_links')
        self.db.sql(query, ('o1', 'v', 'r', 'platform_payment', 'p'))
        self.db.sql(query, ('o1', 'v', 'r', 'platform_payment', 'p'))  # exact replay succeeds
        self.db.conn.commit()
        with self.assertRaises(psycopg.errors.UniqueViolation):
            self.db.sql(query, ('o2', 'v', 'r', 'platform_payment', 'p'))
        self.db.conn.rollback()
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_links')['n'], 1)

    def test_compact_delta_late_revision_and_full_rebuild_preserve_the_same_snapshot(self):
        self.upgrade()
        original = log(1, 'a', 'Services.v1/WaterBills Line:1', 'POST (G00000 | successful)')
        pay = log(2, 'pay', 'DBPath.x.ud_prc_paymentExists', sql('ud_prc_paymentExists', paymentKey='K'))
        self.publish([original, pay])
        callback = log(3, 'callback', 'DBPath.x.ud_prc_paymentExists', sql('ud_prc_paymentExists', paymentKey='K'))
        callback['@timestamp'] = iso(START + FIVE_NS + 1_000_000_000)
        self.publish([callback], START + FIVE_NS)
        changed = dict(original, RequestID='other', message='POST (GD2016 | unavailable)')
        self.publish([changed, pay], mode='recheck')
        before = snapshot(self.db)
        self.db.rebuild(); self.db.rebuild_payment_contract(); self.db.build_semantic_index()
        self.assertEqual(before, snapshot(self.db))


if __name__ == '__main__':
    unittest.main()
