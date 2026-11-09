"""Dangerous-target refusals and exact full-row reconciliation, without PG claims."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import Run_Viewer_Recovery_Checks as recovery


class RecoveryQualificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def cluster(self, source=None):
        return recovery.PrivateCluster(self.root, self.root / 'bin', source or self.root / 'owner_pgdata',
                                       'OWNER-SYSTEM', 5432, '1234abcd')

    def test_full_multiset_hash_is_independent_of_fetch_order_and_chunk_size(self):
        rows = [hashlib.sha256(str(x).encode()).digest() for x in (4, 1, 8, 1, 5, 4, 9)]
        first = recovery.sorted_hash_manifest(iter(rows), self.root / 'first', chunk_rows=2)
        second = recovery.sorted_hash_manifest(reversed(rows), self.root / 'second', chunk_rows=3)
        self.assertEqual(first, second)
        self.assertEqual(first, dict(rows=7, sha256=hashlib.sha256(b''.join(sorted(rows))).hexdigest()))

    def test_missing_duplicate_or_one_changed_row_changes_full_manifest(self):
        a, b = hashlib.sha256(b'a').digest(), hashlib.sha256(b'b').digest()
        manifests = [recovery.sorted_hash_manifest(data, self.root / str(i), chunk_rows=1)
                     for i, data in enumerate(([a, a, b], [a, b], [a, a, a]))]
        self.assertNotEqual(manifests[0], manifests[1])
        self.assertNotEqual(manifests[0], manifests[2])

    def test_empty_table_hashes_correctly(self):
        self.assertEqual(recovery.sorted_hash_manifest([], self.root / 'empty'),
                         dict(rows=0, sha256=hashlib.sha256(b'').hexdigest()))

    def test_existing_manifest_directory_is_never_overwritten(self):
        directory = self.root / 'already'
        directory.mkdir()
        sentinel = directory / 'sentinel'
        sentinel.write_text('preserve')
        with self.assertRaises(FileExistsError):
            recovery.sorted_hash_manifest([], directory)
        self.assertEqual(sentinel.read_text(), 'preserve')

    def test_truncated_digest_refused(self):
        with self.assertRaisesRegex(recovery.QualificationError, 'invalid_row_digest'):
            recovery.sorted_hash_manifest([b'short'], self.root / 'invalid')

    def test_owner_path_is_refused_before_any_server_command(self):
        cluster = self.cluster(self.root / 'isolated_pgdata')
        with patch.object(recovery, 'run_private') as run:
            with self.assertRaisesRegex(recovery.QualificationError, 'unsafe_cluster_path'):
                cluster.initialize()
        run.assert_not_called()

    def test_preexisting_datadir_is_never_initialized(self):
        cluster = self.cluster()
        cluster.data.mkdir()
        sentinel = cluster.data / 'owner-sentinel'
        sentinel.write_text('preserve')
        with patch.object(recovery, 'run_private') as run:
            with self.assertRaisesRegex(recovery.QualificationError, 'cluster_path_already_exists'):
                cluster.initialize()
        run.assert_not_called()
        self.assertEqual(sentinel.read_text(), 'preserve')

    def test_work_directory_inside_owner_pgdata_is_refused(self):
        cluster = recovery.PrivateCluster(self.root / 'owner' / 'nested_test', self.root / 'bin',
                                         self.root / 'owner', 'OWNER-SYSTEM', 5432, '1234abcd')
        with self.assertRaisesRegex(recovery.QualificationError, 'unsafe_cluster_path'):
            cluster.path_guard()

    def test_tampered_guard_blocks_stop_before_connect_or_command(self):
        cluster = self.cluster()
        cluster.created = True
        cluster.marker.write_text(json.dumps(dict(run_id='another', data=str(cluster.data), port=cluster.port)))
        with patch.object(recovery, 'run_private') as run, patch('psycopg.connect') as connect:
            with self.assertRaisesRegex(recovery.QualificationError, 'cluster_marker_mismatch'):
                cluster.stop('immediate')
        run.assert_not_called()
        connect.assert_not_called()

    @unittest.skipIf(os.name == 'nt', 'symlink privileges vary on Windows')
    def test_datadir_symlink_to_existing_cluster_is_refused(self):
        owner = self.root / 'owner_pgdata'
        owner.mkdir()
        cluster = self.cluster(owner)
        cluster.data.symlink_to(owner, target_is_directory=True)
        with self.assertRaisesRegex(recovery.QualificationError, 'unsafe_cluster_path'):
            cluster.path_guard()

    def test_source_environment_never_leaks_into_private_cluster_commands(self):
        with patch.dict(os.environ, {'PGDATA': '/owner', 'PGHOST': 'owner-host', 'PGOPTIONS': 'owner-options',
                                     'PGSERVICE': 'production'}):
            env = recovery.clean_pg_environment()
            self.assertFalse(any(k.upper().startswith('PG') for k in env))
            target = recovery.clean_pg_environment(dict(host='127.0.0.1', port=55432, dbname='new-test', password='secret'))
            self.assertEqual(target['PGPORT'], '55432')
            self.assertEqual(target['PGHOST'], '127.0.0.1')
            self.assertEqual(target['PGDATABASE'], 'new-test')
            self.assertNotIn('PGOPTIONS', target)
            self.assertEqual(os.environ['PGDATA'], '/owner')

    def test_unhandled_source_connection_option_fails_before_work(self):
        with self.assertRaisesRegex(recovery.QualificationError, 'unsupported_connection_option'):
            recovery.clean_pg_environment(dict(dbname='p24_design_viewer', service='external'))

    def test_child_refuses_owner_db_and_nonlocal_targets_before_connect(self):
        for config in (dict(dbname='p24_design_viewer', host='127.0.0.1'),
                       dict(dbname='postgres', host='127.0.0.1'),
                       dict(dbname='p24_design_native_1234abcd_servercrash_qualification', host='remote')):
            with self.subTest(config=config), patch('psycopg.connect') as connect:
                with self.assertRaisesRegex(recovery.QualificationError, 'unsafe_child_database'):
                    recovery.crash_child(dict(config=config))
                connect.assert_not_called()

    def test_create_database_refuses_uncontrolled_names_and_preserves_locale(self):
        locale = dict(encoding='UTF8', provider='c', collate='C', ctype='C')
        for name in ('p24_design_viewer', 'postgres', 'p24_design_native_1234abcd_sql_qualification', 'x; DROP DATABASE x'):
            with self.assertRaisesRegex(recovery.QualificationError, 'unsafe_test_database'):
                recovery.create_database_sql(name, locale)
        query = recovery.create_database_sql('p24_design_native_1234abcd_ownerrestore_qualification', locale).as_string()
        self.assertIn('TEMPLATE template0', query)
        self.assertIn("LC_COLLATE 'C' LC_CTYPE 'C'", query)

    def test_nonstandard_icu_rules_never_silently_discarded(self):
        with self.assertRaisesRegex(recovery.QualificationError, 'custom_icu_rules_require_review'):
            recovery.create_database_sql('p24_design_native_1234abcd_ownerrestore_qualification',
                dict(encoding='UTF8', provider='i', locale='en-US', icu_rules='custom-rules'))


if __name__ == '__main__':
    unittest.main()
