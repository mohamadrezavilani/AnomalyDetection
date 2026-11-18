"""Receipt-bound isolated-session stop and real benchmark cleanup on private PG."""
import json
import os
from pathlib import Path
import time
import unittest
from unittest.mock import patch

from tests import test_behavior_benchmark_pg as fixtures
from viewer_performance.behavior_resources import CopyOwner
from viewer_performance.Stop_Behavior_Benchmark import request_stop


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'), 'disposable PG18 required')
class NativeBenchmarkStopTests(unittest.TestCase):
    setUpClass = classmethod(fixtures.NativeBehaviorBenchmarkTests.setUpClass.__func__)
    tearDownClass = classmethod(fixtures.NativeBehaviorBenchmarkTests.tearDownClass.__func__)
    setUp = fixtures.NativeBehaviorBenchmarkTests.setUp

    def folder(self, name='stop'):
        folder = self.root/name
        folder.mkdir()
        (folder/'release.json').write_text(json.dumps(dict(status='PREPARED_FOR_MAIN_UPDATE',
            stopping_started=True, frozen_cursors={'fixture': 'unchanged'})))
        return folder

    def connect(self, **kw):
        from psycopg.rows import dict_row
        return self.psycopg.connect(**self.params, autocommit=True, row_factory=dict_row, **kw)

    def test_exact_idle_copy_client_stops_and_original_owner_can_cleanup(self):
        folder = self.folder()
        owner = CopyOwner(self.admin, self.name, folder, lambda: None, time.monotonic()+60)
        with owner.clone() as row, self.connect(dbname='postgres', application_name='P24.BehaviorBenchmark.Control'):
            with self.connect(dbname=row['name'], application_name='P24.FinancialScreen.A') as client:
                client.execute('BEGIN READ ONLY');client.execute('SELECT 1')
                result = request_stop(self.admin, folder, expected_source=self.name)
                self.assertEqual(result['status'], 'ISOLATED_COPY_STOPPED_AWAIT_ORIGINAL_CONTROLLER_RESTORE')
                with self.assertRaises(self.psycopg.OperationalError):client.execute('SELECT 1')
        self.assertEqual(owner.state['allocations'][0]['state'], 'DROPPED')
        self.assertTrue(self.admin.execute('SELECT 1 FROM pg_database WHERE datname=%s',(self.name,)).fetchone())

    def test_changed_tag_never_stops_a_client(self):
        folder = self.folder()
        owner = CopyOwner(self.admin, self.name, folder, lambda: None, time.monotonic()+60)
        with owner.clone() as row, self.connect(dbname='postgres', application_name='P24.BehaviorBenchmark.Control'):
            with self.connect(dbname=row['name'], application_name='P24.FinancialScreen.A') as client:
                self.admin.execute(self.sql.SQL('COMMENT ON DATABASE {} IS {}').format(self.sql.Identifier(row['name']),self.sql.Literal('changed-owner')))
                try:
                    with self.assertRaisesRegex(ValueError, 'OWNERSHIP_NOT_PROVEN'):request_stop(self.admin,folder,expected_source=self.name)
                    self.assertEqual(client.execute('SELECT 1 AS ok').fetchone()['ok'],1)
                finally:
                    self.admin.execute(self.sql.SQL('COMMENT ON DATABASE {} IS {}').format(self.sql.Identifier(row['name']),self.sql.Literal('P24.BehaviorBenchmark:'+owner.run_id)))
                receipt=folder/'allocations.json';original=receipt.read_bytes()
                changed=json.loads(original);changed['allocations'][0]['oid']+=1
                receipt.write_text(json.dumps(changed))
                try:
                    with self.assertRaisesRegex(ValueError,'OWNERSHIP_NOT_PROVEN'):request_stop(self.admin,folder,expected_source=self.name)
                    self.assertEqual(client.execute('SELECT 1 AS ok').fetchone()['ok'],1)
                finally:receipt.write_bytes(original)

    def test_unexpected_additional_client_and_scope_activation_refuse_stop(self):
        folder = self.folder()
        owner = CopyOwner(self.admin, self.name, folder, lambda: None, time.monotonic()+60)
        with owner.clone() as row, self.connect(dbname='postgres', application_name='P24.BehaviorBenchmark.Control'):
            with self.connect(dbname=row['name'], application_name='P24.FinancialScreen.A') as client:
                with self.connect(dbname=row['name'], application_name='unreviewed') as extra:
                    with self.assertRaisesRegex(ValueError,'UNEXPECTED_COPY_SESSIONS'):request_stop(self.admin,folder,expected_source=self.name)
                    self.assertEqual(extra.execute('SELECT 1 AS ok').fetchone()['ok'],1)
                r=json.loads((folder/'release.json').read_text());r['scope_command']={'action':'enable'}
                (folder/'release.json').write_text(json.dumps(r))
                with self.assertRaisesRegex(ValueError,'NOT_IN_FROZEN'):request_stop(self.admin,folder,expected_source=self.name)
                self.assertEqual(client.execute('SELECT 1 AS ok').fetchone()['ok'],1)

    def test_real_benchmark_unwinds_owned_copy_and_keeps_source_history(self):
        from viewer_performance import behavior_benchmark as bench
        from viewer_performance.behavior_oracle import retained, archives
        from p24_foundation.viewer_data import ViewerDB
        folder=self.folder('real-stop')
        with ViewerDB(**self.options) as db:
            before=(retained(db),archives(db),db.one('SELECT * FROM viewer_live_state'))
        def interrupt(db, check):
            request_stop(self.admin, folder, expected_source=self.name)
            return retained(db, check)
        with patch.object(bench,'retained',side_effect=interrupt):
            result=bench.run(Path(__file__).resolve().parents[1],folder,lambda:None,lambda v:None,
                windows=2,max_seconds=120,parameters=self.params,options=self.options,
                capture_paths=[j['path'] for j in self.jobs],qualification_disk_path=Path(__file__).resolve().parents[1])
        self.assertEqual(result['status'],'LARGE_HISTORY_BENCHMARK_INCOMPLETE')
        self.assertEqual(result['remaining_owned_databases'],[])
        self.assertEqual(result['cleanup_failures'],[])
        with ViewerDB(**self.options) as db:
            self.assertEqual((retained(db),archives(db),db.one('SELECT * FROM viewer_live_state')),before)


if __name__=='__main__':unittest.main()
