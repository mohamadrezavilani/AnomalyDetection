"""Receipt-bound isolated-session stop and real benchmark cleanup on private PG."""
import json
from contextlib import contextmanager
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

    def test_retention_ends_only_original_control_and_preserves_copy(self):
        folder=self.folder('keep')
        control=self.connect(dbname='postgres',application_name='P24.BehaviorBenchmark.Control')
        self.addCleanup(control.close)
        owner=CopyOwner(control,self.name,folder,lambda:None,time.monotonic()+60)
        self.addCleanup(lambda:self.assertEqual(CopyOwner.recover(self.admin,folder/'allocations.json'),[]))
        def keeper(name):return self.connect(dbname=name,application_name='CopyPreservationRead')
        with self.assertRaises(self.psycopg.OperationalError):
            with owner.clone() as row:
                with self.connect(dbname=row['name'],application_name='P24.FinancialScreen.A') as client:
                    result=request_stop(self.admin,folder,expected_source=self.name,keep_copy=True,keeper_factory=keeper)
                    self.assertEqual(result['status'],'COPY_RETAINED_AWAIT_ORIGINAL_ROLE_RESTORE')
                    self.assertEqual(client.execute('SELECT 1 AS ok').fetchone()['ok'],1)
                    self.assertTrue(json.loads(Path(result['output']).read_text())['copy_retained'])
                    with self.assertRaises(self.psycopg.OperationalError):control.execute('SELECT 1')
        self.assertEqual(owner.state['allocations'][0]['state'],'OWNED')
        self.assertTrue(self.admin.execute('SELECT 1 FROM pg_database WHERE datname=%s',(row['name'],)).fetchone())

    def test_real_handoff_enables_behavior_without_checkpoint_or_history_change(self):
        from viewer_performance import behavior_benchmark as bench
        from viewer_performance.behavior_oracle import retained,archives
        from viewer_performance.fast_writer import FastWriterDB
        from viewer_performance.Behavior_Control import stopped_writer_leases,change
        from p24_foundation.viewer_product_scope import read,BEHAVIOR
        from p24_foundation.viewer_data import ViewerDB
        folder=self.folder('real-keep-enable')
        with ViewerDB(**self.options) as db:
            before=(retained(db),archives(db),db.one('SELECT * FROM viewer_live_state'))
        self.addCleanup(lambda:self.assertEqual(CopyOwner.recover(self.admin,folder/'allocations.json'),[]))
        @contextmanager
        def scope_context():
            with FastWriterDB(**self.options) as db:
                db.writer_identity.enabled=False
                with stopped_writer_leases(db):yield lambda:change(db,'enable',max_seconds=30)
        def interrupt(db,check):
            result=request_stop(self.admin,folder,expected_source=self.name,keep_copy=True,
                keeper_factory=lambda name:self.connect(dbname=name,application_name='CopyPreservationRead'),
                scope_context=scope_context)
            self.assertEqual(result['product_scope']['contract'],BEHAVIOR)
            return retained(db,check)
        with patch.object(bench,'retained',side_effect=interrupt):
            result=bench.run(Path(__file__).resolve().parents[1],folder,lambda:None,lambda value:None,
                windows=2,max_seconds=120,parameters=self.params,options=self.options,
                capture_paths=[j['path'] for j in self.jobs],qualification_disk_path=Path(__file__).resolve().parents[1])
        self.assertEqual(result['status'],'LARGE_HISTORY_BENCHMARK_CLEANUP_INCOMPLETE')
        self.assertEqual(len(result['remaining_owned_databases']),1)
        with ViewerDB(**self.options) as db:
            self.assertEqual(read(db,refresh=True)['contract'],BEHAVIOR)
            self.assertEqual((retained(db),archives(db),db.one('SELECT * FROM viewer_live_state')),before)

    def test_scope_failure_still_keeps_copy_and_leaves_source_full(self):
        from p24_foundation.viewer_product_scope import read,FULL
        from p24_foundation.viewer_data import ViewerDB
        folder=self.folder('failed-enable')
        control=self.connect(dbname='postgres',application_name='P24.BehaviorBenchmark.Control')
        self.addCleanup(control.close)
        owner=CopyOwner(control,self.name,folder,lambda:None,time.monotonic()+60)
        self.addCleanup(lambda:self.assertEqual(CopyOwner.recover(self.admin,folder/'allocations.json'),[]))
        @contextmanager
        def fail_scope():raise ValueError('SIMULATED_SCOPE_FAILURE');yield
        # A controller whose SQL socket has ended cannot subsequently DROP
        # the retained copy, even when activation fails before signaling.
        with self.assertRaises(self.psycopg.OperationalError):
            with owner.clone() as row:
                with self.connect(dbname=row['name'],application_name='P24.FinancialScreen.A'):
                    with self.assertRaisesRegex(ValueError,'SIMULATED_SCOPE_FAILURE'):
                        request_stop(self.admin,folder,expected_source=self.name,keep_copy=True,
                            keeper_factory=lambda name:self.connect(dbname=name,application_name='CopyPreservationRead'),
                            scope_context=fail_scope)
        with ViewerDB(**self.options) as db:self.assertEqual(read(db,refresh=True)['contract'],FULL)
        notes=list(folder.glob('benchmark-keep-*.json'))
        self.assertEqual(len(notes),1);self.assertTrue(json.loads(notes[0].read_text())['copy_retained'])


if __name__=='__main__':unittest.main()
