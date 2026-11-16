"""Read-ahead has bounded resources and no authority over evidence semantics."""
import multiprocessing
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.viewer_online import publish_capture
from tests import test_viewer_contract_fetch_once as contract
from viewer_performance.capacity.baseline import run,semantic_snapshot
from viewer_performance.capacity.fixtures import corpus,START,FIVE
from viewer_performance.capacity.index_prefetch import IndexPrefetchDB,BATCH,probe_sql
from viewer_performance.capacity.local_projection_keys import LocalProjectionKeysDB


def killed_prefetch(options,path,start,point):
    with IndexPrefetchDB(**options) as db:
        db.prepare_candidate()
        if point=='prefetch':
            original=db._probe
            def die(*args):
                original(*args)
                os._exit(73)
            db._probe=die
        publish_capture(db,path,start,start+FIVE,
            fault=lambda stage:os._exit(73) if stage==point else None)
    os._exit(74)


class PrefetchContracts(unittest.TestCase):
    def test_readers_never_open_an_existing_product_database(self):
        import psycopg
        with patch('psycopg.connect',side_effect=AssertionError('must not connect')):
            for name in ('p24_design_viewer','application','p24_design_not_allocated'):
                with self.assertRaisesRegex(ValueError,'qualification_only'):
                    IndexPrefetchDB(config={'dbname':name},keys_path='missing')

    def test_worker_count_and_table_identifiers_are_closed(self):
        for workers in (0,3,8,32):
            with self.assertRaises(ValueError):IndexPrefetchDB(prefetch_workers=workers)
        with self.assertRaises(ValueError):probe_sql('viewer_events; DROP TABLE anything')
        for table in ('viewer_events','viewer_raw_events'):
            sql=probe_sql(table)
            self.assertIn('CROSS JOIN LATERAL',sql)
            self.assertIn(' OFFSET 0',sql)
            self.assertIn('viewer_hmac_bytes_v1(stored.version_key)',sql)
            self.assertNotIn('FOR UPDATE',sql)

    def test_sqlite_does_not_claim_native_prefetch_was_exercised(self):
        report=run(counts=(1,1,1),pairs=1,experiment='index_prefetch_2')
        self.assertEqual(report['status'],'NOT_QUALIFIED_CANDIDATE_UNUSED')
        self.assertTrue(report['checks'][0]['all_equal'])
        self.assertEqual(report['comparison_baseline_variant'],'local_projection_keys')


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'isolated PG18 not configured')
class NativeIndexPrefetch(unittest.TestCase):
    setUpClass=classmethod(contract.NativeContractFetchTests.setUpClass.__func__)
    tearDownClass=classmethod(contract.NativeContractFetchTests.tearDownClass.__func__)
    native=True
    database=contract.ContractChecks.database

    def test_one_two_four_readers_keep_all_publication_boundaries_equal(self):
        for workers in (1,2,4):
            report=run(backend='postgresql',counts=(2,3,4),pairs=2 if workers==2 else 1,
                experiment='index_prefetch_'+str(workers),wal_compression='zstd')
            self.assertEqual(report['status'],'PASS_CANDIDATE_EQUIVALENCE',report.get('failure'))
            self.assertEqual(report['comparison_baseline_variant'],'local_projection_keys')
            for lane in report['lanes']:
                if lane['variant'].startswith('index_prefetch_'):
                    hints=lane['candidate_report']['index_prefetch']
                    self.assertLessEqual(hints['max_pending_observed'],workers)
                    self.assertGreater(hints['successful_batches'],0)
                    self.assertEqual(hints['failures_total'],0)
                    self.assertGreater(hints['readonly_connections_verified'],0)
            if workers==2:
                self.assertEqual(report['checks'][1]['order'],['index_prefetch_2','local_projection_keys'])

    def test_actual_hint_connection_rejects_writes_and_closes_with_publisher(self):
        import psycopg
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);keys=root/'keys';generate_keys(keys)
            with self.database(IndexPrefetchDB,root,keys) as db:
                name=db.conn.info.dbname;db.prepare_candidate()
                future=db._prefetch_pool.submit(lambda:db._reader().execute('CREATE TABLE forbidden_prefetch_write(n int)'))
                with self.assertRaises(psycopg.errors.ReadOnlySqlTransaction):future.result()
                job=corpus(root,(1,1,1))[0]
                result=publish_capture(db,job['path'],START,START+FIVE)
                self.assertEqual(result['status'],'PUBLISHED')
                self.assertLessEqual(db.prefetch_stats['max_pending_observed'],2)
                self.assertLessEqual(len(db._prefetch_connections),2)
                self.assertEqual(db.prefetch_stats['max_inflight_keys'],2*BATCH)
            active=self.admin.execute('SELECT COUNT(*) FROM pg_stat_activity WHERE datname=%s',(name,)).fetchone()[0]
            self.assertEqual(active,0)

    def test_timeout_and_expired_prefetch_budget_cannot_hide_or_drop_evidence(self):
        class Timeout(RuntimeError):sqlstate='57014'
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);keys=root/'keys';generate_keys(keys);jobs=corpus(root,(1,1,1));snapshots=[]
            for mode in ('original','timeout','deadline'):
                with self.database(LocalProjectionKeysDB if mode=='original' else IndexPrefetchDB,root,keys) as db:
                    db.prepare_candidate()
                    for job in jobs[:2]:
                        if mode=='timeout':
                            with patch.object(db,'_reader',side_effect=Timeout('private DSN/value must not be exported')):
                                publish_capture(db,job['path'],job['start'],job['start']+FIVE)
                        elif mode=='deadline':
                            with patch('viewer_performance.capacity.index_prefetch.DEADLINE_SECONDS',0):
                                publish_capture(db,job['path'],job['start'],job['start']+FIVE)
                        else:publish_capture(db,job['path'],job['start'],job['start']+FIVE)
                    snapshots.append(semantic_snapshot(db))
                    if mode=='timeout':
                        self.assertGreater(db.prefetch_stats['failures_total'],0)
                        self.assertNotIn('private DSN',str(db.candidate_report()))
                    if mode=='deadline':self.assertGreater(db.prefetch_stats['deadline_stops'],0)
            self.assertEqual(snapshots[0],snapshots[1]);self.assertEqual(snapshots[0],snapshots[2])

    def test_repeatable_read_keeps_future_uncommitted_publications_invisible(self):
        import psycopg
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);keys=root/'keys';generate_keys(keys);jobs=corpus(root,(1,1,1))
            with self.database(IndexPrefetchDB,root,keys) as db:
                publish_capture(db,jobs[0]['path'],START,START+FIVE);db.prepare_candidate()
                with psycopg.connect(**self.parameters,dbname=db.conn.info.dbname,autocommit=True) as reader:
                    reader.execute('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
                    def state():return reader.execute('SELECT (SELECT COUNT(*) FROM viewer_events),(SELECT generation FROM viewer_live_state WHERE id=1)').fetchone()
                    before=state();observed=[]
                    job=jobs[1]
                    publish_capture(db,job['path'],job['start'],job['start']+FIVE,
                        fault=lambda point:observed.append(state()) if point in ('after_requests','before_commit','after_commit') else None)
                    self.assertEqual(observed,[before]*3)
                    reader.execute('ROLLBACK');self.assertNotEqual(state(),before)

    def test_real_process_kill_during_prefetch_before_and_after_commit_then_restart(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);keys=root/'keys';generate_keys(keys);jobs=corpus(root,(1,1,1))
            for point,committed in (('prefetch',False),('before_commit',False),('after_commit',True)):
                with self.database(LocalProjectionKeysDB,root,keys) as db:
                    publish_capture(db,jobs[0]['path'],START,START+FIVE)
                    options=dict(config={**self.parameters,'dbname':db.conn.info.dbname,'options':'-c jit=off'},keys_path=keys)
                    job=jobs[1]
                    before=semantic_snapshot(db);db.conn.rollback()
                    child=multiprocessing.get_context('spawn').Process(target=killed_prefetch,
                        args=(options,job['path'],job['start'],point))
                    child.start();child.join(30)
                    if child.is_alive():child.kill();child.join();self.fail('prefetch child timed out')
                    self.assertEqual(child.exitcode,73)
                    self.assertEqual(before==semantic_snapshot(db),not committed);db.conn.rollback()
                    with IndexPrefetchDB(**options) as restart:
                        restart.prepare_candidate()
                        result=publish_capture(restart,job['path'],job['start'],job['start']+FIVE,
                            mode='recheck' if committed else 'forward')
                        self.assertEqual(result['new_events']==0,committed)


if __name__=='__main__':unittest.main()
