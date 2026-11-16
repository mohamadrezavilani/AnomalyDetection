"""C3 keeps exact temporary keys and all permanent/global validity checks."""
import multiprocessing
import os
from pathlib import Path
import tempfile
import unittest

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.viewer_online import publish_capture
from p24_foundation.viewer_origin_storage import qualify
from tests import test_viewer_contract_fetch_once as contract_tests
from viewer_performance.capacity.baseline import run,semantic_snapshot
from viewer_performance.capacity.contract_fetch_once import ContractFetchOnceDB
from viewer_performance.capacity.fixtures import corpus,START,FIVE
from viewer_performance.capacity.local_projection_keys import LocalProjectionKeysDB,exact_cached_keys


def killed_local_publication(options,path,start,point):
    with LocalProjectionKeysDB(**options) as db:
        db.prepare_candidate()
        publish_capture(db,path,start,start+FIVE,
            fault=lambda stage:os._exit(73) if stage==point else None)
    os._exit(74)


class LocalQueryContracts(unittest.TestCase):
    def test_only_local_comparisons_skip_binary_acceleration(self):
        clean=LocalProjectionKeysDB._single_version_origin_sql(cached=True)
        statement='''SELECT e.origin_key FROM viewer_projection_events e JOIN viewer_raw_events b
            ON b.origin_key=e.origin_key AND b.version_key=e.version_key WHERE '''+clean
        qualified=qualify(statement)
        self.assertNotIn('viewer_hmac_bytes_v1(v.',qualified)
        self.assertIn('viewer_hmac_bytes_v1(b.origin_key)',qualified)
        self.assertIn('viewer_hmac_bytes_v1(b.version_key)',qualified)
        self.assertIn('b.origin_key=e.origin_key',qualified)

    def test_uncached_global_probes_and_sql_shapes_are_unchanged(self):
        calls=[('_single_version_origin_sql',('e',),dict(indexed=True)),
            ('_global_conflict_predicate',(),dict(indexed=True)),
            ('_request_aggregate_sql',('viewer_events',),dict(scoped=True,indexed_conflict=True)),
            ('_request_roots_sql',('viewer_events',),dict(scoped=True,indexed_conflict=True)),
            ('_access_session_conflicts_sql',('viewer_events',),dict(scoped=True,indexed=True,compact=True))]
        for method,args,kwargs in calls:
            self.assertEqual(getattr(ViewerDB,method)(*args,**kwargs),
                getattr(LocalProjectionKeysDB,method)(*args,**kwargs))
        with self.assertRaisesRegex(ValueError,'query_shape_changed'):
            exact_cached_keys('unexpected query')

    def test_sqlite_cannot_be_misreported_as_exercising_native_local_keys(self):
        report=run(counts=(1,1,1),pairs=1,experiment='local_projection_keys')
        self.assertEqual(report['status'],'NOT_QUALIFIED_CANDIDATE_UNUSED')
        self.assertTrue(report['checks'][0]['all_equal'])
        self.assertFalse(report['candidate_exercised'])


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'isolated PG18 not configured')
class NativeLocalKeys(contract_tests.ContractChecks,unittest.TestCase):
    native=True
    setUpClass=classmethod(contract_tests.NativeContractFetchTests.setUpClass.__func__)
    tearDownClass=classmethod(contract_tests.NativeContractFetchTests.tearDownClass.__func__)

    def database(self,kind,root,keys):
        # Reuse the same independently owned DB allocator/oracle. Only the
        # candidate class changes; the original ViewerDB lane stays original.
        if kind is ContractFetchOnceDB:kind=LocalProjectionKeysDB
        return super().database(kind,root,keys)

    def test_full_boundaries_include_conflict_withdrawal_and_late_payment(self):
        report=run(backend='postgresql',counts=(2,3,4),pairs=2,
            experiment='local_projection_keys',wal_compression='zstd')
        self.assertEqual(report['status'],'PASS_CANDIDATE_EQUIVALENCE',report.get('failure'))
        self.assertEqual(report['comparison_baseline_variant'],'contract_fetch_once')
        self.assertEqual(report['checks'][1]['order'],['local_projection_keys','contract_fetch_once'])
        for lane in report['lanes']:
            self.assertGreater(lane['candidate_report']['fetch_once']['body_pair_lookups'],0)
            if lane['variant']=='local_projection_keys':
                self.assertGreater(lane['candidate_report']['local_projection_keys']['queries'],0)
            self.assertGreater(lane['windows'][-1]['semantic_states'].get('withdrawn',0),0)

    def test_full_text_keys_versions_and_unknown_rows_have_identical_truth_values(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);keys=root/'keys';generate_keys(keys)
            with self.database(ContractFetchOnceDB,root,keys) as db:
                db.sql('CREATE TEMP TABLE viewer_projection_versions(origin_key TEXT PRIMARY KEY,version_count BIGINT,only_version_key TEXT)')
                db.sql('CREATE TEMP TABLE viewer_projection_events(n INTEGER,origin_key TEXT,version_key TEXT)')
                prefix='a'*32
                origins=[(prefix+'1',1,'v1'),(prefix+'2',2,None),('Å',1,'v2'),('A\u030a',1,'v3'),('empty',0,None)]
                for values in origins:db.sql('INSERT INTO viewer_projection_versions VALUES(?,?,?)',values)
                events=[(prefix+'1','v1'),(prefix+'1','different'),(prefix+'2','v1'),
                    ('Å','v2'),('A\u030a','v2'),('A\u030a','v3'),('empty',None),('missing','v1'),(None,None)]
                for i,values in enumerate(events):db.sql('INSERT INTO viewer_projection_events VALUES(?,?,?)',(i,*values))
                results=[]
                for kind in (ViewerDB,LocalProjectionKeysDB):
                    clean=kind._single_version_origin_sql(cached=True)
                    conflict=kind._global_conflict_predicate(cached=True)
                    results.append(db.all('SELECT e.n,('+clean+') AS clean,('+conflict+') AS conflicted FROM viewer_projection_events e ORDER BY e.n'))
                self.assertEqual(*results)

    def test_nonunique_body_and_concurrent_reader_stay_equal_to_original(self):
        self.compare_missing(nonunique=True)
        contract_tests.NativeContractFetchTests.test_snapshot_reader_sees_only_committed_contract_and_window(self)

    def test_actual_process_kill_before_after_commit_reconciles_on_new_connection(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);keys=root/'keys';generate_keys(keys);jobs=corpus(root,(1,1,1))
            with self.database(ContractFetchOnceDB,root,keys) as db:
                publish_capture(db,jobs[0]['path'],START,START+FIVE)
                options=dict(config={**self.parameters,'dbname':db.conn.info.dbname,'options':'-c jit=off'},keys_path=keys)
                for point,job,committed in (('before_commit',jobs[1],False),('after_commit',jobs[2],True)):
                    before=semantic_snapshot(db);db.conn.rollback()
                    child=multiprocessing.get_context('spawn').Process(target=killed_local_publication,
                        args=(options,job['path'],job['start'],point))
                    child.start();child.join(30)
                    if child.is_alive():child.kill();child.join();self.fail('C3 child timed out')
                    self.assertEqual(child.exitcode,73)
                    self.assertEqual(before==semantic_snapshot(db),not committed);db.conn.rollback()
                    with LocalProjectionKeysDB(**options) as restarted:
                        restarted.prepare_candidate()
                        result=publish_capture(restarted,job['path'],job['start'],job['start']+FIVE,
                            mode='recheck' if committed else 'forward')
                        self.assertEqual(result['new_events']==0,committed)


if __name__=='__main__':unittest.main()
