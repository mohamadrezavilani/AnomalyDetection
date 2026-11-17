"""Explicit writer factory, identity fence, per-boundary parity and recovery."""
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.viewer_online import publish_capture
from viewer_performance.fast_writer import (FastWriterDB, FencedConnection, FastWriterHalt,
    activate, verify_sources, ROOT, MANIFEST, BASE_RUNTIME)
from viewer_performance.capacity.baseline import run_lane, semantic_snapshot
from viewer_performance.capacity.fixtures import corpus, START, FIVE
from tests import test_viewer_contract_fetch_once as native_tests


def killed_fast(options, path, start, point):
    with FastWriterDB(**options) as db:
        publish_capture(db, path, start, start+FIVE,
            fault=lambda stage: os._exit(73) if stage==point else None)
    os._exit(74)


class FastWriterContracts(unittest.TestCase):
    def test_exact_manifest_and_canonical_source_contract(self):
        manifest = json.loads((ROOT/MANIFEST).read_text())
        self.assertEqual(verify_sources(), manifest['source_sha256'])
        self.assertEqual(manifest['base_runtime_source_sha256'], BASE_RUNTIME)

    def test_altered_paired_source_cannot_pass_the_profile_fence(self):
        manifest = json.loads((ROOT/MANIFEST).read_text())
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in (*manifest['files_sha256'], MANIFEST):
                path = root/name
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT/name, path)
            changed = root/'viewer_performance/capacity/local_projection_keys.py'
            changed.write_bytes(changed.read_bytes()+b'\n# changed profile\n')
            with self.assertRaisesRegex(ValueError, 'fast_writer_source_changed'):
                verify_sources(root)

    def test_wrong_database_or_remote_server_never_opens_a_connection(self):
        with patch('psycopg.connect', side_effect=AssertionError('unexpected connect')):
            for name in ('application', 'p24_design_unallocated', 'postgres'):
                with self.assertRaisesRegex(ValueError, 'database_not_allowed'):
                    FastWriterDB(config=dict(dbname=name), keys_path='missing')
            with self.assertRaisesRegex(ValueError, 'requires_local_server'):
                FastWriterDB(config=dict(dbname='p24_design_viewer',host='example.invalid'),keys_path='missing')
            with self.assertRaisesRegex(ValueError, 'requires_native'):
                FastWriterDB(sqlite_path='missing',keys_path='missing')

    def test_factory_activation_restores_every_alias_even_after_failure(self):
        from p24_foundation import viewer_data
        from tools import run_behavior_viewer as runner
        self.assertIs(viewer_data.ViewerDB, ViewerDB)
        with self.assertRaisesRegex(RuntimeError, 'test-stop'):
            with activate():
                self.assertIs(viewer_data.ViewerDB, FastWriterDB)
                self.assertIs(runner.ViewerDB, FastWriterDB)
                raise RuntimeError('test-stop')
        self.assertIs(viewer_data.ViewerDB, ViewerDB)
        self.assertIs(runner.ViewerDB, ViewerDB)

    def test_fence_failure_is_not_caught_by_existing_exception_retry_loops(self):
        self.assertFalse(issubclass(FastWriterHalt, Exception))
        class Connection:
            commits=0
            def commit(self):self.commits+=1
        raw=Connection()
        def halt():raise FastWriterHalt()
        proxy=FencedConnection(raw,halt)
        with self.assertRaises(FastWriterHalt):proxy.commit()
        self.assertEqual(raw.commits,0)
        proxy=FencedConnection(raw,lambda:None)
        proxy.commit();self.assertEqual(raw.commits,1)
        proxy.autocommit=True;self.assertTrue(raw.autocommit)

    def test_launcher_requires_an_explicit_trial_before_importing_a_database(self):
        result=subprocess.run([sys.executable,'-B',str(ROOT/'viewer_performance/Run_Viewer_Fast.py')],
            capture_output=True,text=True)
        self.assertEqual(result.returncode,2)
        self.assertEqual(json.loads(result.stdout)['code'],'fast_writer_requires_explicit_trial')
        result=subprocess.run([sys.executable,'-B',str(ROOT/'viewer_performance/Run_Viewer_Fast.py'),'--help'],
            cwd=tempfile.gettempdir(),capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'native PG18 not configured')
class NativeFastWriterTests(unittest.TestCase):
    native=True
    setUpClass=classmethod(native_tests.NativeContractFetchTests.setUpClass.__func__)
    tearDownClass=classmethod(native_tests.NativeContractFetchTests.tearDownClass.__func__)
    database=native_tests.ContractChecks.database

    def test_every_boundary_matches_canonical_including_late_payment_and_conflict(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);keys=root/'keys';generate_keys(keys);jobs=corpus(root,(2,3,4))
            lanes=[]
            for kind in (ViewerDB,FastWriterDB):
                with self.database(kind,root,keys) as db:
                    db.sql('UPDATE viewer_live_state SET stream_key=? WHERE id=1',('capacity-fixed-corpus',))
                    db.conn.commit()
                    options=dict(config={**self.parameters,'dbname':db.conn.info.dbname,'options':'-c jit=off'},keys_path=keys)
                    lanes.append(run_lane(options,jobs,profiled=True,history=True,db_type=kind))
            self.assertEqual([w['oracle'] for w in lanes[0]['windows']],
                             [w['oracle'] for w in lanes[1]['windows']])
            report=lanes[1]['candidate_report']
            self.assertGreater(report['fetch_once']['returned_bodies'],0)
            self.assertGreater(report['local_projection_keys']['queries'],0)

    def test_manifest_change_before_commit_rolls_back_and_same_cursor_can_resume(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);keys=root/'keys';generate_keys(keys);jobs=corpus(root,(1,1,1))
            with self.database(FastWriterDB,root,keys) as db:
                publish_capture(db,jobs[0]['path'],START,START+FIVE)
                before=semantic_snapshot(db);db.conn.rollback()
                job=jobs[1]
                def change(stage):
                    if stage=='before_commit':
                        db.fast_source_sha256='changed-release'
                with self.assertRaises(FastWriterHalt):
                    publish_capture(db,job['path'],job['start'],job['start']+FIVE,fault=change)
                self.assertEqual(before,semantic_snapshot(db));db.conn.rollback()
                db.fast_source_sha256=verify_sources()
                self.assertEqual(publish_capture(db,job['path'],job['start'],job['start']+FIVE)['status'],'PUBLISHED')

    def test_real_kill_before_after_commit_then_rollback_to_canonical_writer(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);keys=root/'keys';generate_keys(keys);jobs=corpus(root,(1,1,1))
            for point,committed in (('before_commit',False),('after_commit',True)):
                with self.database(ViewerDB,root,keys) as db:
                    publish_capture(db,jobs[0]['path'],START,START+FIVE)
                    before=semantic_snapshot(db);db.conn.rollback()
                    options=dict(config={**self.parameters,'dbname':db.conn.info.dbname,'options':'-c jit=off'},keys_path=keys)
                    job=jobs[1]
                    child=multiprocessing.get_context('spawn').Process(target=killed_fast,
                        args=(options,job['path'],job['start'],point))
                    child.start();child.join(30)
                    if child.is_alive():child.kill();child.join();self.fail('fast writer kill timed out')
                    self.assertEqual(child.exitcode,73)
                    self.assertEqual(before==semantic_snapshot(db),not committed);db.conn.rollback()
                    # Data/cursors produced by the opt-in writer remain usable
                    # by the actual old factory, without a data conversion.
                    result=publish_capture(db,job['path'],job['start'],job['start']+FIVE,
                        mode='manual_recheck' if committed else 'forward')
                    self.assertEqual(result['status'],'PUBLISHED')
                    self.assertEqual(result['new_events']==0,committed)

    def test_repeatable_read_never_sees_a_partial_fast_publication(self):
        import psycopg
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);keys=root/'keys';generate_keys(keys);jobs=corpus(root,(1,1,1))
            with self.database(FastWriterDB,root,keys) as db:
                publish_capture(db,jobs[0]['path'],START,START+FIVE)
                with psycopg.connect(**self.parameters,dbname=db.conn.info.dbname,autocommit=True) as reader:
                    reader.execute('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
                    def state():return reader.execute('SELECT (SELECT COUNT(*) FROM viewer_events),(SELECT generation FROM viewer_live_state WHERE id=1)').fetchone()
                    before=state();observed=[]
                    job=jobs[1]
                    publish_capture(db,job['path'],job['start'],job['start']+FIVE,
                        fault=lambda point:observed.append(state()) if point in ('after_requests','before_commit','after_commit') else None)
                    self.assertEqual(observed,[before]*3)
                    reader.execute('ROLLBACK');self.assertNotEqual(state(),before)

    def test_empty_missing_and_nonunique_body_batches_keep_the_canonical_rules(self):
        from viewer_performance.capacity.contract_fetch_once import ContractFetchOnceDB
        def database(kind,root,keys):
            return native_tests.ContractChecks.database(self,
                FastWriterDB if kind is ContractFetchOnceDB else kind,root,keys)
        with patch.object(self,'database',side_effect=database):
            native_tests.ContractChecks.compare_missing(self)
            native_tests.ContractChecks.compare_missing(self,empty_first_batch=True)
            native_tests.ContractChecks.compare_missing(self,nonunique=True)

    def test_owner_qualifier_opens_only_admin_and_its_fresh_databases(self):
        import hashlib
        import psycopg
        from viewer_performance.capacity.fixtures import write,row,sql
        from viewer_performance.Qualify_Viewer_Fast import qualify
        connects=[];connect=psycopg.connect
        def observed_connect(*args,**kwargs):
            connects.append(kwargs.get('dbname'))
            self.assertNotEqual(kwargs.get('dbname'),'p24_design_viewer')
            return connect(*args,**kwargs)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);items=[];bundle=root/'captures.zip'
            with zipfile.ZipFile(bundle,'w') as archive:
                for index in range(4):
                    at=START+index*FIVE
                    records=[row(index*3,'r'+str(index),'Services.v1/WaterBills Line:1','POST (G00000 | successful)',at),
                        row(index*3+1,'r'+str(index),'DBPath.x.ud_prc_paymentExists',sql('p'+str(index)),at)]
                    path=write(root/f'window-{index}.gz',records,at)
                    items.append(dict(archive_name=path.name,sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
                    archive.write(path,path.name)
                archive.writestr('manifest.json',json.dumps(dict(runtime_source_sha256=BASE_RUNTIME,captures=items)))
            config=dict(self.parameters,dbname='p24_design_viewer')
            with patch('viewer_performance.Qualify_Capacity_Candidate.literal_database',return_value=config),patch(
                    'psycopg.connect',side_effect=observed_connect):
                result=qualify(ROOT,bundle,pairs=1)
            receipt=Path(result['output'])
            try:
                self.assertEqual(result['status'],'PASS_FAST_EQUIVALENCE',result.get('failure'))
                full=json.loads(receipt.read_text())
                self.assertEqual(full['cleanup'],dict(allocated=2,dropped=2,failures=[]))
                self.assertEqual(full['checks'][0]['every_publication_equal'],[True]*4)
                self.assertFalse(full['product_database_opened'])
                self.assertTrue(all(name=='postgres' or name.startswith('p24_design_capacity_')
                    and name.endswith('_qualification') for name in connects))
            finally:receipt.unlink()


if __name__=='__main__':unittest.main()
