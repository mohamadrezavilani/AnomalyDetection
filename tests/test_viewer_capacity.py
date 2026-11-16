"""Measurement attribution and unchanged per-boundary publisher results."""
from contextlib import contextmanager
from decimal import Decimal
import gzip
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from viewer_performance.capacity import counters
from viewer_performance.capacity.baseline import run
from viewer_performance.capacity.oracle import digest_table
from viewer_performance.capacity.trace import Trace, signature
from viewer_performance import Collect_Capacity_Inputs as inputs
from viewer_performance import Qualify_Capacity_Candidate as owner_qualification
from viewer_performance.capacity.fixtures import write,row,sql,START,FIVE,iso


class CapacityMeasurementTests(unittest.TestCase):
    def test_owner_connection_config_is_literal_and_never_executed(self):
        with tempfile.TemporaryDirectory() as folder:
            project=Path(folder)
            config=project/'viewer_config.local.py'
            config.write_text("raise RuntimeError('do not execute')\nDATABASE={'host':'127.0.0.1','port':5432,'dbname':'p24_design_viewer','user':'qualified','password':'private-test-password'}")
            result=owner_qualification.literal_database(project)
            self.assertEqual(result['user'],'qualified')
            with patch.dict(os.environ,{'PGPASSWORD':'prior-password'}):
                with owner_qualification.connection_environment(result):
                    self.assertEqual(os.environ['PGPASSWORD'],'private-test-password')
                self.assertEqual(os.environ['PGPASSWORD'],'prior-password')
            config.write_text("DATABASE=dict(host='127.0.0.1')")
            with self.assertRaisesRegex(ValueError,'literal_database_config'):
                owner_qualification.literal_database(project)

    def test_owner_bundle_checks_hashes_and_rejects_path_or_member_changes(self):
        with tempfile.TemporaryDirectory() as folder:
            project=Path(folder);capture_dir=project/'captures';capture_dir.mkdir()
            for i in range(4):write(capture_dir/f'window-{i}.gz',[],START+i*FIVE)
            with patch('p24_foundation.viewer_runtime.runtime_source_digest',return_value=inputs.EXPECTED_RUNTIME):
                bundle=Path(inputs.collect(project,capture_dir=capture_dir)['output'])
            target=project/'extracted';target.mkdir()
            paths=owner_qualification.extract_captures(bundle,target)
            self.assertEqual(len(paths),4)
            for path in paths:self.assertEqual(path.read_bytes(),(capture_dir/path.name).read_bytes())
            altered=project/'altered.zip'
            with zipfile.ZipFile(bundle) as source,zipfile.ZipFile(altered,'w') as output:
                for name in source.namelist():
                    output.writestr('../bad.gz' if name=='window-0.gz' else name,source.read(name))
            with self.assertRaisesRegex(ValueError,'bundle_path'):
                owner_qualification.extract_captures(altered,target)

    def test_owner_helper_never_opens_product_database_and_keeps_credentials_out_of_receipt(self):
        with tempfile.TemporaryDirectory() as folder:
            project=Path(folder);capture_dir=project/'captures';capture_dir.mkdir()
            for i in range(4):write(capture_dir/f'window-{i}.gz',[],START+i*FIVE)
            (project/'viewer_config.local.py').write_text("DATABASE={'host':'127.0.0.1','dbname':'p24_design_viewer','user':'qualified','password':'private-test-secret'}")
            with patch('p24_foundation.viewer_runtime.runtime_source_digest',return_value=inputs.EXPECTED_RUNTIME):
                bundle=Path(inputs.collect(project,capture_dir=capture_dir)['output'])
                with patch('viewer_performance.capacity.baseline.run',return_value=dict(status='PASS_CANDIDATE_EQUIVALENCE')) as run_mock,patch(
                        'p24_foundation.viewer_data.ViewerDB.__init__',side_effect=AssertionError('product opened')):
                    result=owner_qualification.qualify(project,bundle,pairs=1)
            self.assertFalse(result['product_database_opened'])
            self.assertEqual(run_mock.call_args.kwargs['wal_compression'],'zstd')
            self.assertNotIn('private-test-secret',Path(result['output']).read_text())

    def test_capture_selection_requires_four_contiguous_windows_and_keeps_newest_duplicate(self):
        rows=[dict(start_ns=i*inputs.FIVE,marker=str(i)) for i in (6,5,4,2,1,0)]
        self.assertEqual(inputs.select_run(rows),[])
        rows.append(dict(start_ns=3*inputs.FIVE,marker='3'))
        self.assertEqual([r['marker'] for r in inputs.select_run(rows)],['3','4','5','6'])

    def test_private_config_is_parsed_without_executing_code(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'viewer_config.local.py').write_text("raise RuntimeError('must not run')\nLIVE={'capture_dir':'captures'}\n")
            self.assertEqual(inputs.capture_directory(root),(root/'captures').resolve())
            (root/'viewer_config.local.py').write_text("LIVE=dict(capture_dir='other')")
            with self.assertRaisesRegex(ValueError,'explicit_argument'):
                inputs.capture_directory(root)

    def test_collector_preserves_original_capture_bytes_and_names_without_opening_a_database(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);captures=root/'captures';captures.mkdir()
            originals={}
            for i in range(4):
                path=write(captures/f'original-{i}.json.gz',[],START+i*FIVE)
                originals[path.name]=path.read_bytes()
            with patch('p24_foundation.viewer_runtime.runtime_source_digest',return_value=inputs.EXPECTED_RUNTIME),patch(
                    'p24_foundation.viewer_data.ViewerDB.__init__',side_effect=AssertionError('DB access forbidden')):
                result=inputs.collect(root,capture_dir=captures)
            self.assertEqual(result['status'],'VERIFIED_CAPACITY_INPUTS_EXPORTED')
            with zipfile.ZipFile(result['output']) as archive:
                for name,content in originals.items():self.assertEqual(archive.read(name),content)
                manifest=json.loads(archive.read('manifest.json'))
                self.assertFalse(manifest['database_modified'])
                self.assertEqual(len(manifest['captures']),4)

    def test_collector_rejects_complete_flag_without_capture_proof(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for i in range(4):
                path=write(root/f'raw-{i}.gz',[],START+i*FIVE)
                with gzip.open(path,'wt') as stream:
                    json.dump({'complete':True,'count':0,'logs':[],
                        'window_start':iso(START+i*FIVE),
                        'window_end':iso(START+(i+1)*FIVE)},stream)
            with patch('p24_foundation.viewer_runtime.runtime_source_digest',return_value=inputs.EXPECTED_RUNTIME):
                with self.assertRaisesRegex(ValueError,'four_contiguous_verified'):
                    inputs.collect(root,capture_dir=root)

    def test_nested_times_are_exclusive_and_restore_stack_after_failure(self):
        ticks=iter([0,10,40,100])
        trace=Trace(clock=lambda:next(ticks),cpu=lambda:0)
        with self.assertRaisesRegex(RuntimeError,'injected'):
            with trace.span('parent'):
                with trace.span('child'):
                    raise RuntimeError('injected')
        self.assertEqual(trace.spans['parent']['inclusive_ns'],100)
        self.assertEqual(trace.spans['parent']['exclusive_ns'],70)
        self.assertEqual(trace.spans['child']['exclusive_ns'],30)
        self.assertEqual(trace.spans['parent']['failures'],1)
        self.assertEqual(trace.stack,[])

    def test_statement_values_never_leave_fingerprint_metadata(self):
        a=signature("SELECT * FROM viewer_events WHERE request_key='private-request' AND at_ns=123")
        b=signature("SELECT * FROM viewer_events WHERE request_key='other-request' AND at_ns=456")
        self.assertEqual(a,b)
        self.assertNotIn('private-request',str(a))

    def test_backend_epoch_changes_and_counter_resets_are_not_deltas(self):
        a=dict(identity={'pid':1},io=[],wal={'stats_reset':'one','wal_bytes':Decimal(10)})
        b=dict(identity={'pid':2},io=[],wal={'stats_reset':'one','wal_bytes':Decimal(20)})
        self.assertEqual(counters.delta(a,b)['status'],'BACKEND_CHANGED')
        b['identity']=a['identity'];b['wal']['stats_reset']='two'
        self.assertEqual(counters.delta(a,b)['wal']['status'],'COUNTERS_RESET')
        b['wal'].update(stats_reset='one',wal_bytes=Decimal(9))
        self.assertEqual(counters.delta(a,b)['wal']['status'],'COUNTERS_REGRESSED')
        b['wal']['wal_bytes']=Decimal(15)
        out=counters.delta(a,b)
        self.assertEqual(out['wal']['values']['wal_bytes'],5)
        json.dumps(out)  # PG exposes WAL bytes as NUMERIC/Decimal.
        self.assertFalse(out['includes_background_writer_or_other_sessions'])
        self.assertFalse(out['exact_window_attribution'])

    def test_oracle_orders_full_rows_including_ties_and_retains_duplicates(self):
        class DB:
            def __init__(self):
                self.conn=sqlite3.connect(':memory:');self.conn.row_factory=sqlite3.Row
            def sql(self,q):return self.conn.execute(q)
        db=DB();self.addCleanup(db.conn.close)
        db.sql('CREATE TABLE fixture(a TEXT,b TEXT,c TEXT)')
        db.conn.executemany('INSERT INTO fixture VALUES(?,?,?)',[('x','y','b'),('x','y','a')])
        before=digest_table(db,'fixture','*')
        db.sql('DELETE FROM fixture')
        db.conn.executemany('INSERT INTO fixture VALUES(?,?,?)',[('x','y','a'),('x','y','b')])
        self.assertEqual(before,digest_table(db,'fixture','*'))
        db.conn.execute('INSERT INTO fixture VALUES(?,?,?)',('x','y','a'))
        self.assertNotEqual(before,digest_table(db,'fixture','*'))

    def test_profiled_sqlite_keeps_every_boundary_including_late_payment_and_conflict(self):
        report=run(counts=(2,3,4),pairs=2)
        self.assertEqual(report['status'],'PASS_MEASUREMENT_EQUIVALENCE',report.get('failure'))
        self.assertTrue(all(check['all_equal'] for check in report['checks']))
        self.assertEqual(report['checks'][1]['order'],['profiled','plain'])
        lanes=[lane for lane in report['lanes'] if lane['profiled']]
        for lane in lanes:
            self.assertEqual(lane['windows'][0]['trace']['spans']['driver:commit']['calls'],1)
            self.assertGreater(lane['windows'][1]['impacted_requests'],3)
            self.assertEqual(lane['windows'][1]['mode'],'manual_recheck')
            self.assertEqual(lane['windows'][2]['mode'],'manual_recheck')
            self.assertEqual(lane['windows'][1]['oracle']['checkpoint']['next_ns'],
                lane['windows'][2]['oracle']['checkpoint']['next_ns'])
            self.assertEqual(lane['windows'][-1]['kind'],'late_arrival_original_event_time')
            self.assertGreater(lane['windows'][-1]['oracle']['viewer_semantic_transitions']['rows'],0)
        self.assertEqual(report['owner_host_capacity'],'NOT_RUN')
        self.assertEqual(report['cache_pressure_qualification'],'NOT_RUN')

    def test_trace_rejects_product_database_before_replacing_connection(self):
        class Info:dbname='p24_design_viewer'
        class Raw:info=Info()
        class DB:sqlite=False;conn=Raw()
        db=DB();before=db.conn
        with self.assertRaisesRegex(ValueError,'qualification_database'):
            Trace().attach(db)
        self.assertIs(db.conn,before)


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'isolated PG18 not configured')
class NativeCapacityTests(unittest.TestCase):
    def test_owner_helper_compares_private_bundle_without_opening_product_database(self):
        import psycopg
        with tempfile.TemporaryDirectory() as folder:
            project=Path(folder);captures=project/'captures';captures.mkdir()
            config=dict(host=os.environ['P24_DELTA_PG_HOST'],
                port=int(os.environ.get('P24_DELTA_PG_PORT','5432')),
                user=os.environ.get('P24_DELTA_PG_USER','postgres'),
                password=os.environ.get('PGPASSWORD'),dbname='p24_design_viewer')
            (project/'viewer_config.local.py').write_text('DATABASE='+repr(config))
            for i in range(4):
                event=row(i,'r'+str(i),'DBPath.x.ud_prc_paymentExists',sql('K'+str(i)),START+i*FIVE)
                write(captures/f'window-{i}.gz',[event],START+i*FIVE)
            opened=[];connect=psycopg.connect
            def recorded(*args,**kwargs):
                opened.append(kwargs.get('dbname'));return connect(*args,**kwargs)
            with patch('p24_foundation.viewer_runtime.runtime_source_digest',return_value=inputs.EXPECTED_RUNTIME):
                bundle=Path(inputs.collect(project,capture_dir=captures)['output'])
                with patch('psycopg.connect',side_effect=recorded):
                    result=owner_qualification.qualify(project,bundle,pairs=1)
            self.assertEqual(result['status'],'PASS_CANDIDATE_EQUIVALENCE',result.get('failure'))
            self.assertTrue(opened)
            self.assertTrue(all(name=='postgres' or
                name.startswith('p24_design_capacity_') and name.endswith('_qualification') for name in opened))
            self.assertFalse(result['product_database_opened'])

    def test_native_copy_fetch_commit_counters_and_per_boundary_equivalence(self):
        with tempfile.TemporaryDirectory() as folder:
            output=Path(folder)/'native.json'
            report=run(backend='postgresql',counts=(4,8,16),pairs=2,out=output)
            self.assertEqual(json.loads(output.read_text())['status'],report['status'])
        self.assertEqual(report['status'],'PASS_MEASUREMENT_EQUIVALENCE',report.get('failure'))
        self.assertTrue(all(check['all_equal'] for check in report['checks']))
        for lane in report['lanes']:
            if not lane['profiled']:continue
            for window in lane['windows']:
                self.assertEqual(len(window['transaction_counters']),1)
                self.assertEqual(window['backend_counters']['scope'],'one_backend')
                self.assertIn('driver:copy',window['trace']['spans'])
                self.assertEqual(window['trace']['spans']['driver:commit']['calls'],1)


if __name__=='__main__':unittest.main()
