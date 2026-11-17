"""Isolated scope variants: retained contracts, explicit omissions and recovery."""
from contextlib import contextmanager
import multiprocessing
import os
import subprocess
import sys
import shutil
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_online import initialize_live,bind_stream
from viewer_performance.capacity.fixtures import START,FIVE
from viewer_performance.financial_screen.fixtures import corpus
from viewer_performance.capacity.oracle import EVIDENCE,PROJECTIONS,digest_table
from viewer_performance.financial_screen.contracts import coverage,consumer_gate
from viewer_performance.financial_screen.modes import ScreenDB,publisher,request_prefix,role_reader
from p24_foundation.viewer_data import ViewerDB
from tests import test_viewer_contract_fetch_once as native_helpers


def retained(db,mode):
    tables={table:'*' for table in EVIDENCE if mode!='D' or table!='viewer_links'}
    if mode!='D':tables['viewer_requests']='*'
    if mode in ('A','C'):
        tables.update({t:c for t,c in PROJECTIONS.items() if t.startswith('viewer_contract_') or t.startswith('viewer_semantic_')})
    return {table:digest_table(db,table,columns) for table,columns in tables.items()}


def die(options,path,start,point):
    with ScreenDB(**options) as db:
        publisher(db)(path,start,start+FIVE,fault=lambda stage:os._exit(73) if stage==point else None)
    os._exit(74)


class FinancialScreenContracts(unittest.TestCase):
    def test_only_allocated_namespace_and_known_mode_before_connect(self):
        with patch('psycopg.connect',side_effect=AssertionError('unexpected connection')):
            for name in ('p24_design_viewer','postgres','p24_design_capacity_old_qualification'):
                with self.assertRaisesRegex(ValueError,'requires_new_owned_database'):
                    ScreenDB(config=dict(dbname=name),keys_path='absent')
            with self.assertRaisesRegex(ValueError,'unknown_financial_screen_mode'):
                ScreenDB(mode='X',config=dict(dbname='p24_design_capacity_fs_test_qualification'),keys_path='absent')

    def test_missing_outputs_cannot_be_certified_complete(self):
        for mode in ('B1','B2','D'):
            with self.assertRaisesRegex(ValueError,'OUTPUT_NOT_EVALUATED'):
                consumer_gate(coverage(mode),'typed_payment_graph')
        for mode in ('A','B1','B2','C','D'):
            with self.assertRaisesRegex(ValueError,'OUTPUT_NOT_EVALUATED'):
                consumer_gate(coverage(mode),'financial_detectors')
        consumer_gate(coverage('C'),'canonical_executions')

    def test_request_and_semantic_extractors_are_source_specific(self):
        self.assertTrue(callable(request_prefix()))
        self.assertTrue(callable(role_reader(ViewerDB._read_semantic_batch)))
        self.assertTrue(callable(role_reader(ViewerDB._semantic_bootstrap_batches)))

    def test_entrypoint_help_has_no_database_or_maintenance_side_effect(self):
        root=Path(__file__).resolve().parents[1]
        result=subprocess.run([sys.executable,'-B',str(root/'viewer_performance/Screen_Financial_Product.py'),'--help'],
            cwd=tempfile.gettempdir(),capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('--exclusive-run',result.stdout)

    def test_current_process_cpu_memory_is_observable(self):
        from viewer_performance.financial_screen.resources import process_usage,available_memory
        row=process_usage(os.getpid())
        self.assertEqual(row['status'],'READ')
        self.assertGreater(row['rss_bytes'],0)
        self.assertGreater(available_memory(),0)

    @unittest.skipUnless(os.name=='nt','Windows PowerShell parser only')
    def test_powershell_entrypoint_parses_without_execution(self):
        from viewer_performance.financial_screen.host import powershell
        path=Path(__file__).resolve().parents[1]/'viewer_performance/Invoke_Financial_Screen.ps1'
        value=powershell("$tokens=$null;$errors=$null;[void][System.Management.Automation.Language.Parser]::ParseFile($env:P24_SCREEN_PARSE_FILE,[ref]$tokens,[ref]$errors); @{errors=@($errors).Count}|ConvertTo-Json -Compress",
            {'P24_SCREEN_PARSE_FILE':str(path)})
        self.assertEqual(value['errors'],0)

    @unittest.skipUnless(os.name=='nt','Windows PowerShell 5.1 invocation only')
    def test_powershell_saved_launcher_defaults_from_unrelated_directory(self):
        # Execute the actual saved .ps1 with no -Project or -Python. A stub
        # Python target records the handoff; no product code/DB is invoked.
        source=Path(__file__).resolve().parents[1]/'viewer_performance/Invoke_Financial_Screen.ps1'
        with tempfile.TemporaryDirectory(prefix='financial launcher ') as folder:
            project=Path(folder)/'project with spaces';tools=project/'viewer_performance';tools.mkdir(parents=True)
            unrelated=Path(folder)/'different working directory';unrelated.mkdir()
            launcher=tools/source.name;shutil.copyfile(source,launcher)
            (tools/'Screen_Financial_Product.py').write_text(
                'import json,sys\nprint(json.dumps(dict(arguments=sys.argv[1:],python=sys.executable)))\n',encoding='utf-8')
            created=subprocess.run([sys.executable,'-m','venv','--without-pip',str(project/'.venv')],
                capture_output=True,text=True,timeout=60)
            self.assertEqual(created.returncode,0,created.stderr)
            result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
                '-File',str(launcher)],cwd=unrelated,capture_output=True,text=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr)
            record=json.loads(result.stdout);arguments=record['arguments']
            self.assertEqual(Path(arguments[arguments.index('--project')+1]).resolve(),project.resolve())
            self.assertEqual(Path(record['python']).resolve(),(project/'.venv/Scripts/python.exe').resolve())
            self.assertIn('--preflight',arguments)
            self.assertNotIn('--exclusive-run',arguments)

    @unittest.skipUnless(os.name=='nt','Windows PowerShell 5.1 invocation only')
    def test_powershell_saved_launcher_forwards_explicit_options_and_failure(self):
        source=Path(__file__).resolve().parents[1]/'viewer_performance/Invoke_Financial_Screen.ps1'
        with tempfile.TemporaryDirectory(prefix='financial launcher ') as folder:
            root=Path(folder);launcher=root/source.name;shutil.copyfile(source,launcher)
            project=root/'explicit project';tools=project/'viewer_performance';tools.mkdir(parents=True)
            (tools/'Screen_Financial_Product.py').write_text(
                'import json,sys\nprint(json.dumps(dict(status="PREFLIGHT_BLOCKED",arguments=sys.argv[1:])))\nsys.exit(2)\n',encoding='utf-8')
            bundle=root/'capture archive.zip';bundle.write_bytes(b'test placeholder, never opened by the stub')
            result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
                '-File',str(launcher),'-Project',str(project),'-Python',sys.executable,'-Run',
                '-CapturesZip',str(bundle),'-MaxSeconds','37','-Counts','1,2,3','-HistoryRequests','0,16'],
                cwd=root,capture_output=True,text=True,timeout=30)
            self.assertNotEqual(result.returncode,0)
            record=json.loads(result.stdout);arguments=record['arguments']
            self.assertIn('--exclusive-run',arguments);self.assertNotIn('--preflight',arguments)
            for name,expected in (('--counts','1,2,3'),('--history-requests','0,16'),('--max-seconds','37')):
                self.assertEqual(arguments[arguments.index(name)+1],expected)
            self.assertEqual(Path(arguments[arguments.index('--captures-zip')+1]).resolve(),bundle.resolve())
            self.assertIn('Screen blocked or incomplete',result.stderr)

    def test_unknown_frontend_service_observer_and_running_task_block_before_stop(self):
        from viewer_performance.financial_screen.host import make_plan
        snapshot=dict(processes=[dict(ProcessId=1234,CommandLine='python Observe_Viewer_Fast.py')],
            listeners=[dict(OwningProcess=5678)],services=[dict(Name='watchdog',State='Running',StartMode='Auto')],
            tasks=[dict(Name='relauncher',State='Running',Enabled=True)])
        plan=make_plan(Path('X:/project'),snapshot,{},dict(status='NO_VIEWER_LOCK_OWNER_OBSERVED'),
            dict(status='NO_VIEWER_WEB_LISTENER'),None)
        self.assertTrue(any('FRONTEND' in issue for issue in plan['issues']))
        self.assertTrue(any('SERVICE' in issue for issue in plan['issues']))
        self.assertTrue(any('SCHEDULED_TASK' in issue for issue in plan['issues']))
        self.assertTrue(any('UNCONTROLLED_PROJECT_PROCESS' in issue for issue in plan['issues']))

    def test_failed_experiment_restores_previously_active_roles_in_finally(self):
        from viewer_performance.financial_screen import host
        from unittest.mock import MagicMock
        events=[];fake=MagicMock();fake.execute.return_value.fetchone.return_value={'held':True}
        plan=dict(active=dict(ad_worker=True,ad_web=True,viewer=True,viewer_web=True),
            viewer_restart=['fast'],viewer_web_restart=['web'],ad_worker_restart=['ad','start'],ad_web_restart=['ad','web'],task_restore=[])
        before=dict(status='PREFLIGHT_READY',restore_plan=plan)
        def command(*args):
            if args[1]=='ad':events.append('ad-restored');return dict(status='STARTED'),0
            return dict(status='NO_VIEWER_LOCK_OWNER_OBSERVED' if 'Worker' in args[1] else 'NO_VIEWER_WEB_LISTENER'),0
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(host,'product_reader',return_value=fake),patch.object(host,'cursors',return_value={}),\
                 patch.object(host,'stop_role',side_effect=lambda project,role:events.append('stop-'+role) or {}),\
                 patch.object(host,'command',side_effect=command),patch.object(host,'assert_idle'),\
                 patch.object(host,'inventory',return_value=dict(processes=[],tasks=[],services=[],listeners=[])),\
                 patch('psycopg.connect',return_value=MagicMock()),patch.object(host,'parameters',return_value={}),\
                 patch.object(host,'start_process',side_effect=lambda project,args,logs,role:events.append('restore-'+role) or 1),\
                 patch.object(host,'verify_restore',return_value={'verified':True}):
                with self.assertRaisesRegex(RuntimeError,'injected'):
                    with host.maintenance(Path(folder),before,Path(folder)) as state:raise RuntimeError('injected')
                self.assertEqual(state['status'],'PREVIOUS_ROLES_RESTORED')
                self.assertEqual(events,['stop-ad','stop-viewer','stop-web','restore-viewer_web','ad-restored','restore-viewer'])

    def test_no_previous_roles_no_unrequested_restart(self):
        from viewer_performance.financial_screen import host
        from unittest.mock import MagicMock
        before=dict(status='PREFLIGHT_READY',restore_plan=dict(active=dict.fromkeys(('ad_worker','ad_web','viewer','viewer_web'),False),task_restore=[]))
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(host,'product_reader',return_value=MagicMock()),patch.object(host,'cursors',return_value={}),\
                 patch.object(host,'assert_idle'),patch('psycopg.connect',return_value=MagicMock()),patch.object(host,'parameters',return_value={}),\
                 patch.object(host,'inventory',return_value=dict(processes=[],tasks=[],services=[],listeners=[])),\
                 patch.object(host,'verify_restore',return_value={}),patch.object(host,'start_process') as start:
                with host.maintenance(Path(folder),before,Path(folder)):pass
                start.assert_not_called()


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'isolated PG18 not configured')
class NativeFinancialScreen(unittest.TestCase):
    setUpClass=classmethod(native_helpers.NativeContractFetchTests.setUpClass.__func__)
    tearDownClass=classmethod(native_helpers.NativeContractFetchTests.tearDownClass.__func__)

    @contextmanager
    def database(self,root,keys,mode,kind=ScreenDB):
        name='p24_design_capacity_fs_'+uuid.uuid4().hex[:12]+'_qualification'
        self.admin.execute(self.pgsql.SQL('CREATE DATABASE {}').format(self.pgsql.Identifier(name)))
        options=dict(config={**self.parameters,'dbname':name,'options':'-c jit=off'},keys_path=keys)
        if kind is ScreenDB:options['mode']=mode
        try:
            with kind(**options) as db:
                db.init();initialize_live(db);bind_stream(db,start_ns=START,stream_key='scope-screen-tests')
                yield db,options
        finally:self.admin.execute(self.pgsql.SQL('DROP DATABASE {}').format(self.pgsql.Identifier(name)))

    def test_A_is_the_full_unchanged_viewer_reference(self):
        from viewer_performance.fast_writer import FastWriterDB
        from viewer_performance.financial_screen.experiment import retained_snapshot
        from p24_foundation.viewer_online import publish_capture
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);keys=root/'keys';generate_keys(keys);jobs=corpus(root,(1,1,1));snapshots=[]
            for kind in (FastWriterDB,ScreenDB):
                with self.database(root,keys,'A',kind) as (db,_):
                    values=[]
                    for job in jobs:
                        if kind is ScreenDB:publisher(db)(job['path'],job['start'],job['start']+FIVE,mode=job['mode'])
                        else:publish_capture(db,job['path'],job['start'],job['start']+FIVE,mode=job['mode'])
                        values.append(retained_snapshot(db,'A'));db.conn.rollback()
                    snapshots.append(values)
            self.assertEqual(*snapshots)

    def test_retained_contract_at_every_boundary_including_late_and_conflicting_owner(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);keys=root/'keys';generate_keys(keys);jobs=corpus(root,(2,3,4))
            reference=[]
            for mode in ('A','B1','B2','C','D'):
                with self.database(root,keys,mode) as (db,_):
                    for ordinal,job in enumerate(jobs):
                        result=publisher(db)(job['path'],job['start'],job['start']+FIVE,mode=job['mode'])
                        actual=retained(db,mode)
                        if mode=='A':reference.append(actual)
                        else:self.assertEqual(actual,{t:reference[ordinal][t] for t in actual},(mode,ordinal))
                        self.assertFalse(result['full_analysis_ready'])
                        self.assertEqual(db.one('SELECT worker_status FROM viewer_live_state WHERE id=1')['worker_status'],'SCOPE_SCREEN_ONLY')
                        if mode in ('C','D'):
                            self.assertEqual(db.one('SELECT COUNT(*) AS n FROM viewer_actions')['n'],0)
                        db.conn.rollback()
                    if mode=='B1':self.assertGreater(db.screen_counts['closure_output_requests'],0)
                    if mode=='D':self.assertGreater(db.screen_counts['omitted_link_rows'],0)

    def test_real_kill_c_before_and_after_commit_retains_cursor_and_can_resume(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);keys=root/'keys';generate_keys(keys);jobs=corpus(root,(1,1,1))
            for point,committed in (('before_commit',False),('after_commit',True)):
                with self.database(root,keys,'C') as (db,options):
                    publisher(db)(jobs[0]['path'],START,START+FIVE);before=retained(db,'C');db.conn.rollback()
                    job=jobs[1]
                    child=multiprocessing.get_context('spawn').Process(target=die,args=(options,job['path'],job['start'],point))
                    child.start();child.join(30)
                    if child.is_alive():child.kill();child.join();self.fail('screen child did not exit')
                    self.assertEqual(child.exitcode,73)
                    self.assertEqual(before==retained(db,'C'),not committed);db.conn.rollback()
                    after=db.one('SELECT next_ns FROM viewer_live_state WHERE id=1')['next_ns'];db.conn.rollback()
                    self.assertEqual(after,START+(2 if committed else 1)*FIVE)
                    result=publisher(db)(job['path'],job['start'],job['start']+FIVE,mode='recheck' if committed else 'forward')
                    self.assertGreaterEqual(result['generation'],2)

    def test_separate_capacity_databases_balanced_orders_and_retained_history(self):
        from viewer_performance.financial_screen.experiment import run
        report=run(self.parameters,counts=(1,2,3),histories=(0,16),max_seconds=120)
        self.assertEqual(report['status'],'SCOPE_SCREEN_COMPLETE_NOT_PRODUCT_ACCEPTANCE',report.get('failure'))
        self.assertTrue(all(check['retained_outputs_equal'] for check in report['correctness']))
        timed=[l for l in report['lanes'] if l['purpose']=='capacity']
        self.assertEqual(len(timed),20)
        self.assertFalse(any(w['full_table_oracle_executed'] for l in timed for w in l['windows']))
        self.assertFalse(any(w['full_output_oracle'] for l in timed for w in l['windows']))
        self.assertEqual(report['cleanup']['allocated'],report['cleanup']['dropped'])
        self.assertEqual(report['cleanup']['remaining'],[])
        self.assertEqual(len(report['decisions']),10)
        self.assertEqual(len(report['feature_decision_table']),10)

    def test_existing_project_database_session_blocks_before_allocation(self):
        from viewer_performance.financial_screen.experiment import run
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);keys=root/'keys';generate_keys(keys)
            with self.database(root,keys,'A'):
                report=run(self.parameters,counts=(1,1,1),histories=(0,),max_seconds=30)
                self.assertEqual(report['status'],'SCOPE_SCREEN_INCOMPLETE')
                self.assertEqual(report['failure']['code'],'PROJECT_DATABASE_SESSIONS_STILL_PRESENT')
                self.assertEqual(report['cleanup']['allocated'],0)


if __name__=='__main__':unittest.main()
