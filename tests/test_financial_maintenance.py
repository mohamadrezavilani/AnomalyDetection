"""Reviewed supervision, exact process handles and failure-path restoration."""
import copy
from datetime import datetime,timezone
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock,patch

from viewer_performance.financial_screen import reviewed_host as review
from viewer_performance.financial_screen import host


def fixture():
    project=Path(r'C:\fixture\product');entry=r'C:\fixture\support\SERVICE_ENTRY.ps1';proxy=r'C:\fixture\support\lan_proxy.py'
    arguments=f'-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File {entry} -Service lan_proxy'
    def process(pid,parent,exe,command):
        return dict(ProcessId=pid,ParentProcessId=parent,CreationDate='/Date(1000000)/',ExecutablePath=exe,CommandLine=command)
    processes=[
        process(31,21,r'C:\runtime\python.exe',f'"C:\\runtime\\python.exe" -B {proxy} --bind 192.0.2.1 --allow-subnet 192.0.2.0/24'),
        process(21,11,str(project)+r'\.venv\Scripts\python.exe',f'"{project}\\.venv\\Scripts\\python.exe" -B {proxy} --bind 192.0.2.1 --allow-subnet 192.0.2.0/24'),
        process(11,1,r'C:\Windows\powershell.exe','powershell.exe '+arguments),
        process(52,42,r'C:\runtime\python.exe','python.exe -B viewer_performance/Run_Viewer_Web.py --host 127.0.0.1'),
        process(42,32,str(project)+r'\.venv\Scripts\python.exe','python.exe -B viewer_performance/Run_Viewer_Web.py --host 127.0.0.1'),
        process(32,2,r'C:\Windows\powershell.exe',f'''powershell.exe -NoExit -Command & '{project}\.venv\Scripts\python.exe' -B viewer_performance/Run_Viewer_Web.py --host 127.0.0.1''')]
    task=dict(Name='FixtureFrontend',Path='\\',State='Running',Enabled=True,
        Actions=[dict(Execute='powershell.exe',Arguments=arguments,WorkingDirectory=None)])
    sources=[dict(path=path,status='READ_ONLY_SOURCE',sha256=hashlib.sha256(body).hexdigest())
        for path,body in ((entry,b'# fixture entry'),(proxy,b'# fixture proxy'))]
    plan=dict(owners=dict(viewer_web=52),active=dict.fromkeys(('ad_worker','ad_web','viewer','viewer_web'),True),
        issues=['FRONTEND_STOP_AND_RESTORE_PLAN_REQUIRED:31','RUNNING_SCHEDULED_TASK_RESTORE_PLAN_REQUIRED:FixtureFrontend',
            'UNCONTROLLED_PROJECT_PROCESS:21','UNCONTROLLED_PROJECT_PROCESS:32'],task_restore=[task],
        viewer_restart=['fast'],viewer_web_restart=['web'],ad_worker_restart=['ad','start'],ad_web_restart=['ad','web'])
    value=dict(status='PREFLIGHT_BLOCKED',restore_plan=plan,
        inventory=dict(processes=processes,tasks=[task],services=[],listeners=[dict(LocalAddress='192.0.2.1',LocalPort=port,OwningProcess=31) for port in (5021,5022)]),
        external_supervision=dict(sources=sources))
    return project,value


class ReviewedMaintenanceTests(unittest.TestCase):
    def test_review_resolves_only_proven_frontend_task_and_single_purpose_launch_shell(self):
        project,value=fixture();original=copy.deepcopy(value)
        result=review.apply_review(project,value,value,'fixture-digest')
        self.assertEqual(value,original)
        self.assertEqual(result['status'],'PREFLIGHT_READY')
        self.assertEqual(result['restore_plan']['issues'],[])
        self.assertEqual([p['ProcessId'] for p in result['restore_plan']['reviewed_proxy']['processes']],[31,21,11])
        self.assertEqual([p['ProcessId'] for p in result['restore_plan']['idle_launchers']],[32])
        changed=copy.deepcopy(value);changed['restore_plan']['issues'].append('UNCONTROLLED_PROJECT_PROCESS:999')
        self.assertEqual(review.apply_review(project,changed,value,'digest')['status'],'PREFLIGHT_BLOCKED')

    def test_source_action_or_shell_command_change_does_not_bypass_gate(self):
        project,value=fixture()
        for change in ('source','action','shell'):
            current=copy.deepcopy(value)
            if change=='source':current['external_supervision']['sources'][0]['sha256']='changed'
            elif change=='action':current['inventory']['tasks'][0]['Actions'][0]['Arguments']+=' --another-command'
            else:current['inventory']['processes'][-1]['CommandLine']+='; Write-Output unexpected'
            self.assertEqual(review.apply_review(project,current,value,'digest')['status'],'PREFLIGHT_BLOCKED',change)

    def test_idle_shell_requires_same_os_identity_no_child_and_bounded_cpu(self):
        project,value=fixture();plan=review.apply_review(project,value,value,'digest')['restore_plan']
        shell=plan['idle_launchers'][0];snapshot=dict(processes=[shell])
        usage=dict(status='READ',image_name='powershell.exe',created_epoch_seconds=1000.,identity=1,cpu_seconds=1.)
        self.assertEqual(review.idle_ids(snapshot,plan,{},usage=lambda pid:dict(usage),wait=lambda _:None),{32})
        child=copy.deepcopy(shell);child.update(ProcessId=99,ParentProcessId=32)
        with self.assertRaisesRegex(ValueError,'HAS_ACTIVE_CHILD'):
            review.idle_ids(dict(processes=[shell,child]),plan,{},usage=lambda pid:usage)
        replacement=copy.deepcopy(shell);replacement['CreationDate']='/Date(1001000)/'
        with self.assertRaisesRegex(ValueError,'IDENTITY_CHANGED'):review.idle_ids(dict(processes=[replacement]),plan,{})
        rows=iter([dict(usage),dict(usage,cpu_seconds=1.2)])
        with self.assertRaisesRegex(ValueError,'NOT_IDLE'):
            review.idle_ids(snapshot,plan,{},usage=lambda pid:next(rows),wait=lambda _:None)

    def test_task_operations_pin_actions_and_never_stop_a_windows_service(self):
        _,value=fixture();task=value['inventory']['tasks'][0]
        with patch.object(host,'powershell',return_value=task) as execute:
            host.task_control(task,'stop');code,env=execute.call_args.args
        self.assertIn('Stop-ScheduledTask',code);self.assertNotIn('Stop-Service',code)
        self.assertIn('SCHEDULED_TASK_ACTIONS_CHANGED',code)
        self.assertEqual(json.loads(env['P24_SCREEN_TASK_ACTIONS']),task['Actions'])

    def test_sources_are_rechecked_before_any_process_handle_opens(self):
        with tempfile.TemporaryDirectory() as folder:
            source=Path(folder)/'entry.ps1';source.write_bytes(b'changed source')
            proxy=dict(sources=[dict(path=str(source),sha256=hashlib.sha256(b'original source').hexdigest())],processes=[],task={})
            with patch.object(host,'inventory') as inventory,patch.object(host,'task_control') as tasks:
                with self.assertRaisesRegex(ValueError,'SUPERVISOR_SOURCE_CHANGED'):
                    host.stop_reviewed_proxy(Path(folder),proxy)
                inventory.assert_not_called();tasks.assert_not_called()

    def test_proxy_stop_opens_exact_handles_before_task_stop_then_closes_every_handle(self):
        project,value=fixture();plan=review.apply_review(project,value,value,'digest')['restore_plan'];proxy=plan['reviewed_proxy'];events=[]
        class Handle:
            def __init__(self,row):
                self.image=row['ExecutablePath'];self.created=datetime.fromtimestamp(1000,tz=timezone.utc)
                self.handle=row['ProcessId'];self.api=MagicMock();self.api.WaitForSingleObject.return_value=258
                events.append(('open',self.handle))
            def terminate(self):events.append(('terminate',self.handle))
            def close(self):events.append(('close',self.handle))
        rows={p['ProcessId']:p for p in proxy['processes']}
        with patch.object(host,'check_sources'),patch.object(host,'inventory',return_value=value['inventory']),\
             patch.object(host,'task_control',side_effect=lambda task,op:events.append((op,task['Name']))):
            host.stop_reviewed_proxy(project,proxy,open_process=lambda pid:Handle(rows[pid]))
        self.assertEqual(events[:4],[('open',31),('open',21),('open',11),('stop','FixtureFrontend')])
        self.assertEqual([e[1] for e in events if e[0]=='terminate'],[31,21,11])
        self.assertEqual([e[1] for e in events if e[0]=='close'],[31,21,11])
        changed=copy.deepcopy(value['inventory']);changed['processes'][0]['CreationDate']='/Date(1001000)/'
        with patch.object(host,'check_sources'),patch.object(host,'inventory',return_value=changed),patch.object(host,'task_control') as stop:
            with self.assertRaisesRegex(ValueError,'PROCESS_CHANGED_BEFORE_STOP'):
                host.stop_reviewed_proxy(project,proxy,open_process=lambda pid:self.fail('unverified handle'))
            stop.assert_not_called()

    @unittest.skipUnless(os.name=='nt','Windows PowerShell task adapter only')
    def test_actual_powershell_task_adapter_pins_actions_and_round_trips_state(self):
        _,value=fixture();task=value['inventory']['tasks'][0];real=host.powershell
        native=dict(TaskName=task['Name'],TaskPath=task['Path'],State='Running',
            Settings=dict(Enabled=True),Actions=task['Actions'])
        prefix='''$task=ConvertFrom-Json $env:P24_REVIEW_TEST_TASK
function Get-ScheduledTask { param($TaskName,$TaskPath) $task }
function Stop-ScheduledTask { param($TaskName,$TaskPath) $task.State='Ready' }
function Start-ScheduledTask { param($TaskName,$TaskPath) $task.State='Running' }
function Enable-ScheduledTask { param($TaskName,$TaskPath) $task.Settings.Enabled=$true }
function Disable-ScheduledTask { param($TaskName,$TaskPath) $task.Settings.Enabled=$false }
'''
        def execute(code,environment):return real(prefix+code,{**environment,'P24_REVIEW_TEST_TASK':json.dumps(native)})
        with patch.object(host,'powershell',side_effect=execute):
            self.assertEqual(host.task_control(task,'stop')['State'],'Ready')
            self.assertEqual(host.task_control(task,'start')['State'],'Running')
            self.assertFalse(host.task_control(task,'disable')['Enabled'])
            changed=copy.deepcopy(task);changed['Actions'][0]['Arguments']+=' changed'
            with self.assertRaises(host.HostOperationError):host.task_control(changed,'stop')

    @unittest.skipUnless(os.name=='nt','Windows process handle pinning only')
    def test_native_pinned_handle_stops_only_owned_fixture_child(self):
        from viewer_performance.Stop_Viewer_Worker import WindowsProcess
        child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            probe=WindowsProcess(child.pid)
            try:
                row=dict(ProcessId=child.pid,ParentProcessId=os.getpid(),CreationDate='/Date('+str(int(probe.created.timestamp()*1000))+')/',
                    ExecutablePath=probe.image,CommandLine='fixture child only')
            finally:probe.close()
            proxy=dict(processes=[row],task=dict(Name='fixture only'),sources=[])
            with patch.object(host,'inventory',return_value=dict(processes=[row])),patch.object(host,'task_control'):
                result=host.stop_reviewed_proxy(Path.cwd(),proxy)
            self.assertEqual(result['process_handles_verified'],1);child.wait(10)
        finally:
            if child.poll() is None:child.kill();child.wait(10)

    def test_failed_experiment_restores_proxy_and_original_tasks_after_core_roles(self):
        project,value=fixture();before=review.apply_review(project,value,value,'digest');events=[]
        live=copy.deepcopy(value['inventory']);proxy=before['restore_plan']['reviewed_proxy'];fake=MagicMock()
        fake.execute.return_value.fetchone.return_value={'held':True}
        def task_change(task,enabled):live['tasks'][0]['Enabled']=enabled;events.append('enable' if enabled else 'disable')
        def proxy_stop(*args):live['tasks'][0]['State']='Ready';events.append('stop-proxy');return {}
        def proxy_restore(*args):live['tasks'][0]['State']='Running';events.append('restore-proxy');return {}
        def command(*args):
            if args[1]=='ad':events.append('restore-ad');return dict(status='STARTED'),0
            return dict(status='NO_VIEWER_LOCK_OWNER_OBSERVED' if 'Worker' in args[1] else 'NO_VIEWER_WEB_LISTENER'),0
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(host,'product_reader',return_value=fake),patch.object(host,'cursors',return_value={}),\
                 patch.object(host,'inventory',side_effect=lambda project:copy.deepcopy(live)),\
                 patch.object(host,'task_change',side_effect=task_change),patch.object(host,'check_sources'),\
                 patch.object(host,'stop_role',side_effect=lambda project,role:events.append('stop-'+role) or {}),\
                 patch.object(host,'stop_reviewed_proxy',side_effect=proxy_stop),patch.object(host,'restore_reviewed_proxy',side_effect=proxy_restore),\
                 patch.object(host,'wait_for_quiescence'),patch.object(host,'assert_idle'),patch.object(host,'parameters',return_value={}),\
                 patch('psycopg.connect',return_value=MagicMock()),patch.object(host,'command',side_effect=command),\
                 patch.object(host,'start_process',side_effect=lambda project,args,logs,role:events.append('restore-'+role) or 1),\
                 patch.object(host,'verify_restore',side_effect=lambda project,plan:events.append('verify-core') or {}):
                with self.assertRaisesRegex(RuntimeError,'injected'):
                    with host.maintenance(project,before,Path(folder)) as state:raise RuntimeError('injected')
        self.assertEqual(state['status'],'PREVIOUS_ROLES_RESTORED')
        self.assertLess(events.index('stop-ad'),events.index('stop-proxy'))
        self.assertLess(events.index('verify-core'),events.index('enable'))
        self.assertLess(events.index('restore-viewer'),events.index('restore-proxy'))
        self.assertTrue(live['tasks'][0]['Enabled']);self.assertEqual(live['tasks'][0]['State'],'Running')

    def test_new_monitor_during_disable_blocks_before_any_role_stop(self):
        project,value=fixture();before=review.apply_review(project,value,value,'digest')
        live=copy.deepcopy(value['inventory']);live['tasks'][0]['Enabled']=False
        live['processes'].append(dict(ProcessId=999,ParentProcessId=1,CreationDate='/Date(1000000)/',
            ExecutablePath=r'C:\runtime\python.exe',CommandLine=r'python.exe C:\fixture\support\always_on.py --mode monitor'))
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(host,'inventory',side_effect=lambda project:copy.deepcopy(live)),\
                 patch.object(host,'task_change',side_effect=lambda task,enabled:live['tasks'][0].update(Enabled=enabled)),\
                 patch.object(host,'check_sources'),patch.object(host,'stop_role') as stop,\
                 patch.object(host,'verify_restore',return_value={}),patch.object(host,'product_reader',return_value=MagicMock()),\
                 patch.object(host,'cursors',return_value={}):
                with self.assertRaisesRegex(ValueError,'CHANGED_WHILE_DISABLING_AUTOSTART'):
                    with host.maintenance(project,before,Path(folder)):self.fail('experiment started')
                stop.assert_not_called()
        self.assertTrue(live['tasks'][0]['Enabled'])


if __name__=='__main__':unittest.main()
