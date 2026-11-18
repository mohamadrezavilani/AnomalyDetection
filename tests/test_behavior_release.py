"""Lifecycle failure gates and real long-child cancellation, no owner host."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock,patch
from viewer_performance import Behavior_Release as release
from viewer_performance.financial_screen import host


class ReleaseTests(unittest.TestCase):
    def state(self):
        task=dict(Name='fixture',Path='\\',Actions=[dict(Execute='fixture-only')],Enabled=True,State='Ready')
        plan=dict(active=dict.fromkeys(('ad_worker','ad_web','viewer','viewer_web'),False),task_restore=[task],ad_identities={})
        return dict(before=dict(status='PREFLIGHT_READY',restore_plan=plan,inventory=dict(processes=[])),
                    stopping_started=True,attempted_roles=[],disabled_tasks=[task],frozen_cursors={})

    def test_incomplete_financial_repair_never_restarts_roles_or_tasks(self):
        with tempfile.TemporaryDirectory() as folder:
            receipt=Path(folder)/'release.json';state=self.state()
            with patch.object(release,'scope_ready',return_value=False),patch.object(host,'command') as command,patch.object(host,'task_change') as task:
                with self.assertRaisesRegex(ValueError,'NO_WORKER_RESTART'):release.restore(Path(folder),receipt,state)
                command.assert_not_called();task.assert_not_called()
            self.assertEqual(json.loads(receipt.read_text())['status'],'RESTORING_FULL_SUPERVISORS_LEFT_DISABLED')

    def test_changed_task_actions_block_verified_restore(self):
        with tempfile.TemporaryDirectory() as folder:
            receipt=Path(folder)/'release.json';state=self.state();changed=copy.deepcopy(state['disabled_tasks'][0]);changed['Actions']=[]
            with patch.object(release,'scope_ready',return_value=True),patch.object(host,'command',return_value=({'source_sha256':'new'},0)), \
                 patch.object(host,'verify_restore',return_value={}),patch.object(host,'task_change'),patch.object(host,'product_reader'), \
                 patch.object(host,'cursors',return_value={}),patch.object(host,'inventory',return_value={'tasks':[changed]}):
                with self.assertRaisesRegex(ValueError,'RESTORE_INCOMPLETE'):release.restore(Path(folder),receipt,state)
            self.assertIn('SCHEDULED_TASK_RESTORE_NOT_VERIFIED',receipt.read_text())

    def test_cursor_regression_or_history_identity_change_is_blocked(self):
        before=dict(viewer_live_state=[dict(start_ns=1,next_ns=20,generation=3,stream_key='a',keys_fingerprint='b')])
        for field,value in [('next_ns',19),('generation',2),('stream_key','changed')]:
            after=copy.deepcopy(before);after['viewer_live_state'][0][field]=value
            with self.assertRaisesRegex(ValueError,'REGRESSED_OR_STREAM_CHANGED'):release.verify_cursors(before,after)
        after=copy.deepcopy(before);after['viewer_live_state'][0].update(next_ns=21,generation=4)
        release.verify_cursors(before,after)

    def test_new_process_after_disabling_tasks_aborts_before_any_stop(self):
        with tempfile.TemporaryDirectory() as folder:
            state=self.state();before=state['before'];before['restore_plan']['task_restore']=[]
            snapshot=dict(processes=[dict(ProcessId=923,CommandLine=str(Path(folder))+'/unknown.py')],tasks=[],listeners=[],services=[])
            with patch.object(host,'preflight',return_value=before),patch.object(host,'inventory',return_value=snapshot), \
                 patch.object(host,'stop_role') as stop,patch.object(release,'restore') as restore:
                with self.assertRaisesRegex(ValueError,'PROCESS_CHANGED'):release.prepare(Path(folder),Path(folder)/'release.json',None)
                stop.assert_not_called();restore.assert_called_once()

    def test_long_scope_child_uses_own_budget_and_real_cancel_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'viewer_performance').mkdir();state={};receipt=root/'release.json'
            script=root/'viewer_performance/Behavior_Control.py'
            script.write_text("import sys,time,json\nfrom pathlib import Path\np=Path(sys.argv[sys.argv.index('--cancel-file')+1])\nwhile not p.exists():time.sleep(.01)\nprint(json.dumps({'cancelled':True}),flush=True)\n")
            with patch.object(host,'command',side_effect=AssertionError('90-second command must not be used')):
                with self.assertRaisesRegex(TimeoutError,'TIME_BUDGET'):release.scope_command(root,receipt,state,'restore-full',.15)
            self.assertTrue(list(root.glob('scope-cancel-*.json')))
            self.assertIn('cancelled',(root/'scope-command.log').read_text())
            self.assertTrue(state['scope_command']['pid']>0)

    @unittest.skipUnless(os.name=='nt','native Windows process handles required')
    def test_hard_cancel_pins_actual_python_handle_and_rejects_wrong_nonce(self):
        from viewer_performance.financial_screen.resources import process_usage
        with tempfile.TemporaryDirectory() as folder:
            progress=Path(folder)/'progress.json'
            child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])
            try:
                usage=process_usage(child.pid,cpu_only=True)
                progress.write_text(json.dumps(dict(command_token='same',process_pid=child.pid,
                    process_created_epoch_seconds=usage['created_epoch_seconds'])))
                with self.assertRaisesRegex(ValueError,'IDENTITY_UNVERIFIED'):release.hard_stop_scope_python(progress,'different')
                self.assertIsNone(child.poll())
                release.hard_stop_scope_python(progress,'same');child.wait(timeout=10)
                self.assertIsNotNone(child.returncode)
            finally:
                if child.poll() is None:child.terminate();child.wait(timeout=10)

    @unittest.skipUnless(os.name=='nt','native Windows PowerShell required')
    def test_native_powershell_parses_installer_with_pinned_required_commit(self):
        path=Path(__file__).resolve().parents[1]/'viewer_performance/Install_Behavior.ps1'
        code="& { param($p) $errors=$null; $tokens=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($p,[ref]$tokens,[ref]$errors); if($errors.Count){throw ($errors|Out-String)}; $cmd=Get-Command $p; if(-not $cmd.Parameters.ContainsKey('TargetCommit')){throw 'Missing pin'}; 'PASS' } '"+str(path).replace("'","''")+"'"
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',code],capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr);self.assertIn('PASS',result.stdout)


if __name__=='__main__':unittest.main()
