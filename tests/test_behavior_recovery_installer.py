"""Actual Git activation/rollback; Windows role operations are simulated."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock,patch

from AnomalyDetection import Install_Behavior_Recovery as installer
from viewer_performance.behavior_install_git import inspect


class RecoveryInstallerTests(unittest.TestCase):
    def exercise(self,*,dirty=False,stop_blocked=False,manifest_failure=False,diagnostic_failure=False):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'AnomalyDetection').mkdir()
            git=lambda *args:installer.git_command(root,*args)
            git('init','-b','main');git('config','user.name','Fixture');git('config','user.email','fixture@example.invalid')
            manifest=root/'AnomalyDetection/RELEASE_MANIFEST.json'
            manifest.write_text(json.dumps(dict(build_id='old',source_sha256='old')))
            (root/'payload.txt').write_text('old');git('add','.');git('commit','-m','old')
            old=git('rev-parse','HEAD')
            manifest.write_text(json.dumps(dict(build_id=installer.EXPECTED_BUILD,source_sha256='f'*64)))
            (root/'payload.txt').write_text('new');git('add','.');git('commit','-m','new')
            target=git('rev-parse','HEAD');git('checkout','--detach',old)
            if dirty:(root/'payload.txt').write_text('operator edit')
            task=dict(Name='P24-Viewer-Worker',Path='\\',State='Ready',Enabled=True,Actions=[])
            plan=dict(task_restore=[task],active={k:True for k in ('viewer','viewer_web','ad_worker','ad_web')})
            previous=root/'release.json';previous.write_text(json.dumps(dict(status='PREVIOUS_ROLES_RESTORED',before=dict(restore_plan=plan))))
            host=MagicMock();host.key.side_effect=lambda t:(t['Path'],t['Name'])
            host.inventory.return_value=dict(tasks=[task]);host.cursors.return_value={}
            host.product_reader.return_value.__enter__.return_value.execute.return_value.fetchone.return_value=dict(contract='viewer-behavior-1',epoch=1,state='READY')
            def command(project,script,*args):
                if script.endswith('run_anomaly.py') and args==('worker-status',) and diagnostic_failure:
                    raise ValueError('FIXTURE_SOURCE_STATUS_READ_TIMEOUT')
                if script.endswith('Stop_Viewer_Worker.py'):
                    return (dict(status='VIEWER_CONTROL_BLOCKED',code='FIXTURE_BLOCK') if stop_blocked else dict(status='VIEWER_WORKER_STOPPED'),2 if stop_blocked else 0)
                return dict(build_id=installer.EXPECTED_BUILD,source_sha256='f'*64),0
            host.command.side_effect=command
            restored=[]
            def restore(project,receipt,state):
                restored.append(git('rev-parse','HEAD'));state.update(status='PREVIOUS_ROLES_RESTORED',after_restore={'ad':{'health':'RUNNING'}})
                for t in state['disabled_tasks']:host.task_change(t,True)
            def check(project):
                if manifest_failure and git('rev-parse','HEAD')==target:raise ValueError('fixture manifest rejected')
            def command_git(project,*args):return '' if args[0]=='fetch' else installer.git_command(project,*args)
            with redirect_stdout(io.StringIO()),patch.object(installer,'check_manifests',side_effect=check):
                state=installer.install(root,target,previous,host=host,restore=restore,inspect=inspect,git=command_git,wait=lambda _:None)
            return state,host,git('rev-parse','HEAD'),old,target,restored,(root/'payload.txt').read_text()

    def test_fast_forward_restores_roles_and_never_claims_analysis_or_capacity_acceptance(self):
        state,host,head,old,target,restored,_=self.exercise()
        self.assertEqual(state['status'],'RECOVERY_INSTALLED_ROLES_RESTORED');self.assertEqual(head,target)
        self.assertEqual(restored,[target]);self.assertFalse(state['checkpoint_seek_performed'])
        self.assertFalse(state['postgres_restarted']);self.assertFalse(state['settings_modified'])
        self.assertEqual(state['capacity_acceptance'],'NOT_ASSIGNED')
        self.assertEqual(state['analysis_acceptance'],'PENDING_SOURCE_PROGRESS_AND_SCOPE_MIGRATION')

    def test_diagnostic_failure_keeps_successful_install_separate_from_unverified_analysis(self):
        state,host,head,old,target,restored,_=self.exercise(diagnostic_failure=True)
        self.assertEqual(state['status'],'RECOVERY_INSTALLED_ROLES_RESTORED');self.assertEqual(head,target)
        self.assertEqual(restored,[target]);self.assertEqual(state['runtime_receipt_status'],'PARTIAL')
        self.assertFalse(state['analysis_progress_verified']);self.assertFalse(state['runtime_identity_verified'])
        self.assertEqual(state['progress_after']['diagnostic_failure']['code'],'FIXTURE_SOURCE_STATUS_READ_TIMEOUT')

    def test_real_tracked_operator_edits_block_before_stopping_and_remain_unchanged(self):
        state,host,head,old,target,restored,payload=self.exercise(dirty=True)
        self.assertEqual(head,old);self.assertEqual(payload,'operator edit')
        host.stop_role.assert_not_called();self.assertEqual(restored,[])

    def test_rejected_new_code_rolls_back_the_exact_git_head_before_restoring_roles(self):
        state,host,head,old,target,restored,payload=self.exercise(manifest_failure=True)
        self.assertEqual(head,old);self.assertEqual(payload,'old');self.assertEqual(restored,[old])
        self.assertTrue(state['previous_code_restored'])
        self.assertEqual(state['status'],'RECOVERY_UPDATE_INCOMPLETE_SEND_RECEIPT')

    def test_blocked_viewer_stop_keeps_detail_restores_roles_and_never_changes_code(self):
        state,host,head,old,target,restored,_=self.exercise(stop_blocked=True)
        self.assertEqual(head,old);self.assertEqual(restored,[old])
        self.assertEqual(state['viewer_stop_attempts'][0]['result']['code'],'FIXTURE_BLOCK')
        self.assertFalse(state['postgres_restarted'])


if __name__=='__main__':unittest.main()
