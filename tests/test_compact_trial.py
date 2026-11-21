import contextlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from compact_behavior.__main__ import save,process_info
from compact_behavior.server_trial import trial


class FakeHost:
    def __init__(self):
        self.active=True;self.events=[];self.h=self
        self.task=dict(Name='P24-Worker',Path='\\',Enabled=True,State='Ready',Actions=[])
    def command(self,*args):
        if args[0].endswith('run_anomaly.py'):return {'process':{'locked':self.active},'web':{'locked':self.active}},0
        if args[0].endswith('Stop_Viewer_Worker.py'):return {'status':'VIEWER_WORKER_IDENTIFIED' if self.active else 'NO_VIEWER_LOCK_OWNER_OBSERVED'},0
        return {'status':'VIEWER_WEB_IDENTIFIED' if self.active else 'NO_VIEWER_WEB_LISTENER'},0
    def inventory(self):return {'tasks':[dict(self.task)],'processes':[]}
    def task_change(self,task,enabled):self.events.append(('task',enabled));self.task['Enabled']=enabled
    def task_control(self,*args):self.events.append(('task_control',args))
    def stop(self,role):self.events.append(('stop',role));self.active=False
    def reader(self):return contextlib.nullcontext(self)
    def cursors(self,db):return {'cursor':'stable'}


class TrialTests(unittest.TestCase):
    def execute_trial(self,fail=False):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);old=root/'old.json'
            save(old,{'before':{'restore_plan':{'active':{'viewer':True}}}})
            host=FakeHost()
            def restore(project,receipt,state):host.events.append(('restore',));state['restore_failures']=[]
            def execute(folder,state):
                self.assertFalse(host.active);self.assertFalse(host.task['Enabled'])
                if fail:raise ValueError('artificial_trial_failure')
                return {'status':'COMPACT_PROTOTYPE_MEASURED'}
            result=trial(root,old,root/'result',host=host,restore=restore,execute=execute)
            self.assertIn(('restore',),host.events);self.assertTrue((root/'result.zip').is_file())
            return result
    def test_stop_verify_restore_and_export_on_success(self):
        result=self.execute_trial();self.assertEqual(result['status'],'COMPACT_TRIAL_MEASURED_ROLES_RESTORED')
        self.assertTrue(result['legacy_cursors_unchanged_during_trial'])
    def test_restore_and_export_after_child_failure(self):
        result=self.execute_trial(True);self.assertEqual(result['status'],'COMPACT_TRIAL_PARTIAL_SEND_BUNDLE')
        self.assertEqual(result['failure']['code'],'artificial_trial_failure')
    def test_atomic_report_retries_windows_sharing_violation(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'test.json'
            import os
            original=os.replace;attempts=[]
            def replace(*args):
                attempts.append(1)
                if len(attempts)<3:raise PermissionError('sharing')
                return original(*args)
            with patch('compact_behavior.__main__.os.replace',side_effect=replace):save(path,{'ok':True})
            self.assertTrue(json.loads(path.read_text())['ok']);self.assertEqual(len(attempts),3)
    def test_real_platform_process_identity_and_peak_memory(self):
        info=process_info();self.assertGreater(info['process_pid'],0);self.assertGreater(info['process_peak_rss_bytes'],0)
        if __import__('os').name=='nt':self.assertGreater(info['process_created_epoch_seconds'],0)
    def test_compact_manifest_detects_changed_bytes(self):
        from compact_behavior.version import verify
        self.assertGreater(verify()['checked_files'],0)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'a.py').write_text('changed')
            (root/'MANIFEST.json').write_text(json.dumps({'build_id':'test','files_sha256':{'a.py':'0'*64}}))
            with self.assertRaisesRegex(ValueError,'bytes_changed'):verify(root)


if __name__=='__main__':unittest.main()
