import unittest
import os
import subprocess
import base64
import json
from tools.Repair_Compact_History_Task import validate_task,worker_args

class TaskRepairTests(unittest.TestCase):
    def snapshot(self):
        old=r'E:\P24\releases\compact-history-05ad6c7'
        return dict(actions=[dict(Execute='powershell.exe',WorkingDirectory=old,Arguments=worker_args(old,r'E:\P24\pishkhan24',r'E:\P24\pishkhan24\.venv\Scripts\python.exe'))],enabled=False,state='Disabled')
    def validate(self,s):
        return validate_task(s,r'E:\P24\pishkhan24',r'E:\P24\pishkhan24\.venv\Scripts\python.exe')
    def test_owned_old_release_can_migrate(self):
        self.assertTrue(self.validate(self.snapshot()).endswith('05ad6c7'))
    def test_other_project_or_executable_rejected(self):
        for key,value in [('Execute','cmd.exe'),('Arguments','-File unrelated.ps1'),('WorkingDirectory',r'E:\other')]:
            s=self.snapshot();s['actions'][0][key]=value
            with self.assertRaises(ValueError):self.validate(s)
    def test_enabled_or_running_task_rejected(self):
        for key,value in [('enabled',True),('state','Running'),('state','Ready')]:
            s=self.snapshot();s[key]=value
            with self.assertRaises(ValueError):self.validate(s)
    def test_multiple_actions_rejected(self):
        s=self.snapshot();s['actions']*=2
        with self.assertRaises(ValueError):self.validate(s)

    @unittest.skipUnless(os.name == 'nt', 'native Windows PowerShell required')
    def test_native_powershell_parses_migration_and_snapshot(self):
        from tools.Repair_Compact_History_Task import CHANGE,SNAPSHOT
        for script in (CHANGE,SNAPSHOT):
            encoded=base64.b64encode(script.encode('utf-8')).decode()
            check="$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+encoded+"'));$t=$null;$e=$null;[System.Management.Automation.Language.Parser]::ParseInput($s,[ref]$t,[ref]$e)|Out-Null;if($e.Count){throw 'parse failed'}"
            command=base64.b64encode(check.encode('utf-16le')).decode()
            result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',command],capture_output=True,timeout=30)
            self.assertEqual(result.returncode,0)
