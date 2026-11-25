import unittest
import os
import subprocess
import base64
import json
import uuid
from tools.Repair_Compact_History_Task import validate_task,worker_args,wait_for_stopped_task

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

    def test_cim_numeric_state_is_not_a_friendly_enum_string(self):
        for value in (1, '1', 'Disabled'):
            s=self.snapshot();s['state']=value
            self.validate(s)
        s=self.snapshot();s.update(state='localized display',state_code=1)
        self.validate(s)
        for value in (0,2,3,4,True,None,'unexpected'):
            s=self.snapshot();s['state_code']=value
            with self.assertRaises(ValueError):self.validate(s)

    def wait(self, snapshots, timeout=2, **options):
        now=[0];reads=[]
        def read():
            item=snapshots[min(len(reads),len(snapshots)-1)];reads.append(item);return item
        def sleep(seconds):now[0]+=seconds
        return wait_for_stopped_task(read,r'E:\P24\pishkhan24',r'E:\P24\pishkhan24\.venv\Scripts\python.exe',
            timeout=timeout,clock=lambda:now[0],sleep=sleep,**options)

    def test_worker_stops_before_launcher_and_scheduler(self):
        running=self.snapshot();running['state']='4'
        self.assertEqual(self.wait([running,self.snapshot()])['state'],'Disabled')
        with self.assertRaises(TimeoutError):self.wait([running])

    def test_upgrade_drains_once_and_waits_for_confirmed_exit(self):
        busy=dict(self.snapshot(),state_code=4,instances=1)
        stopping=dict(self.snapshot(),state_code=1,instances=1)
        calls=[]
        def drain(snapshot):
            calls.append(snapshot)
            return True
        self.wait([busy,busy,stopping,self.snapshot()],drain=drain)
        self.assertEqual(calls,[busy])
        calls.clear()
        self.wait([self.snapshot()],drain=drain)
        self.assertFalse(calls)
        with self.assertRaises(TimeoutError):
            self.wait([stopping],drain=drain,settle=5)
        self.assertEqual(calls,[stopping])

    def test_guarded_drain_retries_busy_worker_and_revalidates_owner(self):
        from unittest.mock import Mock
        busy=dict(self.snapshot(),state_code=4)
        drain=Mock(side_effect=[False,True])
        self.wait([busy]*3+[self.snapshot()],drain=drain)
        self.assertEqual(drain.call_count,2)
        with self.assertRaises(ValueError):
            self.wait([busy,dict(busy,enabled=True)],drain=lambda _:self.fail('ownership guard bypassed'))

    def test_task_change_during_drain_is_rejected(self):
        running=self.snapshot();running['state']='Running'
        enabled=self.snapshot();enabled['enabled']=True
        foreign=self.snapshot();foreign['actions'][0]['Arguments']='unrelated'
        for changed in (enabled,foreign):
            with self.assertRaises(ValueError):self.wait([running,changed])

    @unittest.skipUnless(os.name == 'nt', 'native Windows Task Scheduler required')
    def test_native_disabled_task_snapshot_and_guarded_migration(self):
        from tools.Repair_Compact_History_Task import SNAPSHOT,CHANGE
        name='P24-CompactHistory-Test-'+uuid.uuid4().hex
        old=self.snapshot()['actions'][0]['WorkingDirectory']
        project=r'E:\P24\pishkhan24';python=r'E:\P24\pishkhan24\.venv\Scripts\python.exe'
        new=r'E:\P24\releases\compact-history-test-new'
        env=dict(os.environ,P24_OLD_ROOT=old,P24_OLD_ARGS=worker_args(old,project,python),
            P24_NEW_ROOT=new,P24_NEW_ARGS=worker_args(new,project,python))
        def ps(script):
            script="$ErrorActionPreference='Stop'\n"+script.replace('P24-CompactHistory',name)
            command=base64.b64encode(script.encode('utf-16le')).decode()
            r=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',command],
                env=env,capture_output=True,text=True,timeout=30)
            self.assertEqual(r.returncode,0,r.stderr)
            return r.stdout.strip()
        try:
            ps("""
$a=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $env:P24_OLD_ARGS -WorkingDirectory $env:P24_OLD_ROOT
Register-ScheduledTask -TaskName 'P24-CompactHistory' -Action $a -Force | Out-Null
Disable-ScheduledTask -TaskName 'P24-CompactHistory' | Out-Null
""")
            first=json.loads(ps(SNAPSHOT));self.validate(first)
            self.assertEqual(first['state_code'],1)
            ps(CHANGE)
            after=json.loads(ps(SNAPSHOT));self.assertEqual(validate_task(after,project,python),new)
            # Same stale CAS cannot migrate the already changed task again.
            stale=CHANGE.replace("throw 'History task changed since inspection'", "exit 17")
            command=base64.b64encode(stale.replace('P24-CompactHistory',name).encode('utf-16le')).decode()
            r=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',command],env=env,capture_output=True,timeout=30)
            self.assertEqual(r.returncode,17)
        finally:
            ps("Get-ScheduledTask -TaskName 'P24-CompactHistory' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false")

    @unittest.skipUnless(os.name == 'nt', 'native Windows Task Scheduler required')
    def test_native_drain_stops_only_the_disabled_launcher(self):
        import tempfile
        from pathlib import Path
        from tools.Repair_Compact_History_Task import DRAIN, SNAPSHOT
        from viewer_performance.financial_screen.host import powershell
        name='P24-DrainTest-'+uuid.uuid4().hex
        def run(script):
            return powershell(script.replace('P24-CompactHistory',name),env)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'compact_product').mkdir()
            (root/'compact_product/History_Compact_Product.ps1').write_text(
                "param($Action,$Project,$Python)\nSet-Content -LiteralPath (Join-Path $Project 'started') -Value yes\nStart-Sleep 150",
                encoding='utf-8')
            python=os.path.join(folder,'dummy.exe')
            env=dict(P24_OLD_ROOT=folder,P24_OLD_ARGS=worker_args(folder,folder,python),P24_DRAIN_PROJECT=folder)
            try:
                run(r"""
$a=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $env:P24_OLD_ARGS -WorkingDirectory $env:P24_OLD_ROOT
Register-ScheduledTask -TaskPath '\' -TaskName 'P24-CompactHistory' -Action $a -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskPath '\' -TaskName 'P24-CompactHistory'
for($i=0;$i -lt 70;$i++){if(Test-Path (Join-Path $env:P24_OLD_ROOT 'started')){break};Start-Sleep -Milliseconds 200}
if(!(Test-Path (Join-Path $env:P24_OLD_ROOT 'started'))){throw 'test launcher did not start'}
Disable-ScheduledTask -TaskPath '\' -TaskName 'P24-CompactHistory' | Out-Null
""")
                first=run(SNAPSHOT)
                self.assertFalse(first['enabled'])
                self.assertGreater(first['instances'],0)
                self.assertEqual(run(DRAIN)['status'],'OWNED_LAUNCHER_STOP_REQUESTED')
                final=wait_for_stopped_task(lambda:run(SNAPSHOT),folder,python,timeout=30)
                self.assertEqual(final['instances'],0)
                self.assertEqual(run(DRAIN)['status'],'ALREADY_DRAINED')
            finally:
                run(r"""
$t=Get-ScheduledTask -TaskPath '\' -TaskName 'P24-CompactHistory' -ErrorAction SilentlyContinue
if($t){Stop-ScheduledTask -InputObject $t -ErrorAction SilentlyContinue;Unregister-ScheduledTask -InputObject $t -Confirm:$false}
""")

    @unittest.skipUnless(os.name == 'nt', 'native Windows PowerShell required')
    def test_native_powershell_parses_migration_and_snapshot(self):
        from tools.Repair_Compact_History_Task import CHANGE,SNAPSHOT
        for script in (CHANGE,SNAPSHOT):
            encoded=base64.b64encode(script.encode('utf-8')).decode()
            check="$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+encoded+"'));$t=$null;$e=$null;[System.Management.Automation.Language.Parser]::ParseInput($s,[ref]$t,[ref]$e)|Out-Null;if($e.Count){throw 'parse failed'}"
            command=base64.b64encode(check.encode('utf-16le')).decode()
            result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',command],capture_output=True,timeout=30)
            self.assertEqual(result.returncode,0)
