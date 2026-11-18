"""Real PowerShell/Git upgrade plumbing using a synthetic lifecycle controller.

No database/service is opened. This qualifies installer failure recovery and
preservation, not native Windows PostgreSQL or production stop/restore health.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

CONTROLLER='''import argparse,json,os
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--project');p.add_argument('--receipt');p.add_argument('--action');p.add_argument('--reviewed-preflight');p.add_argument('--max-seconds');a=p.parse_args()
r=Path(a.receipt);state=json.loads(r.read_text()) if r.exists() else {}
phase=os.environ.get('P24_TEST_INSTALL_PHASE','pass');code=0
if a.action=='prepare-update':state={'status':'PREPARED_FOR_MAIN_UPDATE'}
elif a.action=='restore':state['status']='PREVIOUS_ROLES_RESTORED'
elif phase=='before_scope':code=2
elif phase=='after_scope':state.update(status='PREVIOUS_ROLES_RESTORED',scope_command={'action':'enable'});code=2
elif phase=='repair':state.update(status='RESTORING_FULL_SUPERVISORS_LEFT_DISABLED',scope_command={'action':'restore-full'});code=2
else:state.update(status='PREVIOUS_ROLES_RESTORED',scope_command={'action':'enable'})
r.write_text(json.dumps(state));print(json.dumps(state));raise SystemExit(code)
'''


@unittest.skipUnless(os.name=='nt','native Windows PowerShell/Git required')
class NativeWindowsInstallerTests(unittest.TestCase):
    def test_real_fast_forward_and_failures_preserve_ignored_evidence(self):
        installer=Path(__file__).resolve().parents[1]/'viewer_performance/Install_Behavior.ps1'
        def quote(value):return "'"+str(value).replace("'","''")+"'"
        for phase in ('pass','before_scope','after_scope','repair'):
            with self.subTest(phase=phase),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);project=root/'project';project.mkdir();remote=root/'remote.git'
                def git(*args,cwd=project):
                    result=subprocess.run(['git',*args],cwd=cwd,capture_output=True,text=True,timeout=30)
                    if result.returncode:raise AssertionError(result.stderr)
                    return result.stdout.strip()
                git('init','-b','main');git('config','user.email','fixture@example.invalid');git('config','user.name','Fixture')
                (project/'.gitignore').write_text('.venv/\nprivate/\nAnomalyDetection/reports/\n')
                (project/'old.txt').write_text('installed old checkout');git('add','.');git('commit','-m','fixture old');old=git('rev-parse','HEAD')
                (project/'viewer_performance').mkdir();(project/'viewer_performance/Behavior_Release.py').write_text(CONTROLLER)
                git('add','.');git('commit','-m','fixture reviewed target');target=git('rev-parse','HEAD')
                git('clone','--bare',str(project),str(remote),cwd=root);git('remote','add','origin',str(remote));git('reset','--hard',old)
                subprocess.run([sys.executable,'-m','venv','--without-pip',str(project/'.venv')],check=True,capture_output=True,timeout=60)
                (project/'private').mkdir();evidence=project/'private/evidence.bin';evidence.write_bytes(b'untouched private evidence')
                harness=root/'harness.ps1'
                harness.write_text("$ErrorActionPreference='Stop'\n$global:P24FixtureGit=(Get-Command git -CommandType Application | Select-Object -First 1).Source\nfunction global:git { if($args[0] -eq 'remote' -and $args[1] -eq 'get-url'){ 'https://github.com/mohamadrezavilani/AnomalyDetection.git'; $global:LASTEXITCODE=0 } else { & $global:P24FixtureGit @args; $global:LASTEXITCODE=$LASTEXITCODE } }\n& "+quote(installer)+' -Project '+quote(project)+' -TargetCommit '+quote(target)+' -SkipBenchmark\n',encoding='utf-8')
                result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(harness)],
                                      env=dict(os.environ,P24_TEST_INSTALL_PHASE=phase),capture_output=True,text=True,timeout=90)
                self.assertEqual(result.returncode==0,phase=='pass',result.stdout+result.stderr)
                self.assertEqual(git('rev-parse','HEAD'),old if phase=='before_scope' else target)
                self.assertEqual(evidence.read_bytes(),b'untouched private evidence')
                receipt=next(project.glob('AnomalyDetection/reports/Behavior_Release_*/release.json'))
                state=json.loads(receipt.read_text())
                self.assertEqual(state['status'],'RESTORING_FULL_SUPERVISORS_LEFT_DISABLED' if phase=='repair' else 'PREVIOUS_ROLES_RESTORED')


if __name__=='__main__':unittest.main()
