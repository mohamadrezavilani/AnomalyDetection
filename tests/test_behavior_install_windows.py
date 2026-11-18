"""Real PowerShell/Git upgrade plumbing using a synthetic lifecycle controller.

No database/service is opened. Only the repository URL literal is replaced
with the disposable bare repository; all Git commands use the real executable.
This is not native Windows PostgreSQL or production stop/restore health.
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
if a.action=='prepare-update':
 state={'status':'PREPARED_FOR_MAIN_UPDATE'}
 if phase=='late_edit':(Path(a.project)/'old.txt').write_text('preserve concurrent edit')
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
        for phase in ('pass','before_scope','after_scope','repair','generated_report','dirty_code','staged_report','late_edit'):
            with self.subTest(phase=phase),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);project=root/'project';project.mkdir();remote=root/'remote.git'
                def git(*args,cwd=project):
                    result=subprocess.run(['git',*args],cwd=cwd,capture_output=True,text=True,timeout=30)
                    if result.returncode:raise AssertionError(result.stderr)
                    return result.stdout.strip()
                git('init','-b','main');git('config','user.email','fixture@example.invalid');git('config','user.name','Fixture')
                (project/'.gitignore').write_text('.venv/\nprivate/\nAnomalyDetection/reports/\n')
                (project/'old.txt').write_text('installed old checkout')
                startup=project/'validation/viewer_startup.json';startup.parent.mkdir()
                startup.write_text(json.dumps(dict(mode='RESUME_CHECKPOINT',runtime_source_sha256='a'*64,live=dict(generation=1))))
                git('add','.');git('commit','-m','fixture old');old=git('rev-parse','HEAD')
                (project/'viewer_performance').mkdir();(project/'viewer_performance/Behavior_Release.py').write_text(CONTROLLER)
                (project/'viewer_performance/behavior_install_git.py').write_bytes((installer.parent/'behavior_install_git.py').read_bytes())
                git('add','.');git('commit','-m','fixture reviewed target');target=git('rev-parse','HEAD')
                git('clone','--bare',str(project),str(remote),cwd=root)
                git('remote','add','origin',str(remote))
                git('reset','--hard',old)
                subprocess.run([sys.executable,'-m','venv','--without-pip',str(project/'.venv')],check=True,capture_output=True,timeout=60)
                (project/'private').mkdir();evidence=project/'private/evidence.bin';evidence.write_bytes(b'untouched private evidence')
                if phase in ('generated_report','staged_report'):
                    startup.write_text(json.dumps(dict(mode='RESUME_CHECKPOINT',runtime_source_sha256='a'*64,live=dict(generation=99))))
                    if phase=='staged_report':git('add','validation/viewer_startup.json')
                if phase=='dirty_code':(project/'old.txt').write_text('preserve operator edit')
                report_bytes=startup.read_bytes()
                selected=root/'Install_Behavior.ps1'
                text=installer.read_text(encoding='utf-8')
                original="'https://github.com/mohamadrezavilani/anomalydetection.git'"
                self.assertEqual(text.count(original),1)
                selected.write_text(text.replace(original,quote(str(remote).lower())),encoding='utf-8')
                harness=root/'harness.ps1'
                harness.write_text("$ErrorActionPreference='Stop'\n& "+quote(selected)+' -Project '+quote(project)+' -TargetCommit '+quote(target)+' -SkipBenchmark\n',encoding='utf-8')
                result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(harness)],
                                      env=dict(os.environ,P24_TEST_INSTALL_PHASE=phase),capture_output=True,text=True,timeout=90)
                self.assertEqual(result.returncode==0,phase in ('pass','generated_report'),result.stdout+result.stderr)
                self.assertEqual(git('rev-parse','HEAD'),old if phase in ('before_scope','dirty_code','staged_report','late_edit') else target)
                self.assertEqual(evidence.read_bytes(),b'untouched private evidence')
                self.assertEqual(startup.read_bytes(),report_bytes)
                if phase in ('dirty_code','staged_report'):
                    self.assertFalse(list(project.glob('AnomalyDetection/reports/Behavior_Release_*/release.json')))
                    check=json.loads(next(project.glob('AnomalyDetection/reports/Behavior_Release_*/git-precheck.json')).read_text())
                    self.assertEqual(check['status'],'INSTALL_GIT_BLOCKED')
                    self.assertTrue(check['blocking_changes'])
                    self.assertIn(check['blocking_changes'][0]['path'],result.stdout)
                    continue
                if phase=='late_edit':
                    self.assertEqual((project/'old.txt').read_text(),'preserve concurrent edit')
                    check=json.loads(next(project.glob('AnomalyDetection/reports/Behavior_Release_*/git-frozen-check.json')).read_text())
                    self.assertEqual(check['status'],'INSTALL_GIT_BLOCKED')
                receipt=next(project.glob('AnomalyDetection/reports/Behavior_Release_*/release.json'))
                state=json.loads(receipt.read_text())
                self.assertEqual(state['status'],'RESTORING_FULL_SUPERVISORS_LEFT_DISABLED' if phase=='repair' else 'PREVIOUS_ROLES_RESTORED')


if __name__=='__main__':unittest.main()
