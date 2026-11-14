"""Byte-pinned Windows entrypoints survive Git checkout without relaxing hashes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from tools.check_viewer_install import verify_release
from p24_foundation.viewer_runtime import runtime_source_digest

ROOT=Path(__file__).resolve().parents[1]
LAUNCHERS=('Start_Viewer.cmd','Start_Viewer_Standard.cmd','tools/viewer.ps1')
spec=importlib.util.spec_from_file_location('launcher_repair',ROOT/'viewer_performance/Repair_Viewer_Launchers.py')
repair_tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(repair_tool)


def git_fixture(root):
    def git(*args):
        return subprocess.check_output(['git',*args],cwd=root,stderr=subprocess.DEVNULL)
    git('init','-b','old');git('config','user.name','Fixture');git('config','user.email','fixture@example.invalid')
    (root/'.gitattributes').write_bytes(b'* -text\n')
    expected={}
    for name in LAUNCHERS:
        path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'# original launcher\n')
        expected[name]=hashlib.sha256(path.read_bytes()).hexdigest()
    (root/'RELEASE_MANIFEST.json').write_text(json.dumps({'files_sha256':expected}))
    (root/'operator.txt').write_bytes(b'original operator file\n')
    git('add','.');git('commit','-m','original')
    return git


class LauncherBytesTests(unittest.TestCase):
    @unittest.skipUnless(os.name=='nt','Windows launcher forwarding and readiness')
    def test_windows_start_forwards_lan_host_and_reports_only_matching_health(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'tools').mkdir();(root/'viewer_performance').mkdir()
            (root/'viewer_config.local.py').write_text('# fixture only\n')
            (root/'RELEASE_MANIFEST.json').write_text(json.dumps({'runtime_source_sha256':'fixture-runtime'}))
            (root/'tools/check_viewer_install.py').write_text("print('{\"status\":\"READY_TO_START\"}')\n")
            for name in ('tools/viewer.ps1','viewer_performance/viewer.ps1'):
                (root/name).write_bytes((ROOT/name).read_bytes())
            capture=root/'children.jsonl'
            code="""$ErrorActionPreference='Stop'
function Start-Process { param($FilePath,$WorkingDirectory,$ArgumentList)
    @{argv=$ArgumentList} | ConvertTo-Json -Compress | Add-Content -Encoding UTF8 -LiteralPath $env:P24_VIEWER_TEST_CAPTURE
}
function Invoke-WebRequest { param($Uri,[switch]$UseBasicParsing,$TimeoutSec)
    [pscustomobject]@{Content='{"status":"ok","service":"viewer","runtime_sha256":"fixture-runtime"}'}
}
& (Join-Path $env:P24_VIEWER_TEST_ROOT $env:P24_VIEWER_TEST_SCRIPT) -Action Start -Python $env:P24_VIEWER_TEST_PYTHON -WebHost '10.20.30.40' -ResumeCheckpoint
"""
            for script in ('tools/viewer.ps1','viewer_performance/viewer.ps1'):
                env=dict(os.environ,P24_VIEWER_TEST_CAPTURE=str(capture),P24_VIEWER_TEST_ROOT=str(root),
                         P24_VIEWER_TEST_SCRIPT=script,P24_VIEWER_TEST_PYTHON=sys.executable)
                result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',code],
                    cwd=root,env=env,capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertIn('VIEWER_WEB_READY',result.stdout)
                self.assertIn('10.20.30.40:5021',result.stdout)
            children=[json.loads(line)['argv'] for line in capture.read_text(encoding='utf-8-sig').splitlines()]
            self.assertEqual(len(children),4)
            for args in children:
                self.assertIn('-ResumeCheckpoint',args)
                self.assertEqual(args[args.index('-WebHost')+1],'"10.20.30.40"')

    def test_matching_manifest_with_mode_changes_is_repaired_in_git_too(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);git=git_fixture(root)
            if os.name=='nt':
                git('update-index','--chmod=+x','--',*LAUNCHERS)
            else:
                git('config','core.filemode','true')
                for name in LAUNCHERS:(root/name).chmod(0o755)
            (root/'operator.txt').write_bytes(b'preserve this local edit\n')
            report=root/'validation/installation_check.json';report.parent.mkdir();report.write_bytes(b'{}\n')
            manifest=json.loads((root/'RELEASE_MANIFEST.json').read_text())
            for name in LAUNCHERS:
                self.assertEqual(hashlib.sha256((root/name).read_bytes()).hexdigest(),manifest['files_sha256'][name])
            self.assertNotEqual(git('diff','HEAD','--name-only','--',*LAUNCHERS),b'')
            result=repair_tool.repair(root)
            self.assertEqual(result['status'],'EXACT_LAUNCHER_BYTES_REPAIRED')
            self.assertTrue(result['git_launchers_clean'])
            self.assertEqual(git('diff','HEAD','--name-only','--',*LAUNCHERS),b'')
            self.assertEqual(git('diff','--cached','--name-only','--',*LAUNCHERS),b'')
            self.assertEqual((root/'operator.txt').read_bytes(),b'preserve this local edit\n')
            self.assertEqual(report.read_bytes(),b'{}\n')

    def test_staged_crlf_is_repaired_even_when_working_bytes_already_match(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);git=git_fixture(root)
            for name in LAUNCHERS:(root/name).write_bytes(b'# original launcher\r\n')
            git('add','--',*LAUNCHERS)
            for name in LAUNCHERS:(root/name).write_bytes(b'# original launcher\n')
            self.assertNotEqual(git('diff','--cached','--name-only'),b'')
            result=repair_tool.repair(root)
            self.assertTrue(result['git_launchers_clean'])
            self.assertEqual(git('status','--porcelain'),b'')

    def test_real_staged_edit_is_preserved_even_if_working_files_match_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);git=git_fixture(root)
            path=root/LAUNCHERS[-1];original=path.read_bytes()
            path.write_bytes(b'# preserve this staged operator edit\n');git('add','--',LAUNCHERS[-1])
            path.write_bytes(original)
            before=git('diff','--cached','--binary')
            with self.assertRaisesRegex(ValueError,'LAUNCHER_INDEX_CONTENT_CHANGED'):
                repair_tool.repair(root)
            self.assertEqual(git('diff','--cached','--binary'),before)
            self.assertEqual(path.read_bytes(),original)

    @unittest.skipUnless(os.name=='nt','Windows PowerShell bootstrap')
    def test_windows_stdin_bootstrap_repairs_git_before_fast_forwarding(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);git=git_fixture(root)
            git('checkout','-b','new')
            script=root/'viewer_performance/Repair_Viewer_Launchers.py'
            script.parent.mkdir();script.write_bytes((ROOT/'viewer_performance/Repair_Viewer_Launchers.py').read_bytes())
            (root/LAUNCHERS[0]).write_bytes(b'# new launcher\n')
            git('add','.');git('commit','-m','new packaging');git('checkout','old')
            self.assertFalse(script.exists())
            git('update-index','--chmod=+x','--',*LAUNCHERS)
            self.assertNotEqual(subprocess.run(['git','merge','--ff-only','new'],cwd=root,capture_output=True).returncode,0)
            code="$ErrorActionPreference='Stop';$src=git show new:viewer_performance/Repair_Viewer_Launchers.py;if($LASTEXITCODE){exit $LASTEXITCODE};$src | & $env:P24_REPAIR_TEST_PYTHON -B - --project-root .;if($LASTEXITCODE){exit $LASTEXITCODE};git merge --ff-only new;exit $LASTEXITCODE"
            env=dict(os.environ,P24_REPAIR_TEST_PYTHON=sys.executable)
            result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',code],
                cwd=root,env=env,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn('"git_launchers_clean": true',result.stdout)
            self.assertTrue(script.is_file())
            self.assertEqual((root/LAUNCHERS[0]).read_bytes(),b'# new launcher\n')

    def test_guarded_repair_then_fast_forward_upgrades_old_crlf_working_files(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture=Path(temp)
            def git(*args):
                return subprocess.check_output(['git',*args],cwd=fixture,stderr=subprocess.DEVNULL)
            git('init','-b','old');git('config','user.name','Fixture');git('config','user.email','fixture@example.invalid')
            git('config','core.autocrlf','true')
            (fixture/'.gitattributes').write_bytes(b'* text=auto eol=lf\n')
            for name in LAUNCHERS:
                path=fixture/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'# old launcher\n')
            def manifest():
                (fixture/'RELEASE_MANIFEST.json').write_text(json.dumps({'files_sha256':{
                    n:hashlib.sha256((fixture/n).read_bytes()).hexdigest() for n in LAUNCHERS}}))
            manifest()
            git('add','.');git('commit','-m','old')
            git('checkout','-b','new')
            (fixture/'.gitattributes').write_bytes((ROOT/'.gitattributes').read_bytes())
            for name in LAUNCHERS:(fixture/name).write_bytes((ROOT/name).read_bytes())
            manifest()
            git('add','.');git('commit','-m','byte-pinned launchers');git('checkout','old')
            for name in LAUNCHERS:
                path=fixture/name;path.write_bytes(path.read_bytes().replace(b'\r\n',b'\n').replace(b'\n',b'\r\n'))
            self.assertNotEqual(git('status','--porcelain'),b'')
            self.assertEqual(repair_tool.repair(fixture)['status'],'EXACT_LAUNCHER_BYTES_REPAIRED')
            self.assertEqual(git('status','--porcelain'),b'')
            git('merge','--ff-only','new')
            for name in LAUNCHERS:self.assertEqual((fixture/name).read_bytes(),(ROOT/name).read_bytes())
            self.assertEqual(repair_tool.repair(fixture)['status'],'ALREADY_MATCH')

    def test_repair_refuses_real_edits_before_writing_any_launcher(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);expected={}
            for name in LAUNCHERS:
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'unchanged\r\n')
                expected[name]=hashlib.sha256(b'unchanged\n').hexdigest()
            (root/LAUNCHERS[-1]).write_bytes(b'operator edit\r\n')
            (root/'RELEASE_MANIFEST.json').write_text(json.dumps({'files_sha256':expected}))
            before={name:(root/name).read_bytes() for name in LAUNCHERS}
            with self.assertRaisesRegex(ValueError,'LAUNCHER_CONTENT_CHANGED'):repair_tool.repair(root)
            self.assertEqual(before,{name:(root/name).read_bytes() for name in LAUNCHERS})

    def test_whole_release_has_exact_installed_bytes(self):
        result=verify_release(ROOT)
        self.assertEqual(result['status'],'PASS',result)
    def test_exact_manifest_bytes_are_crlf_and_git_marks_them_non_text(self):
        manifest=json.loads((ROOT/'RELEASE_MANIFEST.json').read_text(encoding='utf-8'))
        for name in LAUNCHERS:
            content=(ROOT/name).read_bytes()
            self.assertIn(b'\r\n',content)
            self.assertNotIn(b'\n',content.replace(b'\r\n',b''))
            self.assertEqual(hashlib.sha256(content).hexdigest(),manifest['files_sha256'][name])
        output=subprocess.check_output(['git','check-attr','text','--',*LAUNCHERS],cwd=ROOT,text=True)
        self.assertTrue(all(line.endswith(': text: unset') for line in output.splitlines()))
    def test_strict_release_check_still_rejects_changed_bytes_including_newline_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);name=LAUNCHERS[0];data=(ROOT/name).read_bytes()
            (root/name).write_bytes(data)
            (root/'RELEASE_MANIFEST.json').write_text(json.dumps({'files_sha256':{name:hashlib.sha256(data).hexdigest()}}))
            self.assertEqual(verify_release(root)['status'],'PASS')
            (root/name).write_bytes(data.replace(b'\r\n',b'\n'))
            self.assertEqual(verify_release(root)['mismatches'],[name])
    def test_release_runtime_has_an_exact_supported_pin_and_verified_ad_identity(self):
        import runpy
        profiles=runpy.run_path(str(ROOT/'AnomalyDetection/anomaly_detection/source_profiles.py'))
        self.assertEqual(runtime_source_digest(ROOT),profiles['R37_RUNTIME'])
        module=runpy.run_path(str(ROOT/'AnomalyDetection/run_anomaly.py'))
        declared=json.loads((ROOT/'AnomalyDetection/RELEASE_MANIFEST.json').read_text())
        self.assertEqual(module['verify_build'](),declared['source_sha256'])
        self.assertEqual(module['EXPECTED_BUILD'],'AD-20261114-POINT-PROBES')

    @unittest.skipUnless(os.name=='nt','Windows PowerShell parser')
    def test_both_launcher_scripts_parse_in_windows_powershell(self):
        code="$ErrorActionPreference='Stop';foreach($p in @('tools/viewer.ps1','viewer_performance/viewer.ps1')){$t=$null;$e=$null;[System.Management.Automation.Language.Parser]::ParseFile((Join-Path (Get-Location) $p),[ref]$t,[ref]$e)|Out-Null;if($e.Count){throw 'launcher_parse_failed'}}"
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',code],cwd=ROOT,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)


if __name__=='__main__':unittest.main()
