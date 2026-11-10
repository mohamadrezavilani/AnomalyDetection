"""Byte-pinned Windows entrypoints survive Git checkout without relaxing hashes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from tools.check_viewer_install import verify_release
from p24_foundation.viewer_runtime import runtime_source_digest

ROOT=Path(__file__).resolve().parents[1]
LAUNCHERS=('Start_Viewer.cmd','Start_Viewer_Standard.cmd','tools/viewer.ps1')
spec=importlib.util.spec_from_file_location('launcher_repair',ROOT/'viewer_performance/Repair_Viewer_Launchers.py')
repair_tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(repair_tool)


class LauncherBytesTests(unittest.TestCase):
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
    def test_launcher_only_fix_preserves_viewer_runtime_and_ad_identity(self):
        self.assertEqual(runtime_source_digest(ROOT),'7664ee33a6f2be3257796f9b53780e9b1a1e6d06e37f7022bed46ca66cbbce55')
        import runpy
        module=runpy.run_path(str(ROOT/'AnomalyDetection/run_anomaly.py'))
        self.assertEqual(module['verify_build'](),'49495da2c80b81208ebaae0834de301160b7e73794653938cdfbd3082449a86d')

    @unittest.skipUnless(os.name=='nt','Windows PowerShell parser')
    def test_both_launcher_scripts_parse_in_windows_powershell(self):
        code="$ErrorActionPreference='Stop';foreach($p in @('tools/viewer.ps1','viewer_performance/viewer.ps1')){$t=$null;$e=$null;[System.Management.Automation.Language.Parser]::ParseFile((Join-Path (Get-Location) $p),[ref]$t,[ref]$e)|Out-Null;if($e.Count){throw 'launcher_parse_failed'}}"
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',code],cwd=ROOT,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)


if __name__=='__main__':unittest.main()
