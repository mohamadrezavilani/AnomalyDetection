"""Real nested AD CLI pipes remain strict and readable under a legacy locale."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from viewer_performance import Run_Viewer_Index_Probe_UTF8 as entry

ROOT=Path(__file__).resolve().parents[1]


class UTF8EntryTests(unittest.TestCase):
    def test_actual_launcher_reexecutes_once_then_blocks_before_database_without_config(self):
        with tempfile.TemporaryDirectory() as folder:
            project=Path(folder)
            # Copy pinned public code only. No local config, keys, database,
            # process reports or product data can enter this fixture.
            for directory in ('p24_foundation','tools','review_ui','catalogs'):
                for source in (ROOT/directory).rglob('*'):
                    if source.is_file() and source.suffix in ('.py','.html','.css','.js','.json','.csv') and '__pycache__' not in source.parts:
                        target=project/source.relative_to(ROOT);target.parent.mkdir(parents=True,exist_ok=True)
                        shutil.copyfile(source,target)
            body=(ROOT/'viewer_performance/CAPACITY_MANIFEST.json').read_bytes()
            mf=project/'viewer_performance/CAPACITY_MANIFEST.json';mf.parent.mkdir(parents=True,exist_ok=True);mf.write_bytes(body)
            for name in json.loads(body)['files_sha256']:
                if name.startswith('viewer_performance/') and name.endswith('.py'):
                    target=project/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,target)
            env=dict(os.environ,PYTHONUTF8='0',PYTHONIOENCODING='ascii')
            result=subprocess.run([sys.executable,'-B',entry.__file__,'--project',str(project),'--seconds','10'],
                env=env,capture_output=True,encoding='utf-8',timeout=20)
            self.assertEqual(result.returncode,2,result.stderr)
            value=json.loads(result.stdout)
            self.assertEqual(value['code'],'literal_database_config_required')
            self.assertFalse(value['database_modified']);self.assertFalse(value['workers_restarted'])

    def test_real_legacy_status_failure_and_utf8_round_trip_preserve_process_gates(self):
        from AnomalyDetection.anomaly_detection import BUILD_ID
        from AnomalyDetection.anomaly_detection.process_control import OwnedProcessLock,write_json
        from viewer_performance import Observe_Viewer_Index_Parallel as shared
        with tempfile.TemporaryDirectory() as folder:
            project=Path(folder);ad=project/'AnomalyDetection';ad.mkdir()
            (ad/'RELEASE_MANIFEST.json').write_text(json.dumps(dict(build_id=BUILD_ID,source_sha256='fixture-source')))
            (ad/'run_anomaly.py').write_text('import sys\nfrom pathlib import Path\n'
                'sys.path.insert(0,'+repr(str(ROOT/'AnomalyDetection'))+')\n'
                'from anomaly_detection import product_cli\n'
                'product_cli.ROOT=Path('+repr(str(ad))+')\n'
                'raise SystemExit(product_cli.main("fixture-source"))\n',encoding='utf-8')
            verifier=project/'verify_status.py'
            verifier.write_text('import sys,json\nfrom pathlib import Path\n'
                'sys.path.insert(0,'+repr(str(ROOT))+')\n'
                'from viewer_performance.Observe_Viewer_Index_Parallel import ad_status\n'
                'try:\n value=ad_status(Path('+repr(str(project))+'))\n'
                'except ValueError as exc:\n print(json.dumps({"code":str(exc)}));raise SystemExit(2)\n'
                'print(json.dumps(value,ensure_ascii=False))\n',encoding='utf-8')
            with patch.dict(os.environ,{'PYTHONUTF8':'0','PYTHONIOENCODING':'ascii'}):
                with OwnedProcessLock(ad,'baseline_worker','fixture-source') as locked:
                    write_json(ad/'reports/product_status.json',dict(locked.owner,state='RUNNING',
                        phase='خواندن وضعیت فارسی',heartbeat_ns=time.time_ns()))
                    with self.assertRaisesRegex(ValueError,'ad_status_command_failed'):shared.ad_status(project)
                    result=entry.run_utf8([sys.executable,'-B',str(verifier)],timeout=8)
                    self.assertEqual(result.returncode,0,result.stderr)
                    value=json.loads(result.stdout)
                    self.assertEqual(value['counters']['phase'],'خواندن وضعیت فارسی')
                    self.assertEqual(value['instance_token'],locked.owner['instance_token'])
                stopped=entry.run_utf8([sys.executable,'-B',str(verifier)],timeout=8)
                self.assertEqual(stopped.returncode,2)
                self.assertEqual(json.loads(stopped.stdout)['code'],'current_ad_process_with_fresh_heartbeat_required')
                self.assertEqual(os.environ['PYTHONUTF8'],'0')
                self.assertEqual(os.environ['PYTHONIOENCODING'],'ascii')

    def test_pinned_shared_sources_match_the_unchanged_manifest(self):
        shared_sha=entry.verify_sources(ROOT)
        self.assertEqual(len(shared_sha),64)
        with tempfile.TemporaryDirectory() as folder:
            project=Path(folder);(project/'viewer_performance').mkdir()
            (project/'viewer_performance/CAPACITY_MANIFEST.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'shared_capacity_manifest_mismatch'):
                entry.verify_sources(project)

    def test_entrypoint_help_works_outside_project_without_pythonpath(self):
        with tempfile.TemporaryDirectory() as folder:
            result=subprocess.run([sys.executable,'-B',entry.__file__,'--help'],cwd=folder,
                env={k:v for k,v in os.environ.items() if k!='PYTHONPATH'},capture_output=True,text=True,timeout=8)
            self.assertEqual(result.returncode,0,result.stderr)

    def test_invalid_budget_is_blocked_before_any_source_or_worker_operation(self):
        with patch.object(entry,'verify_sources',side_effect=AssertionError('must not read source')):
            with patch('builtins.print') as printed:
                result=entry.main(['--project',str(ROOT),'--seconds','0'])
            self.assertEqual(result,2)
            self.assertEqual(json.loads(printed.call_args[0][0])['code'],'parallel_probe_budget_must_be_10_to_60_seconds')


if __name__=='__main__':unittest.main()
