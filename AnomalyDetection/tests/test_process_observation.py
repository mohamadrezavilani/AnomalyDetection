"""Read failures must not erase OS locks or imply a stopped/verified worker."""
import errno
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

from anomaly_detection import process_control as processes, product_control as control


class ProcessObservationTests(unittest.TestCase):
    def denied(self, path, default=None):
        if Path(path).name == 'baseline_process.json':
            raise PermissionError(errno.EACCES, 'private-error-text', 'private-path')
        return self.read_json(path, default)

    def setUp(self):
        self.read_json = processes.read_json

    def test_permission_failure_preserves_a_real_busy_lock_without_owner_guessing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with processes.OwnedProcessLock(root, 'baseline_worker', 'sha') as lock:
                with patch.object(processes, 'read_json', side_effect=self.denied), patch.object(processes.time, 'sleep'):
                    owner = processes.process_owner(root)
                self.assertTrue(owner['locked'])
                self.assertIsNone(owner['owner'])
                self.assertEqual(owner['owner_read_status'], 'UNAVAILABLE')
                self.assertEqual(owner['owner_read_failure']['errno'], errno.EACCES)
                self.assertNotIn('private-', json.dumps(owner))
                self.assertTrue(processes.process_owner(root)['locked'])
                self.assertEqual(processes.process_owner(root)['owner']['instance_token'], lock.owner['instance_token'])

    def test_transient_metadata_denial_is_retried_and_returns_the_actual_owner(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with processes.OwnedProcessLock(root, 'baseline_worker', 'sha') as lock:
                attempts = []
                def read(path, default=None):
                    attempts.append(path)
                    if len(attempts) == 1:
                        raise PermissionError(errno.EACCES, 'private-error-text')
                    return self.read_json(path, default)
                with patch.object(processes, 'read_json', side_effect=read), patch.object(processes.time, 'sleep'):
                    owner = processes.process_owner(root)
                self.assertEqual(owner['owner'], lock.owner)
                self.assertEqual(len(attempts), 2)
                self.assertEqual(owner['owner_read_status'], 'AVAILABLE')

    def test_unreadable_metadata_with_a_free_lock_does_not_make_the_lock_busy(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with processes.OwnedProcessLock(root, 'baseline_worker', 'sha'):
                pass
            with patch.object(processes, 'read_json', side_effect=self.denied), patch.object(processes.time, 'sleep'):
                owner = processes.process_owner(root)
            self.assertFalse(owner['locked'])
            self.assertIsNone(owner['owner'])
            with processes.OwnedProcessLock(root, 'baseline_worker', 'new-sha'):
                self.assertTrue(processes.process_owner(root)['locked'])

    def test_unreadable_owner_is_unknown_even_if_a_recent_heartbeat_has_a_token(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with processes.OwnedProcessLock(root, 'baseline_worker', 'sha') as lock:
                processes.write_json(root/'reports/product_status.json', dict(lock.owner, state='RUNNING', heartbeat_ns=time.time_ns()))
                with patch.object(processes, 'read_json', side_effect=self.denied), patch.object(processes.time, 'sleep'):
                    observed = control.status(root)
                self.assertEqual(observed['health'], 'PROCESS_IDENTITY_UNAVAILABLE')
                self.assertIsNone(observed['running'])
                self.assertFalse(observed['observation_matches_process'])
                self.assertTrue(observed['process']['locked'])
                self.assertEqual(observed['diagnostic_failures'][0]['stage'], 'worker_identity')

    def test_missing_owner_token_never_matches_an_unrelated_heartbeat(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with processes.OwnedProcessLock(root, 'baseline_worker', 'sha'):
                processes.write_json(root/'data/baseline_process.json', {})
                processes.write_json(root/'reports/product_status.json', {'state':'RUNNING', 'heartbeat_ns':time.time_ns()})
                observed = control.status(root)
                self.assertEqual(observed['health'], 'PROCESS_IDENTITY_UNAVAILABLE')
                self.assertFalse(observed['observation_matches_process'])

    def test_start_cannot_spawn_when_the_busy_lock_identity_is_unavailable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with processes.OwnedProcessLock(root, 'baseline_worker', 'sha'):
                with patch.object(processes, 'read_json', side_effect=self.denied), patch.object(processes.time, 'sleep'), patch.object(control, 'spawn') as spawn:
                    result = control.start(root, 'sha')
                self.assertEqual(result['status'], 'PROCESS_IDENTITY_UNAVAILABLE')
                spawn.assert_not_called()

    def test_stop_does_not_report_already_stopped_or_write_when_owner_cannot_be_read(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with processes.OwnedProcessLock(root, 'baseline_worker', 'sha'):
                with patch.object(processes, 'read_json', side_effect=self.denied), patch.object(processes.time, 'sleep'), patch.object(control, 'write_json') as write:
                    result = control.stop(root, wait_seconds=0)
                self.assertEqual(result['status'], 'STOP_BLOCKED_IDENTITY_UNAVAILABLE')
                self.assertEqual(result['resources'], ['baseline'])
                write.assert_not_called()

    def test_worker_export_retains_unknown_identity_and_cannot_claim_same_instance(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with processes.OwnedProcessLock(root, 'baseline_worker', 'sha'):
                with patch.object(processes, 'read_json', side_effect=self.denied), patch.object(processes.time, 'sleep'), patch('anomaly_detection.product_diagnostics.snapshot', return_value={'status':'NOT_RUN_FIXTURE'}):
                    observed, output = control.export_report(root, 'sha', observe_seconds=0)
                self.assertEqual(observed['health'], 'PROCESS_IDENTITY_UNAVAILABLE')
                with zipfile.ZipFile(output) as archive:
                    value = json.loads(archive.read('worker_observation.json'))
                self.assertFalse(value['same_instance'])
                self.assertFalse(value['process_identity_verified'])
                self.assertFalse(value['observation_complete'])

    def test_credentials_still_fail_closed_instead_of_using_observer_fallback(self):
        with patch.object(Path, 'read_text', side_effect=PermissionError(errno.EACCES, 'private-error-text')), patch.object(Path, 'is_file', return_value=True), patch.object(Path, 'stat') as stat:
            stat.return_value.st_size = 10
            with self.assertRaises(PermissionError):
                processes.read_json(Path('pg_credentials.local.json'))

    def test_released_lock_and_retained_recent_heartbeat_do_not_verify_a_running_process(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with processes.OwnedProcessLock(root, 'baseline_worker', 'sha') as lock:
                processes.write_json(root/'reports/product_status.json', dict(lock.owner, state='RUNNING', heartbeat_ns=time.time_ns()))
            with patch('anomaly_detection.product_diagnostics.snapshot', return_value={'status':'NOT_RUN_FIXTURE'}):
                observed, output = control.export_report(root, 'sha', observe_seconds=0)
            self.assertEqual(observed['health'], 'STOPPED')
            self.assertFalse(observed['observation_matches_process'])
            with zipfile.ZipFile(output) as archive:
                value = json.loads(archive.read('worker_observation.json'))
            self.assertFalse(value['same_instance'])
            self.assertFalse(value['process_identity_verified'])

    def test_stop_keeps_waiting_if_identity_becomes_unreadable_after_request(self):
        initial = {'locked':True, 'owner':{'job':'baseline_worker', 'instance_token':'actual-token'}}
        unavailable = {'locked':True, 'owner':None}
        free = {'locked':False, 'owner':None}
        with patch.object(control, 'process_owner', side_effect=[initial, free, unavailable, free]), patch.object(control, 'write_json') as write, patch.object(control.time, 'sleep') as wait:
            result = control.stop(Path('.'), wait_seconds=10)
        self.assertEqual(result['status'], 'STOPPED')
        self.assertEqual(wait.call_count, 1)
        self.assertEqual(write.call_count, 1)

    def test_separate_reporter_writes_only_reports_and_preserves_target_source_and_data(self):
        reporter = Path(__file__).resolve().parents[1] / 'Collect_Acceptance_ReadOnly.py'
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp); root = project/'AnomalyDetection'; root.mkdir()
            launcher = root/'run_anomaly.py'
            launcher.write_text('raise RuntimeError("target-code-must-not-execute")\n', encoding='utf-8')
            (root/'RELEASE_MANIFEST.json').write_text(json.dumps({'build_id':'INSTALLED-FIXTURE', 'source_sha256':'installed-sha', 'files_sha256':{}}), encoding='utf-8')
            (root/'data').mkdir()
            sentinel = root/'data/retained-evidence'; sentinel.write_bytes(b'private retained evidence')
            before = {p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()}
            proc = subprocess.run([sys.executable, '-B', str(reporter), '--project', str(project), '--seconds', '0'], capture_output=True, text=True, timeout=20)
            self.assertEqual(proc.returncode, 2, proc.stdout+proc.stderr)
            value = json.loads(proc.stdout)
            self.assertEqual(value['status'], 'PARTIAL_EVIDENCE_BUNDLE_EXPORTED')
            self.assertFalse(value['installation_source_modified'])
            self.assertFalse(value['database_modified'])
            for name, body in before.items():
                self.assertEqual((root/name).read_bytes(), body)
            self.assertTrue(all(p.relative_to(root) in before or p.is_relative_to(root/'reports') for p in root.rglob('*') if p.is_file()))
            with zipfile.ZipFile(value['output']) as archive:
                manifest = json.loads(archive.read('acceptance_manifest.json'))
            self.assertEqual(manifest['installed_build_id'], 'INSTALLED-FIXTURE')
            self.assertEqual(manifest['installed_source_sha256'], 'installed-sha')
            self.assertNotEqual(manifest['build_id'], 'INSTALLED-FIXTURE')
            self.assertEqual(manifest['identity_scope'], 'REPORT_COLLECTOR_NOT_RUNNING_WORKER')


if __name__ == '__main__':
    unittest.main()
