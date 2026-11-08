"""Startup receipt regressions. These fixtures do not contact production."""
from pathlib import Path
import json
import subprocess
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
from unittest import TestCase, main
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import Install_Update as installer
from anomaly_detection import BUILD_ID
from anomaly_detection import product_control

SHA = 'a' * 64


class Clock:
    def __init__(self):
        self.elapsed = 0

    def monotonic(self):
        return self.elapsed

    def sleep(self, seconds):
        self.elapsed += seconds


def snapshot(health='RUNNING', *, pid=400, token='new', heartbeat=10,
             storage=True, source=True, locked=True, web=True, **extra):
    owner = {'job': 'baseline_worker', 'pid': pid, 'instance_token': token,
             'build_id': BUILD_ID, 'source_sha256': SHA}
    worker = dict(owner, heartbeat_ns=heartbeat, phase='read_fresh_window', storage_ready=storage)
    if source:
        worker['source_status'] = {'source_read_only': True, 'semantic_state': 'ready'}
    worker.update(extra)
    return {'health': health, 'running': locked, 'observation_matches_process': True,
            'heartbeat_age_seconds': 0.1, 'worker': worker, 'process': {'locked': locked, 'owner': owner},
            'web': {'locked': web, 'owner': dict(owner, job='product_web', pid=500)}}


class ReleaseStartupTests(TestCase):
    def test_worker_start_ignores_old_owner_during_lock_handoff(self):
        child = SimpleNamespace(pid=400, poll=lambda: None)
        states = [snapshot(token='old', locked=False), snapshot(token='old'), snapshot(pid=401)]
        with patch.object(product_control, 'spawn', return_value=child) as spawn, \
                patch.object(product_control.uuid, 'uuid4', return_value=SimpleNamespace(hex='new')), \
                patch.object(product_control, 'status', side_effect=states), \
                patch.object(product_control, 'time', Clock()):
            result = product_control.start(Path('.'), SHA)
        self.assertEqual(result['status'], 'STARTED')
        self.assertEqual(result['child_pid'], 400)
        self.assertEqual(result['process']['owner']['pid'], 401)
        self.assertEqual(result['process']['owner']['instance_token'], 'new')
        spawn.assert_called_once_with(Path('.'), 'worker-run', instance_token='new')

    def test_slow_start_waits_for_two_current_heartbeats_and_web(self):
        states = [snapshot(pid=399, token='old'), snapshot('PREPARING_POSTGRESQL', storage=False, source=False),
                  snapshot('RUNNING', heartbeat=11, source=False), snapshot('DEGRADED_EVALUATION', heartbeat=12),
                  snapshot(heartbeat=13), snapshot(heartbeat=13), snapshot(heartbeat=14, web=False),
                  snapshot(heartbeat=15), snapshot(heartbeat=16)]
        with patch.object(product_control, 'status', side_effect=states), patch.object(installer, 'time', Clock()), \
                patch.object(installer, 'web_status_matches', side_effect=[False, True]) as web:
            result = installer.await_worker(Path('.'), BUILD_ID, SHA,
                {'status': 'STARTING', 'child_pid': 399, 'expected_instance_token': 'new'}, 12)
        self.assertEqual(result['instance_token'], 'new')
        self.assertEqual(result['web'], 'PASS_LOCAL_STATUS_GET')
        self.assertEqual(web.call_count, 2)
        self.assertEqual(result['elapsed_seconds'], 4)
        self.assertEqual((result['launcher_pid'], result['observed_worker_pid']), (399, 400))

    def test_same_build_and_pid_with_wrong_token_is_rejected(self):
        with patch.object(product_control, 'status', return_value=snapshot(token='other')), \
                patch.object(installer, 'time', Clock()), patch.object(installer, 'web_status_matches') as web:
            with self.assertRaisesRegex(installer.InstallFailure, 'UPDATED_WORKER_STARTUP_TIMEOUT') as caught:
                installer.await_worker(Path('.'), BUILD_ID, SHA,
                    {'status': 'STARTING', 'child_pid': 400, 'expected_instance_token': 'new'}, 2)
        self.assertFalse(caught.exception.details['startup']['matching_process'])
        self.assertEqual(caught.exception.details['startup']['observed_build_id'], BUILD_ID)
        web.assert_not_called()

    def test_cli_forwards_token_to_worker(self):
        from anomaly_detection import product_cli, product_worker
        token = 'd' * 32
        with patch.object(sys, 'argv', ['run_anomaly.py', 'worker-run', '--instance-token', token]), \
                patch.object(product_worker, 'run', return_value=0) as worker:
            self.assertEqual(product_cli.main(SHA), 0)
        worker.assert_called_once_with(product_cli.ROOT, SHA, instance_token=token)

    def test_persistent_postgresql_failure_remains_a_failure_with_phase(self):
        waiting = snapshot('WAITING_FOR_DATABASE_LOCK', storage=False, source=False, phase='prepare_owned_schema',
                           last_storage_failure={'error_type': 'LockNotAvailable', 'sqlstate': '55P03'})
        with patch.object(product_control, 'status', return_value=waiting), patch.object(installer, 'time', Clock()), \
                patch.object(installer, 'web_status_matches') as web:
            with self.assertRaisesRegex(installer.InstallFailure, 'UPDATED_WORKER_STARTUP_TIMEOUT') as caught:
                installer.await_worker(Path('.'), BUILD_ID, SHA, {'status': 'STARTING', 'child_pid': 400}, 2)
        self.assertEqual(caught.exception.details['startup']['phase'], 'prepare_owned_schema')
        self.assertEqual(caught.exception.details['startup']['last_storage_failure']['sqlstate'], '55P03')
        web.assert_not_called()

    def test_exited_or_replaced_instance_cannot_qualify(self):
        for current in (snapshot('STOPPED', locked=False, stop_reason='WORKER_FAILED'),
                        snapshot(pid=401, token='replacement')):
            first = snapshot('PREPARING_POSTGRESQL')
            with self.subTest(current=current['health']), \
                    patch.object(product_control, 'status', side_effect=[first, current]), \
                    patch.object(installer, 'time', Clock()):
                with self.assertRaisesRegex(installer.InstallFailure, 'UPDATED_WORKER_EXITED_OR_REPLACED'):
                    installer.await_worker(Path('.'), BUILD_ID, SHA, {'status': 'STARTING', 'child_pid': 400}, 10)

    def test_local_web_must_report_the_current_running_worker(self):
        worker = snapshot()['worker']
        for fields, expected in (({}, True), ({'instance_token': 'old'}, False), ({'state': 'STOPPED'}, False)):
            payload = dict(worker, state='RUNNING') | fields
            response = SimpleNamespace(status=200, read=lambda limit: json.dumps(payload).encode())
            with self.subTest(fields=fields), patch('http.client.HTTPConnection') as connection:
                connection.return_value.getresponse.return_value = response
                self.assertIs(installer.web_status_matches(worker), expected)
                connection.return_value.request.assert_called_once_with('GET', '/api/status')
                connection.return_value.close.assert_called_once()

    def test_real_process_wrapper_and_worker_have_different_pids(self):
        script = str(Path(__file__).resolve())
        launchers = []
        def spawn(root, command, *, instance_token):
            self.assertEqual(command, 'worker-run')
            process = subprocess.Popen([sys.executable, '-B', script, '--fixture-launcher', str(root), instance_token])
            launchers.append(process)
            return process

        with TemporaryDirectory(prefix='ad-startup-wrapper-') as folder:
            root = Path(folder)
            try:
                with patch.object(product_control, 'spawn', side_effect=spawn), \
                        patch.object(installer, 'web_status_matches', return_value=True):
                    started = product_control.start(root, SHA)
                    self.assertEqual(started['status'], 'STARTED')
                    ready = installer.await_worker(root, BUILD_ID, SHA, started, 5)
                self.assertNotEqual(ready['launcher_pid'], ready['pid'])
                self.assertEqual(ready['observed_worker_pid'], ready['pid'])
                self.assertEqual(ready['instance_token'], started['expected_instance_token'])
            finally:
                product_control.stop(root, wait_seconds=3)
                for process in launchers:
                    process.wait(timeout=12)


def fixture_worker(root, token):
    """Hold actual OS locks. PostgreSQL and the web GET are controlled fixtures."""
    from anomaly_detection.process_control import OwnedProcessLock, read_json, write_json

    with OwnedProcessLock(root, 'baseline_worker', SHA, instance_token=token) as owner, \
            OwnedProcessLock(root, 'product_web', SHA, resource='web'):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if read_json(root/'data/A2W_stop_request.json', {}).get('instance_token') == token:
                return 0
            write_json(root/'reports/product_status.json', dict(owner.owner, state='RUNNING',
                heartbeat_ns=time.time_ns(), storage_ready=True, phase='fixture',
                source_status={'source_read_only': True, 'semantic_state': 'ready'}))
            time.sleep(.05)
    return 0


if __name__ == '__main__':
    if sys.argv[1:2] == ['--fixture-launcher']:
        raise SystemExit(subprocess.call([sys.executable, '-B', __file__, '--fixture-worker', *sys.argv[2:]]))
    if sys.argv[1:2] == ['--fixture-worker']:
        raise SystemExit(fixture_worker(Path(sys.argv[2]), sys.argv[3]))
    main()
