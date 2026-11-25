from pathlib import Path
import unittest
from tools.Upgrade_Compact_Context import upgrade

class ContextUpgradeTests(unittest.TestCase):
    def run_steps(self, responses):
        calls=[]
        def execute(args,cwd):
            calls.append((args,cwd));return responses[len(calls)-1]
        report=upgrade(Path('project'),Path('new'),Path('old'),Path('history-old'),'sha',execute=execute)
        return report,calls
    def test_history_stops_before_core_and_resumes_after_confirmed_restore(self):
        result,calls=self.run_steps([(0,{'source_sha256':'old-sha'}),(0,{'history_state':'ACTIVE','from_tehran':'2026-11-20T00:00:00+03:30'}),
            (0,{}),(0,{}),(0,{}),(2,{'status':'COMPACT_UPGRADE_FAILED_PREVIOUS_RELEASE_RESTORED'}),(0,{})])
        self.assertIn('history-stop',calls[3][0])
        self.assertEqual(calls[5][0][0],Path('new/tools/Upgrade_Compact_Product.py'))
        self.assertIn('--resume-existing',calls[6][0])
        self.assertIn('2026-11-20T00:00:00+03:30',calls[6][0])
        self.assertNotIn('old-sha',calls[6][0])
        self.assertEqual(result['status'],'COMPACT_CONTEXT_UPGRADE_INCOMPLETE')
    def test_mixed_history_restore_uses_existing_narrowed_floor_and_old_task_root(self):
        floor='2026-11-19T20:30:00Z'
        result,calls=self.run_steps([(0,{'source_sha256':'core24'}),(0,{'history_state':'ACTIVE','from_utc':floor}),
            (0,{}),(0,{}),(0,{}),(2,{'status':'COMPACT_UPGRADE_FAILED_PREVIOUS_RELEASE_RESTORED'}),(0,{})])
        self.assertIn('--resume-existing',calls[-1][0]); self.assertIn(floor,calls[-1][0])
        self.assertEqual(calls[-1][1],Path('history-old'))

    def test_owned_history_migrates_only_after_core_succeeds(self):
        result,calls=self.run_steps([(0,{'source_sha256':'old-sha'}),(0,{'history_state':'ACTIVE','from_tehran':'2026-11-20T00:00:00+03:30'}),
            (0,{}),(0,{}),(0,{}),(0,{}),(0,{})])
        self.assertEqual(result['status'],'COMPACT_CONTEXT_CORE_AND_HISTORY_UPGRADED')
        self.assertEqual(calls[3][1],Path('history-old'))
        self.assertIn('--drain-launcher',calls[4][0])
        self.assertIn('2026-11-20T00:00:00+03:30',calls[4][0])
        self.assertEqual(calls[6][0][0],Path('new/tools/Repair_Compact_History_Task.py'))
    def test_stop_failure_and_completed_history(self):
        result,calls=self.run_steps([(0,{'source_sha256':'old-sha'}),(0,{'history_state':'ACTIVE','from_tehran':'2026-11-20T00:00:00+03:30'}),(0,{}),(2,{})])
        self.assertEqual(len(calls),4)
        result,calls=self.run_steps([(0,{'source_sha256':'old-sha'}),(0,{'history_state':'COMPLETE'}),(0,{}),(0,{})])
        self.assertEqual(len(calls),4)
        self.assertEqual(result['status'],'COMPACT_CONTEXT_CORE_UPGRADED_HISTORY_ALREADY_COMPLETE')
    def test_unconfirmed_stop_never_resumes_history_or_migrates(self):
        result,calls=self.run_steps([(0,{'source_sha256':'old-sha'}),(0,{'history_state':'ACTIVE','from_tehran':'2026-11-20T00:00:00+03:30'}),
            (0,{}),(0,{}),(0,{}),(2,{'status':'COMPACT_UPGRADE_RESTORE_NEEDS_ATTENTION'})])
        self.assertEqual(len(calls),6)
        self.assertEqual(result['status'],'COMPACT_CONTEXT_UPGRADE_INCOMPLETE')
    def test_failed_candidate_preflight_does_not_stop_history(self):
        result,calls=self.run_steps([(0,{'source_sha256':'old-sha'}),(0,{'history_state':'ACTIVE','from_tehran':'2026-11-20T00:00:00+03:30'}),(2,{})])
        self.assertEqual(len(calls),3)


class RecoveryTests(unittest.TestCase):
    def baseline(self):
        return dict(input_next_ns=100, history=dict(job_id='synthetic-job', next_ns=50))

    def host(self):
        import copy
        baseline = self.baseline()
        class Host:
            def __init__(self):
                self.calls = []
                self.values = {}
                self.fail = None
                self.check = dict(copy.deepcopy(baseline))
                self.check['history'].update(from_ns=0, target_ns=90, state='ACTIVE')
            def checkpoint(self):
                self.calls.append(('checkpoint',))
                return copy.deepcopy(self.check)
            def roles(self):
                return copy.deepcopy(self.values)
            def task(self, which, action):
                self.calls.append(('task', which, action))
                if action == 'register':
                    self.online('supervisor' if which == 'core' else 'history')
            def online(self, role):
                self.values[role] = dict(running=True, state='READY', heartbeat_age_seconds=0,
                                         package=dict(source_sha256='accepted'))
            def start(self, role):
                self.calls.append(('start', role))
                if self.fail == role:
                    raise TimeoutError('ROLE_NOT_READY:' + role)
                self.online(role)
            def wait(self, role, expected):
                self.calls.append(('wait', role))
            def guard(self, expected):
                self.calls.append(('guard',))
                if self.fail == 'guard':
                    raise ValueError('UNLEASED_COMPACT_PROCESSES:999')
            def probe(self):
                self.calls.append(('probe',))
            def stop_supervisor(self):
                self.calls.append(('stop_supervisor',))
                self.values['supervisor']['running'] = False
        return Host()

    def run_recovery(self, host):
        from tools.Recover_Compact_Product import recover
        return recover(host, self.baseline(), 'accepted', lambda stage: None)

    def test_sequential_start_waits_before_next_and_preserves_job(self):
        host = self.host()
        result = self.run_recovery(host)
        self.assertEqual([c for c in host.calls if c[0] in ('start', 'wait')], [
            ('start', 'web'), ('wait', 'web'), ('start', 'ingest'), ('wait', 'ingest'),
            ('start', 'analysis'), ('wait', 'analysis'), ('wait', 'supervisor'), ('wait', 'history')])
        self.assertEqual(result['before'], result['after'])
        self.assertLess(host.calls.index(('probe',)), host.calls.index(('task', 'core', 'register')))
        self.assertLess(host.calls.index(('wait', 'supervisor')), host.calls.index(('task', 'history', 'register')))

    def test_partial_recovery_rerun_does_not_duplicate_workers(self):
        host = self.host()
        host.online('web')
        host.online('supervisor')
        self.run_recovery(host)
        self.assertNotIn(('start', 'web'), host.calls)
        self.assertLess(host.calls.index(('stop_supervisor',)), host.calls.index(('start', 'ingest')))

    def test_pending_process_or_start_failure_does_not_trigger_rollback_start_loop(self):
        for failed in ('guard', 'ingest'):
            host = self.host()
            host.fail = failed
            with self.assertRaises((ValueError, TimeoutError)):
                self.run_recovery(host)
            self.assertNotIn(('start', 'analysis'), host.calls)
            self.assertNotIn(('task', 'core', 'register'), host.calls)
            self.assertNotIn(('task', 'history', 'register'), host.calls)
            self.assertEqual(host.calls.count(('start', 'ingest')), int(failed == 'ingest'))

    def test_wrong_release_and_regressed_checkpoint_precede_scheduler_mutations(self):
        host = self.host()
        host.online('web')
        host.values['web']['package']['source_sha256'] = 'failed-candidate'
        with self.assertRaisesRegex(ValueError, 'RUNNING_RELEASE_MISMATCH'):
            self.run_recovery(host)
        self.assertFalse(any(c[0] == 'task' for c in host.calls))
        host = self.host()
        host.check['input_next_ns'] = 99
        with self.assertRaisesRegex(ValueError, 'INPUT_CHECKPOINT_REWOUND'):
            self.run_recovery(host)
        self.assertFalse(any(c[0] == 'task' for c in host.calls))

    def test_completed_history_is_not_recreated(self):
        host = self.host()
        host.check['history']['state'] = 'COMPLETE'
        self.run_recovery(host)
        self.assertNotIn(('task', 'history', 'register'), host.calls)

    def test_supervisor_reappearing_during_start_blocks_new_launch(self):
        host = self.host()
        original = host.guard
        def restarted(expected):
            original(expected)
            host.online('supervisor')
        host.guard = restarted
        with self.assertRaisesRegex(ValueError, 'SUPERVISOR_REAPPEARED'):
            self.run_recovery(host)
        self.assertFalse(any(c[0] == 'start' for c in host.calls))

    def test_preservation_rejects_replacement_range_and_regression(self):
        import copy
        from tools.Recover_Compact_Product import preserved
        before = self.host().checkpoint()
        for field, value in [('job_id', 'replacement'), ('from_ns', 1), ('target_ns', 91), ('next_ns', 49)]:
            after = copy.deepcopy(before)
            after['history'][field] = value
            with self.assertRaises(ValueError):
                preserved(before, after)

    def test_receipt_and_task_cannot_select_another_release(self):
        from tools.Recover_Compact_Product import validate_receipt, validate_task_root
        receipt = dict(status='COMPACT_UPGRADE_RESTORE_NEEDS_ATTENTION', data_reset=False,
                       previous_code_root=r'E:\accepted', before=self.baseline())
        validate_receipt(receipt, r'e:\accepted')
        with self.assertRaises(ValueError):
            validate_receipt(receipt, r'E:\candidate')
        with self.assertRaises(ValueError):
            validate_task_root(dict(exists=True, actions=[dict(WorkingDirectory=r'E:\candidate')]), r'E:\accepted')

    def test_process_guard_checks_tokens_birth_and_unleased_venv_parent(self):
        import copy
        from tools.Recover_Compact_Product import validate_processes
        from viewer_performance.financial_screen.reviewed_host import words
        command = r'python.exe -B -m compact_product worker web --project "E:\project" --token synthetic-token'
        child = dict(ProcessId=20, ParentProcessId=19, CreationDate='1970-01-01T00:01:40Z', CommandLine=command)
        parent = dict(child, ProcessId=19, ParentProcessId=18)
        role = dict(running=True, process_pid=20, process_created_epoch_seconds=100, command_token='synthetic-token')
        validate_processes([child, parent], {'web': role}, r'E:\project', words)
        for mutation in ('birth', 'token', 'extra'):
            rows = copy.deepcopy([child, parent])
            if mutation == 'birth':
                rows[0]['CreationDate'] = '1970-01-01T00:02:40Z'
            elif mutation == 'token':
                rows[0]['CommandLine'] = command.replace('synthetic-token', 'other-token')
            else:
                rows.append(dict(child, ProcessId=30))
            with self.assertRaises(ValueError):
                validate_processes(rows, {'web': role}, r'E:\project', words)
        with self.assertRaisesRegex(ValueError, 'UNLEASED_COMPACT_PROCESSES'):
            validate_processes([child], {}, r'E:\project', words)
        # A different project is never stopped or counted as this project's role.
        validate_processes([child], {}, r'E:\another-project', words)
        # Scheduled supervisor/history generate their token inside the process.
        for action, name in [('supervise', 'supervisor'), ('history-worker', 'history')]:
            scheduled = dict(child, CommandLine=r'python.exe -B -m compact_product ' + action + r' --project E:\project')
            validate_processes([scheduled], {name: role}, r'E:\project', words)

    @unittest.skipUnless(__import__('os').name == 'nt', 'native Windows CIM required')
    def test_native_bounded_inventory(self):
        import os
        from tools.Recover_Compact_Product import INVENTORY
        from viewer_performance.financial_screen.host import powershell
        value = powershell(INVENTORY)
        self.assertGreater(value['commit_limit_bytes'], 0)
        self.assertTrue(any(row['ProcessId'] == os.getpid() for row in value['processes']))
        self.assertLessEqual(len(value['processes']), 512)


class SequentialUpgradeTests(unittest.TestCase):
    baseline = RecoveryTests.baseline
    host = RecoveryTests.host
    def upgrade_host(self):
        host = self.host()
        for role in ('web', 'ingest', 'analysis', 'supervisor'):
            host.online(role)
        def stop_core():
            host.calls.append(('stop_core',))
            for value in host.values.values():
                value['running'] = False
        host.stop_core = stop_core
        host.check_children = lambda: host.calls.append(('children_exited',))
        host.catalog = lambda: host.calls.append(('catalog',))
        return host

    def test_preflight_waits_for_transient_failure_and_reports_persistent_role(self):
        from tools.Upgrade_Compact_Product import wait_existing_core
        host = self.upgrade_host()
        host.online('history')
        host.values['history']['package'] = {'source_sha256':'separate-history-build'}
        host.values['analysis'].update(failure={'type':'QueryCanceled','sqlstate':'57014'},state='RETRYING')
        seen = []
        def recover(_):
            host.online('analysis')
        wait_existing_core(host, 'accepted', lambda _: None, seen.append, allow_history=True, sleep=recover)
        self.assertEqual(list(seen[0]), ['analysis'])
        self.assertEqual(seen[0]['analysis']['sqlstate'],'57014')
        host.values['web']['running'] = False
        with self.assertRaisesRegex(TimeoutError, 'MUST_BE_HEALTHY:web'):
            wait_existing_core(host, 'accepted', lambda _: None, seen.append, allow_history=True, timeout=0)
        self.assertFalse(host.calls)

    def test_success_stops_processes_before_sequential_launch(self):
        from tools.Upgrade_Compact_Product import upgrade_core
        host = self.upgrade_host()
        result = upgrade_core(host, 'accepted', 'accepted', lambda before: self.fail('unexpected restore'), lambda s: None, lambda v: None)
        self.assertEqual(result['status'], 'COMPACT_UPGRADED_HISTORY_PRESERVED')
        self.assertLess(host.calls.index(('children_exited',)), host.calls.index(('start', 'web')))
        self.assertLess(host.calls.index(('wait', 'web')), host.calls.index(('start', 'ingest')))

    def test_failed_start_preserves_original_error_and_drains_before_restore(self):
        from tools.Upgrade_Compact_Product import upgrade_core
        host = self.upgrade_host()
        host.fail = 'ingest'
        saved = []
        def restore(before):
            self.assertFalse(any(v.get('running') for v in host.roles().values()))
            self.assertEqual(host.calls[-1], ('children_exited',))
            return {'restored': True}
        result = upgrade_core(host, 'accepted', 'accepted', restore, lambda s: None, lambda v: saved.append(v['failure']))
        self.assertEqual(result['status'], 'COMPACT_UPGRADE_FAILED_PREVIOUS_RELEASE_RESTORED')
        self.assertEqual(saved[0]['code'], 'ROLE_NOT_READY:ingest')
        self.assertNotIn(('start', 'analysis'), host.calls)

    def test_unleased_child_blocks_rollback_even_when_all_leases_are_gone(self):
        from tools.Upgrade_Compact_Product import upgrade_core, quiesce
        from unittest.mock import patch
        host = self.upgrade_host()
        host.fail = 'ingest'
        def children():
            if ('start', 'ingest') in host.calls:
                raise ValueError('OWNED_CHILD_STILL_STARTING')
        host.check_children = children
        def bounded(h, expected, emit):
            return quiesce(h, expected, emit, timeout=0)
        with patch('tools.Upgrade_Compact_Product.quiesce', side_effect=bounded):
            result = upgrade_core(host, 'accepted', 'accepted', lambda v: self.fail('unsafe rollback'), lambda s: None, lambda v: None)
        self.assertEqual(result['status'], 'COMPACT_UPGRADE_RESTORE_NEEDS_ATTENTION')
        self.assertEqual(result['restore_failure']['code'], 'CORE_PROCESSES_NOT_DRAINED_NO_ROLLBACK_STARTED')

    def test_running_history_blocks_upgrade_before_stop(self):
        from tools.Upgrade_Compact_Product import upgrade_core
        host = self.upgrade_host();host.online('history')
        result = upgrade_core(host, 'accepted', 'accepted', lambda v: self.fail('restore'), lambda s: None, lambda v: None)
        self.assertEqual(result['failure']['code'], 'STOP_HISTORY_BEFORE_CORE_UPGRADE')
        self.assertNotIn(('stop_core',), host.calls)

    def test_transport_relays_bounded_json_and_retains_exit_failure(self):
        from tools.Upgrade_Compact_Context import run
        from contextlib import redirect_stdout
        import io
        output = io.StringIO()
        with redirect_stdout(output):
            code, value = run(['-c', 'print("x"*100000);print(\'{"status":"SYNTHETIC_FAILURE"}\');raise SystemExit(2)'], Path.cwd())
        self.assertEqual(code, 2)
        self.assertEqual(value['status'], 'SYNTHETIC_FAILURE')
        self.assertNotIn('xxxxx', output.getvalue())

    def test_phase_export_bounds_reads_and_excludes_content_and_rechecks(self):
        import tempfile,json
        from tools.Review_Compact_Write_Phases import sample
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'history.log'
            value=dict(event='HISTORY_PUBLICATION',fresh_publication=True,start_ns=1,
                       stream_lock_acquire_seconds=.2,context_upsert_seconds=1.2,
                       source_records=10,payload='private-synthetic-content')
            path.write_bytes(b'x'*10000+b'\n'+json.dumps(value).encode()+b'\n'+
                json.dumps(dict(value,fresh_publication=False,start_ns=2)).encode()+b'\n')
            result=sample(path,'history',1024)
            self.assertLessEqual(result['bytes_read'],1024)
            self.assertEqual(len(result['rows']),1)
            self.assertNotIn('private',json.dumps(result))
            self.assertEqual(result['rows'][0]['context_upsert_seconds'],1.2)
