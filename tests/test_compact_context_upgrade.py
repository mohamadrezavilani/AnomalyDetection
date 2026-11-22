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
    def test_core_failure_never_stops_history(self):
        result,calls=self.run_steps([(0,{'history_state':'ACTIVE'}),(2,{'status':'RESTORED'})])
        self.assertEqual(len(calls),2)
        self.assertEqual(result['status'],'COMPACT_CONTEXT_UPGRADE_INCOMPLETE')
    def test_owned_history_migrates_only_after_core_and_stop_succeed(self):
        result,calls=self.run_steps([(0,{'history_state':'ACTIVE'}),(0,{}),(0,{}),(0,{})])
        self.assertEqual(result['status'],'COMPACT_CONTEXT_CORE_AND_HISTORY_UPGRADED')
        self.assertEqual(calls[2][1],Path('history-old'))
        self.assertIn('history-stop',calls[2][0])
        self.assertEqual(calls[3][0][0],Path('new/tools/Repair_Compact_History_Task.py'))
    def test_stop_failure_and_completed_history(self):
        result,calls=self.run_steps([(0,{'history_state':'ACTIVE'}),(0,{}),(2,{})])
        self.assertEqual(len(calls),3)
        result,calls=self.run_steps([(0,{'history_state':'COMPLETE'}),(0,{})])
        self.assertEqual(len(calls),2)
        self.assertEqual(result['status'],'COMPACT_CONTEXT_CORE_UPGRADED_HISTORY_ALREADY_COMPLETE')


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
