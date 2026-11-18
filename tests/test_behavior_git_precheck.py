"""Real Git gates keep generated receipts but reject source and index edits."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from viewer_performance.behavior_install_git import inspect, REPORT


class InstallGitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.executable = shutil.which('git')
        self.git('init', '-b', 'main')
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'core.autocrlf', 'false')
        (self.root / '.gitignore').write_text('AnomalyDetection/reports/\n')
        self.report = self.root / REPORT
        self.report.parent.mkdir()
        self.original = self.body(1)
        self.report.write_bytes(self.original)
        (self.root / 'code.py').write_text('original\n')
        self.git('add', '.')
        self.git('commit', '-m', 'installed')
        self.old = self.git('rev-parse', 'HEAD').decode().strip()
        (self.root / 'code.py').write_text('reviewed target\n')
        self.git('add', '.')
        self.git('commit', '-m', 'target')
        self.target = self.git('rev-parse', 'HEAD').decode().strip()
        self.git('reset', '--hard', self.old)

    def body(self, generation):
        return json.dumps(dict(mode='RESUME_CHECKPOINT', runtime_source_sha256='a'*64,
                               live=dict(generation=generation))).encode()

    def git(self, *args):
        return subprocess.check_output([self.executable, *args], cwd=self.root, stderr=subprocess.DEVNULL)

    def run_check(self):
        return inspect(self.root, self.target, self.executable,
                       self.root / 'AnomalyDetection/reports/install/git-precheck.json')

    def test_generated_receipt_survives_precheck_and_actual_fast_forward(self):
        current = self.body(99)
        self.report.write_bytes(current)
        before = self.git('diff', '--binary')
        result = self.run_check()
        self.assertEqual(result['status'], 'INSTALL_GIT_READY')
        saved = Path(result['allowed_generated_reports'][0]['preserved'])
        self.assertEqual(saved.read_bytes(), current)
        self.assertEqual(self.git('diff', '--binary'), before)
        self.git('merge', '--ff-only', self.target)
        self.assertEqual(self.report.read_bytes(), current)
        self.assertEqual((self.root / 'code.py').read_text(), 'reviewed target\n')

    def test_actual_source_edit_is_named_and_never_reset(self):
        (self.root / 'code.py').write_text('operator edit\n')
        result = self.run_check()
        self.assertEqual(result['status'], 'INSTALL_GIT_BLOCKED')
        self.assertEqual(result['blocking_changes'], [dict(path='code.py', status=' M')])
        self.assertEqual((self.root / 'code.py').read_text(), 'operator edit\n')
        self.assertEqual(self.git('rev-parse', 'HEAD').decode().strip(), self.old)

    def test_staged_receipt_edit_is_not_a_generated_worktree_exception(self):
        self.report.write_bytes(self.body(99))
        self.git('add', REPORT)
        before = self.git('diff', '--cached', '--binary')
        result = self.run_check()
        self.assertEqual(result['status'], 'INSTALL_GIT_BLOCKED')
        self.assertEqual(result['blocking_changes'][0]['status'], 'M ')
        self.assertEqual(self.git('diff', '--cached', '--binary'), before)

    def test_receipt_target_change_requires_review(self):
        self.git('checkout', self.target)
        self.report.write_bytes(self.body(2))
        self.git('add', REPORT)
        self.git('commit', '-m', 'changed report in target')
        self.target = self.git('rev-parse', 'HEAD').decode().strip()
        self.git('reset', '--hard', self.old)
        self.report.write_bytes(self.body(99))
        result = self.run_check()
        self.assertEqual(result['status'], 'INSTALL_GIT_BLOCKED')
        self.assertEqual(result['failure']['code'], 'STARTUP_REPORT_HEAD_INDEX_TARGET_MUST_MATCH')

    def test_invalid_json_report_is_blocked_and_unchanged(self):
        self.report.write_bytes(b'not a startup receipt')
        result = self.run_check()
        self.assertEqual(result['status'], 'INSTALL_GIT_BLOCKED')
        self.assertEqual(self.report.read_bytes(), b'not a startup receipt')

    def test_clean_worktree_needs_no_report_exception(self):
        result = self.run_check()
        self.assertEqual(result['status'], 'INSTALL_GIT_READY')
        self.assertEqual(result['changed_paths'], [])

    def test_rename_records_both_paths_and_blocks_without_mutation(self):
        self.git('mv', 'code.py', 'renamed.py')
        result = self.run_check()
        self.assertEqual(result['status'], 'INSTALL_GIT_BLOCKED')
        self.assertEqual(result['blocking_changes'], [dict(path='renamed.py', status='R ', original_path='code.py')])
        self.assertTrue((self.root / 'renamed.py').is_file())

    def test_actual_git_error_records_operation_and_exit_code(self):
        self.report.write_bytes(self.body(99))
        self.target = 'f'*40
        result = self.run_check()
        self.assertEqual(result['status'], 'INSTALL_GIT_BLOCKED')
        self.assertEqual(result['git_failure']['operation'], 'ls-tree')
        self.assertNotEqual(result['git_failure']['exit_code'], 0)

    def test_failed_git_is_distinguished_from_dirty_content(self):
        result = inspect(self.root, self.target, self.root/'missing-git',
                         self.root/'AnomalyDetection/reports/install/git-precheck.json')
        self.assertEqual(result['status'], 'INSTALL_GIT_BLOCKED')
        self.assertEqual(result['failure']['error_type'], 'FileNotFoundError')
        self.assertEqual(result['changed_paths'], [])


if __name__ == '__main__':
    unittest.main()
