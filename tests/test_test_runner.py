import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

SPEC=importlib.util.spec_from_file_location('test_runner_policy',Path(__file__).resolve().parents[1]/'tools/run_tests.py')
RUNNER=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class RunnerSkipPolicyTests(unittest.TestCase):
    def skipped(self,name,reason):
        return [(SimpleNamespace(id=lambda:name),reason)]

    def test_only_declared_posix_check_is_expected_on_windows(self):
        result=RUNNER.classify_skips(self.skipped(RUNNER.POSIX_PERMISSION_TEST,RUNNER.POSIX_SKIP_REASON),platform_name='nt')
        self.assertEqual(len(result['expected_skip_details']),1)
        self.assertEqual(result['unexpected_skip_details'],[])

    def test_skipped_functional_test_still_fails_gate_on_windows(self):
        result=RUNNER.classify_skips(self.skipped('tests.test_postgres.functional','database unavailable'),platform_name='nt')
        self.assertEqual(len(result['unexpected_skip_details']),1)
        self.assertEqual(result['expected_skip_details'],[])

    def test_unexpected_reason_is_not_allowlisted(self):
        result=RUNNER.classify_skips(self.skipped(RUNNER.POSIX_PERMISSION_TEST,'missing dependency'),platform_name='nt')
        self.assertEqual(len(result['unexpected_skip_details']),1)

    def test_posix_check_cannot_be_skipped_on_posix(self):
        result=RUNNER.classify_skips(self.skipped(RUNNER.POSIX_PERMISSION_TEST,RUNNER.POSIX_SKIP_REASON),platform_name='posix')
        self.assertEqual(len(result['unexpected_skip_details']),1)
