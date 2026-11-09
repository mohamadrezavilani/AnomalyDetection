"""Finite supervisor checks using fake publishers and disposable child processes."""
import json
import hashlib
from contextlib import nullcontext
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from p24_foundation.errors import FoundationError
from p24_foundation import replay

PUBLICATION = "00000000-0000-4000-8000-000000000001"


class FakeChild:
    def __init__(self, stdout, payload, code=0, timeout=False):
        stdout.write(payload)
        stdout.flush()
        self.code, self.timeout = code, timeout
        self.returncode = None
        self.killed = self.reaped = False

    def wait(self, timeout=None):
        if self.timeout and not self.killed:
            raise subprocess.TimeoutExpired("private command", timeout)
        self.returncode = -9 if self.killed else self.code
        self.reaped = True
        return self.returncode

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.output = self.root / "report.json"
        self.children, self.commands = [], []

    def tearDown(self):
        self.directory.cleanup()

    def run_replay(self, **changes):
        args = dict(config=self.root / "PRIVATE_CONFIG", plans=[self.root / "PRIVATE_PLAN_1"],
            max_runtime_seconds=10, output=self.output, publish_command=[sys.executable, "PRIVATE_TOOL"])
        args.update(changes)
        return replay.replay_plans(**args)

    def child_factory(self, responses):
        responses = iter(responses)
        def start(command, *, stdout, stderr, shell):
            self.assertFalse(shell)
            self.assertEqual(stderr, subprocess.DEVNULL)
            before = json.loads(self.output.read_text())
            self.assertTrue(before["requires_reconciliation"])
            self.assertEqual(before["steps"][-1]["status"], "outcome_unknown")
            if os.name == "posix":
                self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
            self.commands.append(command)
            child = FakeChild(stdout, **next(responses))
            self.children.append(child)
            return child
        return start

    def success(self, generation=1):
        return json.dumps(dict(status="published", publication_id=PUBLICATION,
            generation=generation, extra="PRIVATE_RAW_SENTINEL")).encode()

    def test_ordered_success_keeps_only_safe_ids_and_generations(self):
        with patch.object(replay.subprocess, "Popen", side_effect=self.child_factory([
            dict(payload=self.success(1)), dict(payload=self.success(2))])):
            report = self.run_replay(plans=[self.root / "one", self.root / "two"])
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["completed"], 2)
        self.assertEqual([c[-1] for c in self.commands], [str((self.root / "one").resolve()), str((self.root / "two").resolve())])
        self.assertEqual([s["generation"] for s in report["steps"]], [1, 2])
        public = self.output.read_text()
        self.assertNotIn("PRIVATE", public)
        self.assertNotIn(str(self.root), public)
        self.assertFalse(report["requires_reconciliation"])

    def test_existing_report_and_creation_failure_start_no_children(self):
        self.output.write_bytes(b"preserve-original")
        with patch.object(replay.subprocess, "Popen", side_effect=AssertionError("must not start")):
            with self.assertRaisesRegex(FoundationError, "collector_replay_output_exists"):
                self.run_replay()
        self.assertEqual(self.output.read_bytes(), b"preserve-original")
        self.output.unlink()
        with patch.object(replay.os, "link", side_effect=OSError("PRIVATE_ERROR")), \
             patch.object(replay.subprocess, "Popen", side_effect=AssertionError("must not start")):
            with self.assertRaisesRegex(FoundationError, "collector_replay_report_write_failed"):
                self.run_replay()

    def test_invalid_bounds_start_no_children(self):
        for changes in (dict(plans=[]), dict(plans=[Path("x")] * 129),
                        dict(max_runtime_seconds=True), dict(max_runtime_seconds=3601)):
            with patch.object(replay.subprocess, "Popen", side_effect=AssertionError("must not start")):
                with self.assertRaisesRegex(FoundationError, "invalid_collector_replay_bounds"):
                    self.run_replay(**changes)
        self.assertFalse(self.output.exists())

    def test_failed_missing_or_malformed_result_stops_without_retry(self):
        for payload, code in [(b'{"status":"FAIL","error":"PRIVATE_ERROR"}', 2),
            (b"", 0), (b"PRIVATE_BAD_JSON", 0), (self.success(), 1),
            (b'{"status":"published","status":"published"}', 0),
            (b"x" * (replay.MAX_RESULT_BYTES + 1), 0),
            (json.dumps(dict(status="published", publication_id=PUBLICATION, generation=True)).encode(), 0)]:
            with self.subTest(code=code, bytes=len(payload)):
                self.output.unlink(missing_ok=True)
                self.commands.clear()
                with patch.object(replay.subprocess, "Popen", side_effect=self.child_factory([
                    dict(payload=payload, code=code)])):
                    report = self.run_replay(plans=[Path("one"), Path("must-not-start")])
                self.assertEqual(len(self.commands), 1)
                self.assertEqual(report["status"], "stopped")
                self.assertTrue(report["requires_reconciliation"])
                self.assertEqual(report["steps"][0]["status"], "outcome_unknown")
                self.assertNotIn("PRIVATE", self.output.read_text())

    def test_timeout_reaps_child_even_when_it_already_printed_success(self):
        with patch.object(replay.subprocess, "Popen", side_effect=self.child_factory([
            dict(payload=self.success(), timeout=True)])):
            report = self.run_replay(plans=[Path("one"), Path("never")])
        self.assertEqual(report["steps"][0]["status"], "outcome_unknown")
        self.assertEqual(report["completed"], 0)
        self.assertTrue(self.children[0].killed)
        self.assertTrue(self.children[0].reaped)
        self.assertEqual(len(self.commands), 1)

    def test_deadline_between_plans_preserves_first_success(self):
        with patch.object(replay.time, "monotonic", side_effect=[0, 0, 0, 0, 2]), \
             patch.object(replay.subprocess, "Popen", side_effect=self.child_factory([dict(payload=self.success())])):
            report = self.run_replay(plans=[Path("one"), Path("two")], max_runtime_seconds=1)
        self.assertEqual(report["status"], "deadline_reached")
        self.assertEqual(report["completed"], 1)
        self.assertFalse(report["requires_reconciliation"])

    def test_launch_failure_and_report_failure_do_not_continue(self):
        with patch.object(replay.subprocess, "Popen", side_effect=OSError("PRIVATE_FAILURE")):
            report = self.run_replay(plans=[Path("one"), Path("two")])
        self.assertEqual(report["steps"][0]["status"], "not_started")
        self.assertFalse(report["requires_reconciliation"])
        self.output.unlink()
        real_write = replay._write_report
        def fail_update(path, report, *, create=False):
            if not create:
                raise FoundationError("collector_replay_report_write_failed")
            real_write(path, report, create=create)
        with patch.object(replay, "_write_report", side_effect=fail_update), \
             patch.object(replay.subprocess, "Popen", side_effect=AssertionError("must not start")):
            with self.assertRaises(FoundationError):
                self.run_replay()

    def test_real_child_timeout_leaves_reconciliation_warning(self):
        report = self.run_replay(max_runtime_seconds=1,
            publish_command=[sys.executable, "-c", "import time;time.sleep(30)"])
        self.assertTrue(report["requires_reconciliation"])
        self.assertEqual(report["steps"][0]["reason"], "publication_deadline_exceeded")

    def test_real_child_success_with_path_arguments(self):
        script = "print(" + repr(self.success().decode()) + ")"
        report = self.run_replay(publish_command=[sys.executable, "-c", script])
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["steps"][0]["publication_id"], PUBLICATION)

    def test_cli_missing_plan_returns_failure_without_disclosing_paths(self):
        tool = Path(__file__).resolve().parents[1] / "tools/collector_pipeline.py"
        result = subprocess.run([sys.executable, str(tool), "replay", "--config", str(self.root / "PRIVATE_CONFIG"),
            "--plans", str(self.root / "PRIVATE_MISSING_PLAN"), "--max-runtime-seconds", "10", "--output", str(self.output)],
            capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("PRIVATE", result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "stopped")

    def test_interruption_reaps_child_and_retains_previous_success(self):
        factory = self.child_factory([dict(payload=self.success()), dict(payload=b"")])
        def start(*args, **kwargs):
            child = factory(*args, **kwargs)
            if len(self.children) == 2:
                original_wait = child.wait
                def wait(timeout=None):
                    if not child.killed:
                        raise KeyboardInterrupt()
                    return original_wait(timeout)
                child.wait = wait
            return child
        with patch.object(replay.subprocess, "Popen", side_effect=start):
            report = self.run_replay(plans=[Path("one"), Path("two"), Path("never")])
        self.assertEqual(report["completed"], 1)
        self.assertEqual(report["steps"][1]["reason"], "publication_interrupted")
        self.assertTrue(self.children[1].killed and self.children[1].reaped)

    def reconciliation(self, *, found=True, current=4, digest=None, cutoff="1792477800000000000"):
        plan = {"expected_generation": 0, "event_cutoff": "2026-10-20T07:30:00Z",
                "captures": [{"source_key": "collector:stream:1:2", "batch": SimpleNamespace(original=b"PRIVATE_RAW")} ]}
        manifest = {"effective_sources": [PUBLICATION], "event_cutoff_ns": cutoff}
        connection = Mock()
        connection.transaction.return_value = nullcontext()
        response = lambda row: SimpleNamespace(fetchone=lambda: row)
        connection.execute.side_effect = [None, response((PUBLICATION,)), response((current,)),
            response((PUBLICATION, manifest, "sealed") if found else None),
            SimpleNamespace(fetchall=lambda: [(PUBLICATION, "collector:stream:1:2",
                digest or hashlib.sha256(b"PRIVATE_RAW").hexdigest())])]
        result = replay.inspect_plan_commit(connection, "PRIVATE_NAMESPACE", plan)
        for call in connection.execute.call_args_list:
            sql = call.args[0].strip()
            self.assertTrue(sql.startswith("SELECT") or sql.startswith("SET TRANSACTION"))
        self.assertIn("READ ONLY", connection.execute.call_args_list[0].args[0])
        self.assertNotIn("PRIVATE", json.dumps(result))
        return result

    def test_reconciliation_reads_historical_commit_after_current_pointer_advances(self):
        cutoff = str(replay.microsecond_cutoff("2026-10-20T07:30:00Z").epoch_ns)
        result = self.reconciliation(cutoff=cutoff)
        self.assertEqual(result["assessment"], "planned_content_observed")
        self.assertEqual(result["current_generation"], 4)
        self.assertEqual(result["generation_inspected"], 1)
        self.assertFalse(result["automatic_retry_authorized"])

    def test_reconciliation_distinguishes_missing_commit_and_different_content(self):
        self.assertEqual(self.reconciliation(found=False)["assessment"], "no_commit_observed_at_read_time")
        self.assertEqual(self.reconciliation(digest="different")["assessment"], "different_committed_content")
