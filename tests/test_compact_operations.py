from contextlib import ExitStack, nullcontext
from pathlib import Path
from types import SimpleNamespace
import json
import copy
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from compact_product.config import Config
from compact_product.operations import execute, legacy_receipt, short_gate_checks, wait_for_supervisor, task


def healthy_observation():
    return dict(
        measurement=dict(fresh_windows=3,new_source_records=100,fresh_windows_per_hour=60,
            fresh_windows_analyzed=3,latest_revisions_consumed=3,fresh_windows_timing_confirmed=3),
        web_p95_seconds=.2,
        samples=[dict(health=dict(
            analysis_latency_p95_seconds=1,first_analysis_latency_p95_seconds=1,
            latest_readiness={"service_rate":{"NORMAL":1}},
            source_backlog_windows=0,reference_pending_windows=0,
            analysis_pending_windows=0,dirty_keys=0,reanalysis_windows=0,
            latest_received_end_ns=100,latest_analyzed_end_ns=100,
            latest_analysis_timing_confirmed=True,analysis_timing_unconfirmed_windows=0,
            roles={r:dict(running=True,state="RUNNING",heartbeat_age_seconds=1,failure=None)
                for r in ("ingest","analysis","web")}
        ))],
    )


class CompactOperationTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "native Windows PowerShell required")
    def test_native_installer_imports_release_with_separate_data_and_calling_directories(self):
        from compact_product import BUILD
        with tempfile.TemporaryDirectory(prefix="compact installer ") as directory:
            root = Path(directory)
            data = root / "installed data without module"
            caller = root / "unrelated caller"
            data.mkdir(); caller.mkdir()
            script = Path(__file__).resolve().parents[1] / "compact_product/Install_Compact_Product.ps1"
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script),
                 "-Action", "Version", "-Project", str(data), "-Python", sys.executable],
                cwd=caller, capture_output=True, text=True, timeout=45,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            identity = json.loads(result.stdout)
            self.assertEqual(identity["build_id"], BUILD)
            self.assertTrue(identity["source_sha256"])
            self.assertEqual(list(data.iterdir()), [])

    def exercise(self, action, *, fail=None, task_failure=False, supervisor_failure=False, health_override=None):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            project = Path(directory)
            old = project / "release.json"
            old.write_text(
                json.dumps(
                    dict(project=str(project), before=dict(restore_plan={"active": {}}))
                )
            )
            args = SimpleNamespace(
                action=action, seconds=60, legacy_receipt=old, receipt=None
            )
            for name, value in [
                ("require_windows_admin", None),
                ("load", (Config(), {"DATABASE": {}, "ELASTICSEARCH": {}}, "stream")),
                (
                    "status",
                    {r: dict(running=False) for r in ("ingest", "analysis", "web")},
                ),
                ("start", {}),
                ("probe", []),
                ("assert_legacy_frozen", None),
            ]:
                stack.enter_context(
                    patch("compact_product.operations." + name, return_value=value)
                )
            stop = stack.enter_context(patch("compact_product.operations.stop"))
            task = stack.enter_context(
                patch(
                    "compact_product.operations.task",
                    return_value={"status": "OK"},
                    side_effect=ValueError("task_failed") if task_failure else None,
                )
            )
            stack.enter_context(
                patch(
                    "viewer_performance.Diagnose_Three_Modes.controller_lock",
                    return_value=nullcontext(),
                )
            )
            factory = stack.enter_context(
                patch("viewer_performance.Diagnose_Three_Modes.ProductionHost")
            )
            factory.return_value.reader.return_value = nullcontext(None)
            factory.return_value.h.cursors.return_value = {}
            stack.enter_context(
                patch(
                    "compact_behavior.probe_elastic.probe",
                    return_value={"status": "FIRST_SEARCH_PAGE_VALID"},
                )
            )
            stack.enter_context(patch("compact_product.operations.AnalysisStore"))

            def freeze(project, state, receipt, host):
                state["stopping_started"] = True
                state["frozen_cursors"] = {}

            def restore(project, receipt, state):
                state["status"] = "PREVIOUS_ROLES_RESTORED"

            stack.enter_context(
                patch("compact_behavior.server_trial.freeze", side_effect=freeze)
            )
            restored = stack.enter_context(
                patch(
                    "viewer_performance.Behavior_Release.restore", side_effect=restore
                )
            )
            observation = healthy_observation()
            if health_override:
                observation["samples"][-1]["health"].update(health_override)
            stack.enter_context(patch("compact_product.operations.wait_for_supervisor",
                return_value={"running":True},
                side_effect=TimeoutError("autostart_not_confirmed") if supervisor_failure else None))
            stack.enter_context(
                patch(
                    "compact_product.operations.observe",
                    side_effect=ValueError(fail) if fail else None,
                    return_value=observation,
                )
            )
            result = execute(project, args)
            return result, restored.call_count, stop.call_count, task.call_args_list

    def test_trial_restores_previous_roles_and_keeps_success_status(self):
        value, restored, stopped, tasks = self.exercise("trial")
        self.assertEqual(
            value["status"], "COMPACT_TRIAL_COMPLETE_PREVIOUS_ROLES_RESTORED"
        )
        self.assertEqual(restored, 1)
        self.assertEqual(stopped, 1)

    def test_trial_failure_is_not_overwritten_by_restore_success(self):
        value, restored, stopped, tasks = self.exercise(
            "trial", fail="synthetic_capture_failure"
        )
        self.assertEqual(value["status"], "COMPACT_TRIAL_INCOMPLETE")
        self.assertEqual(restored, 1)
        self.assertEqual(value["failure"]["code"], "synthetic_capture_failure")

    def test_install_keeps_new_roles_only_after_gate(self):
        value, restored, stopped, tasks = self.exercise("install")
        self.assertEqual(
            value["status"], "COMPACT_CANDIDATE_INSTALLED_LONG_RUN_PENDING"
        )
        self.assertEqual(restored, 0)
        self.assertEqual(stopped, 0)

    def test_partial_task_registration_cannot_restore_old_roles_under_new_watchdog(
        self,
    ):
        value, restored, stopped, tasks = self.exercise("install", task_failure=True)
        self.assertEqual(value["status"], "COMPACT_RESTORE_INCOMPLETE")
        self.assertEqual(restored, 0)
        self.assertEqual(tasks[-1].args[1], "disable")

    def test_old_receipt_requires_a_concrete_restore_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "bad.json"
            path.write_text("{}")
            with self.assertRaisesRegex(ValueError, "invalid"):
                legacy_receipt(root, path)

    def test_reanalysis_and_incomplete_timings_block_an_apparently_fast_install(self):
        changes = [
            ("analysis_pending_windows", 1), ("reanalysis_windows", 1), ("dirty_keys", 1),
            ("reference_pending_windows", 1), ("source_backlog_windows", 1),
            ("latest_analyzed_end_ns", 99), ("latest_analysis_timing_confirmed", False),
            ("analysis_timing_unconfirmed_windows", 1), ("analysis_latency_p95_seconds", 301),
            ("first_analysis_latency_p95_seconds", 301),
        ]
        self.assertTrue(all(short_gate_checks(healthy_observation()).values()))
        for key, value in changes:
            with self.subTest(key=key):
                observation = healthy_observation()
                observation["samples"][-1]["health"][key] = value
                self.assertFalse(all(short_gate_checks(observation).values()))

    def test_install_with_pending_reference_work_restores_legacy_roles(self):
        value, restored, stopped, tasks = self.exercise("install", health_override={"reanalysis_windows":1})
        self.assertEqual(value["status"], "COMPACT_INSTALL_ROLLED_BACK")
        self.assertEqual(restored, 1)
        self.assertEqual(tasks, [])

    def test_failure_to_confirm_autostart_rolls_back_registered_candidate(self):
        value, restored, stopped, tasks = self.exercise("install", supervisor_failure=True)
        self.assertEqual(value["status"], "COMPACT_INSTALL_ROLLED_BACK")
        self.assertEqual(restored, 1)
        self.assertEqual([call.args[1] for call in tasks], ["register", "disable", "stop"])

    def test_failed_or_stale_role_does_not_pass_by_holding_a_lock(self):
        for change in ({"failure":{"code":"source_timeout"}}, {"heartbeat_age_seconds":20}, {"state":"RETRYING"}):
            value = healthy_observation()
            value["samples"][-1]["health"]["roles"]["analysis"].update(change)
            self.assertFalse(short_gate_checks(value)["roles_healthy"])

    def test_unsaturated_live_workload_requires_explicit_zero_backlogs(self):
        value = healthy_observation()
        value["measurement"]["fresh_windows_per_hour"] = 12
        self.assertTrue(short_gate_checks(value)["measured_rate_or_no_backlog"])
        value["samples"][0]["health"]["reference_pending_windows"] = None
        self.assertFalse(short_gate_checks(value)["measured_rate_or_no_backlog"])

    def test_autostart_uses_the_immutable_release_code_not_data_project(self):
        with tempfile.TemporaryDirectory() as directory, patch("viewer_performance.financial_screen.host.powershell", return_value={}) as shell:
            task(Path(directory), "register")
            script, environment = shell.call_args.args
            self.assertIn("-WorkingDirectory $env:P24_COMPACT_CODE_ROOT", script)
            self.assertEqual(environment["P24_COMPACT_ROOT"], directory)
            self.assertEqual(environment["P24_COMPACT_CODE_ROOT"], str(Path(__file__).resolve().parents[1]))

    def test_supervisor_confirmation_requires_the_expected_package(self):
        wrong = dict(running=True,state="SUPERVISING",heartbeat_age_seconds=0,package={"source_sha256":"other"})
        good = dict(wrong,package={"source_sha256":"expected"})
        with patch("compact_product.version.verify", return_value={"source_sha256":"expected"}), patch("compact_product.operations.status", side_effect=[{"supervisor":wrong},{"supervisor":good}]), patch("compact_product.operations.time.sleep"):
            self.assertEqual(wait_for_supervisor(Path(".")), good)
        with patch("compact_product.version.verify", return_value={"source_sha256":"expected"}), patch("compact_product.operations.status", return_value={"supervisor":wrong}):
            with self.assertRaises(TimeoutError):
                wait_for_supervisor(Path("."), timeout=0)


if __name__ == "__main__":
    unittest.main()
