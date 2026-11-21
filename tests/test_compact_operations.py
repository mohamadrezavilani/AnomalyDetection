from contextlib import ExitStack, nullcontext
from pathlib import Path
from types import SimpleNamespace
import json
import tempfile
import unittest
from unittest.mock import Mock, patch
from compact_product.config import Config
from compact_product.operations import execute, legacy_receipt


class CompactOperationTests(unittest.TestCase):
    def exercise(self, action, *, fail=None, task_failure=False):
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
            observation = dict(
                measurement=dict(
                    fresh_windows=3,
                    new_source_records=100,
                    fresh_windows_analyzed=3,
                    latest_revisions_consumed=3,
                ),
                web_p95_seconds=0.2,
                samples=[
                    dict(
                        health=dict(
                            analysis_latency_p95_seconds=1,
                            latest_readiness={"service_rate": {"NORMAL": 1}},
                        )
                    )
                ],
            )
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


if __name__ == "__main__":
    unittest.main()
