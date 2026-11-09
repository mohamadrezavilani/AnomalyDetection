"""Synthetic transports and disposable-DB tests; never contact Elasticsearch."""
import copy
from datetime import timedelta
import hashlib
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import uuid

from p24_foundation.collector_pipeline import (capture_summary, capture_window, load_plan,
                                               publish_plan, verified_target)
from p24_foundation.errors import FoundationError
from p24_foundation.privacy import canonical
from p24_foundation.publication import ObservationPublisher
from p24_foundation.store import FoundationStore, initialize
from p24_foundation.time import parse_time
from tests.acquisition_helpers import capture, START, END
from tests.helpers import (ROOT, TEST_KEYS, document, fixture, MANIFEST,
                           issue_test_access_token, test_access_policy)


def packet_for(rows, start=START, end=END, pattern="fixture-*"):
    packet = capture(rows)
    packet["acquisition"].update(window_start=start, window_end=end, index_pattern=pattern)
    initial = packet["slices"][0]["attempts"][0]["initial_request"]
    initial["index"] = pattern
    initial["body"]["query"]["bool"]["filter"][0]["range"]["@timestamp"] = {"gte": start, "lt": end}
    return packet


class FakeTransport:
    def __init__(self, pages):
        self.pages = iter(pages)
        self.calls, self.cleared = [], []

    def next(self):
        result = next(self.pages)
        if isinstance(result, Exception):
            raise result
        return copy.deepcopy(result)

    def search(self, **kwargs):
        self.calls.append(("search", kwargs))
        return self.next()

    def scroll(self, **kwargs):
        self.calls.append(("scroll", kwargs))
        return self.next()

    def clear_scroll(self, **kwargs):
        self.cleared.append(kwargs["scroll_id"])


class PlanFiles:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def plan(self, packets, **changes):
        items = []
        for index, packet in enumerate(packets):
            data = canonical(packet)
            path = self.root / f"capture-{index}.json"
            path.write_bytes(data)
            items.append(dict(path=path.name, sha256=hashlib.sha256(data).hexdigest()))
        result = dict(version="p24-collector-import.1", stream="synthetic-main", index_pattern="fixture-*",
                      expected_generation=0, event_cutoff=END, captures=items)
        result.update(changes)
        path = self.root / "plan.json"
        path.write_bytes(canonical(result))
        return path, result


class CollectorPipelineTests(PlanFiles, unittest.TestCase):
    def test_plan_generation_rejects_excess_files_before_reading_and_stops_at_byte_limit(self):
        from tools import collector_pipeline as command
        source = self.root / "capture.json"
        source.write_bytes(canonical(capture()))
        args = SimpleNamespace(stream="synthetic-main", index_pattern="fixture-*", expected_generation=0,
            event_cutoff=END, captures=[source] * 129, replacements=None, output=self.root / "output.json")
        with patch.object(command, "read_batch", side_effect=AssertionError("must not read")):
            with self.assertRaisesRegex(FoundationError, "collector_plan_input_limit"):
                command.generate_plan(args)
        args.captures = [source] * 3
        with patch.object(command, "MAX_INPUT_BYTES", len(source.read_bytes())), \
             patch.object(command, "read_batch", wraps=command.read_batch) as reader:
            with self.assertRaisesRegex(FoundationError, "collector_plan_input_limit"):
                command.generate_plan(args)
            self.assertLessEqual(reader.call_count, 2)
        self.assertFalse(args.output.exists())

    def test_plan_validation_file_is_private_and_removed_when_validation_fails(self):
        from tools import collector_pipeline as command
        source = self.root / "capture.json"
        source.write_bytes(canonical(capture()))
        args = SimpleNamespace(stream="synthetic-main", index_pattern="fixture-*", expected_generation=0,
            event_cutoff=END, captures=[source], replacements=None, output=self.root / "output.json")
        temporary = []
        def reject(path):
            temporary.append(path)
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            raise FoundationError("validation_rejected")
        with patch.object(command, "load_plan", side_effect=reject):
            with self.assertRaisesRegex(FoundationError, "validation_rejected"):
                command.generate_plan(args)
        self.assertEqual(len(temporary), 1)
        self.assertFalse(temporary[0].exists())
        self.assertFalse(args.output.exists())

    def test_plan_command_hashes_explicit_capture_validates_and_preserves_source(self):
        from tools.collector_pipeline import generate_plan
        source = self.root / "capture.json"
        source.write_bytes(canonical(capture()))
        original = source.read_bytes()
        output = self.root / "nested" / "import-plan.json"
        result = generate_plan(SimpleNamespace(stream="synthetic-main", index_pattern="fixture-*",
            expected_generation=0, event_cutoff=END, captures=[source], replacements=None, output=output))
        raw = json.loads(output.read_bytes())
        validated = load_plan(output)
        self.assertEqual(result["status"], "planned")
        self.assertFalse(result["database_used"])
        self.assertFalse(result["network_used"])
        self.assertEqual(raw["version"], "p24-collector-import.1")
        self.assertEqual(raw["captures"][0]["sha256"], hashlib.sha256(original).hexdigest())
        self.assertEqual(len(validated["captures"]), 1)
        self.assertEqual(source.read_bytes(), original)

    def test_plan_command_rejects_partial_bad_cutoff_and_existing_output(self):
        from tools.collector_pipeline import generate_plan
        packet = capture()
        packet["slices"][0]["attempts"][0]["failure_kind"] = "transport_timeout"
        source = self.root / "partial.json"
        source.write_bytes(canonical(packet))
        output = self.root / "plan.json"
        args = SimpleNamespace(stream="synthetic-main", index_pattern="fixture-*", expected_generation=0,
            event_cutoff=END, captures=[source], replacements=None, output=output)
        with self.assertRaises(FoundationError):
            generate_plan(args)
        source.write_bytes(canonical(capture()))
        args.event_cutoff = "2026-10-20T07:25:00Z"
        with self.assertRaises(FoundationError):
            generate_plan(args)
        output.write_bytes(b"keep-existing")
        args.event_cutoff = END
        with self.assertRaisesRegex(FoundationError, "collector_plan_output_exists"):
            generate_plan(args)
        self.assertEqual(output.read_bytes(), b"keep-existing")

    def test_plan_command_requires_unique_replacement_hints_for_explicit_windows(self):
        from tools.collector_pipeline import generate_plan
        source = self.root / "capture.json"
        source.write_bytes(canonical(capture()))
        hint = {"window_start": START, "window_end": END,
                "snapshot_id": "00000000-0000-4000-8000-000000000001", "intake_revision": 1}
        hints = self.root / "replacements.json"
        hints.write_text(json.dumps([hint, hint]))
        args = SimpleNamespace(stream="synthetic-main", index_pattern="fixture-*", expected_generation=0,
            event_cutoff=END, captures=[source], replacements=hints, output=self.root / "plan.json")
        with self.assertRaisesRegex(FoundationError, "invalid_collector_plan_input"):
            generate_plan(args)
        hints.write_text(json.dumps([dict(hint, window_start="2026-10-20T07:20:00Z",
                                         window_end="2026-10-20T07:25:00Z")]))
        with self.assertRaisesRegex(FoundationError, "invalid_collector_plan_input"):
            generate_plan(args)
        hints.write_text(json.dumps([hint]))
        result = generate_plan(args)
        self.assertEqual(result["status"], "planned")
        self.assertEqual(json.loads(args.output.read_text())["captures"][0]["replaces"],
                         {"snapshot_id": hint["snapshot_id"], "intake_revision": 1})

    def test_actual_requests_and_final_cursor_are_retained_without_deduplication(self):
        pages = [p["response"] for p in capture()["slices"][0]["attempts"][0]["pages"]]
        client = FakeTransport(pages)
        result = capture_window(client, index_pattern="fixture-*", start=START, end=END)
        self.assertTrue(capture_summary(result)["query_traversal_complete"])
        self.assertFalse(capture_summary(result)["source_window_complete"])
        self.assertEqual(client.cleared, ["SYNTHETIC_CURSOR_FINAL"])
        recorded = json.loads(result.original)
        attempt = recorded["slices"][0]["attempts"][0]
        self.assertEqual(attempt["initial_request"]["body"], client.calls[0][1]["body"])
        self.assertEqual([p["response"] for p in attempt["pages"]], pages)
        self.assertEqual(client.calls[2][1]["scroll_id"], "SYNTHETIC_CURSOR_1")

    def test_partial_transport_failure_is_retained_and_not_importable(self):
        packet = capture()
        first = packet["slices"][0]["attempts"][0]["pages"][0]["response"]
        client = FakeTransport([first, TimeoutError("PRIVATE_URL_AND_PASSWORD")])
        batch = capture_window(client, index_pattern="fixture-*", start=START, end=END)
        summary = capture_summary(batch)
        self.assertEqual(len(batch.records), 1)
        self.assertFalse(summary["query_traversal_complete"])
        self.assertNotIn("PRIVATE_URL_AND_PASSWORD", json.dumps(summary))
        self.assertEqual(client.cleared, ["SYNTHETIC_CURSOR_0"])
        path, _ = self.plan([json.loads(batch.original)])
        with self.assertRaisesRegex(FoundationError, "collector_capture_not_eligible"):
            load_plan(path)

    def test_unassessable_response_is_retained_without_forging_accepted_records(self):
        packet = capture([document(message="RAW_DIAGNOSTIC_SENTINEL")])
        pages = [p["response"] for p in packet["slices"][0]["attempts"][0]["pages"]]
        pages[0]["hits"]["total"] = {"value": True, "relation": "eq"}
        batch = capture_window(FakeTransport(pages), index_pattern="fixture-*", start=START, end=END)
        summary = capture_summary(batch)
        self.assertIn(b"RAW_DIAGNOSTIC_SENTINEL", batch.original)
        self.assertNotIn("RAW_DIAGNOSTIC_SENTINEL", json.dumps(summary))
        self.assertEqual(summary["assessment_status"], "invalid_capture")
        self.assertIsNone(summary["records"])
        self.assertFalse(summary["query_traversal_complete"])
        path, _ = self.plan([json.loads(batch.original)])
        with self.assertRaisesRegex(FoundationError, "invalid_acquisition_total"):
            load_plan(path)

    def test_missing_final_cursor_does_not_erase_latest_valid_cleanup_cursor(self):
        pages = [p["response"] for p in capture()["slices"][0]["attempts"][0]["pages"]]
        pages[-1].pop("_scroll_id")
        client = FakeTransport(pages)
        batch = capture_window(client, index_pattern="fixture-*", start=START, end=END)
        self.assertTrue(capture_summary(batch)["query_traversal_complete"])
        self.assertEqual(client.cleared, ["SYNTHETIC_CURSOR_1"])

    def test_duplicate_origin_and_bad_shards_do_not_become_complete(self):
        for change in ("duplicate", "shards"):
            packet = capture()
            pages = [p["response"] for p in packet["slices"][0]["attempts"][0]["pages"]]
            if change == "duplicate":
                pages[1]["hits"]["hits"] = pages[0]["hits"]["hits"]
            else:
                pages[0]["_shards"] = dict(total=1, successful=0, failed=1)
            batch = capture_window(FakeTransport(pages), index_pattern="fixture-*", start=START, end=END)
            self.assertFalse(capture_summary(batch)["query_traversal_complete"])

    def test_capture_record_bound_keeps_partial_evidence_and_stops_requests(self):
        pages = [p["response"] for p in capture()["slices"][0]["attempts"][0]["pages"]]
        client = FakeTransport(pages)
        with patch("p24_foundation.collector_pipeline.MAX_RECORDS", 1):
            batch = capture_window(client, index_pattern="fixture-*", start=START, end=END)
        self.assertEqual(len(batch.records), 1)
        self.assertEqual(len(client.calls), 2)
        self.assertFalse(capture_summary(batch)["query_traversal_complete"])
        self.assertEqual(json.loads(batch.original)["slices"][0]["attempts"][0]["failure_kind"], "cancelled")

    def test_invalid_window_and_bounds_make_no_requests(self):
        client = FakeTransport([])
        for changes in (dict(end="2026-10-20T07:35:00Z"), dict(max_runtime_seconds=True),
                        dict(page_size=10001), dict(index_pattern="bad index")):
            args = dict(index_pattern="fixture-*", start=START, end=END)
            args.update(changes)
            with self.assertRaises(FoundationError):
                capture_window(client, **args)
        self.assertEqual(client.calls, [])

    def test_summary_filters_raw_identity_secrets_and_scroll_cursors(self):
        row = document(message="PASSWORD_RAW_SENTINEL OTP_RAW_SENTINEL SESSION_RAW_SENTINEL")
        pages = [p["response"] for p in capture([row])["slices"][0]["attempts"][0]["pages"]]
        batch = capture_window(FakeTransport(pages), index_pattern="fixture-*", start=START, end=END)
        self.assertIn(b"PASSWORD_RAW_SENTINEL", batch.original)
        public = json.dumps(capture_summary(batch))
        for sentinel in ("PASSWORD_RAW_SENTINEL", "OTP_RAW_SENTINEL", "SESSION_RAW_SENTINEL", "SYNTHETIC_CURSOR"):
            self.assertNotIn(sentinel, public)

    def test_plan_pins_original_bytes_and_checks_scope_before_database_access(self):
        path, raw = self.plan([capture()])
        plan = load_plan(path)
        self.assertEqual(len(plan["captures"]), 1)
        self.assertTrue(plan["captures"][0]["source_key"].startswith("collector:synthetic-main:"))
        (self.root / raw["captures"][0]["path"]).write_bytes(canonical(capture([])))
        with self.assertRaisesRegex(FoundationError, "collector_capture_digest_mismatch"):
            load_plan(path)

    def test_legacy_dump_filtered_or_wrong_stream_capture_is_rejected(self):
        legacy = dict(logs=[document()], count=1, complete=True, window_start=START, window_end=END)
        filtered = capture()
        filtered["acquisition"]["query"]["scope"] = "filtered"
        for packet, changes in ((legacy, {}), (filtered, {}), (capture(), {"index_pattern": "another-*"})):
            path, _ = self.plan([packet], **changes)
            with self.assertRaises(FoundationError):
                load_plan(path)

    def test_plan_rejects_duplicate_windows_booleans_and_duplicate_json_keys(self):
        path, _ = self.plan([capture(), capture()])
        with self.assertRaisesRegex(FoundationError, "duplicate_collector_window"):
            load_plan(path)
        path, _ = self.plan([capture()], expected_generation=True)
        with self.assertRaises(FoundationError):
            load_plan(path)
        path.write_text('{"version":0,"version":1}')
        with self.assertRaisesRegex(FoundationError, "invalid_collector_import_plan"):
            load_plan(path)

    def test_target_verification_and_cli_fail_without_importing_source_or_echoing_paths(self):
        (self.root / "elastic_log_fetcher.py").write_text("raise RuntimeError('PRIVATE_SENTINEL')")
        with self.assertRaisesRegex(FoundationError, "collector_target_hash_mismatch"):
            verified_target(self.root)
        process = subprocess.run([sys.executable, str(ROOT / "tools/collector_pipeline.py"),
            "inspect", "--target-root", str(self.root)], capture_output=True, text=True)
        self.assertEqual(process.returncode, 2)
        self.assertNotIn("PRIVATE_SENTINEL", process.stdout + process.stderr)
        self.assertNotIn(str(self.root), process.stdout + process.stderr)

    def test_capture_existing_output_refuses_before_loading_target_or_network(self):
        from tools import collector_pipeline as command
        output = self.root / "capture.json"
        output.write_bytes(b"preserve-original")
        with patch.object(command, "verified_target", side_effect=AssertionError("must not load source")):
            with self.assertRaisesRegex(FoundationError, "collector_capture_output_exists"):
                command.collect(SimpleNamespace(output=output))
        self.assertEqual(output.read_bytes(), b"preserve-original")

    def test_transport_verification_rejects_unknown_bytes_without_executing_them(self):
        from p24_foundation.collector_pipeline import verified_transport
        (self.root/'elastic_log_fetcher.py').write_text("raise RuntimeError('PRIVATE_SENTINEL')")
        with self.assertRaisesRegex(FoundationError,'collector_transport_hash_mismatch'):
            verified_transport(self.root)

    def test_transport_missing_file_uses_safe_error(self):
        from p24_foundation.collector_pipeline import verified_transport
        with self.assertRaisesRegex(FoundationError,'collector_transport_file_missing'):
            verified_transport(self.root)

    def test_transport_loader_suppresses_settings_output_restores_modules_and_never_runs_main(self):
        from tools import collector_pipeline as command
        files={"PopulationVersion/config.py":b"print('PRIVATE_SETTINGS')\nES_INDEX_PATTERN='fixture-*'\n",
               "elastic_log_fetcher.py":b"from config import ES_INDEX_PATTERN as INDEX_PATTERN\nif __name__=='__main__': raise RuntimeError('must not start')\n"}
        previous=sys.modules.get('config');old_path=sys.path[:];output=io.StringIO()
        with patch.object(command,'verified_transport',return_value=files),redirect_stdout(output):
            module=command.load_transport(self.root)
        self.assertEqual(output.getvalue(),'');self.assertEqual(module.INDEX_PATTERN,'fixture-*')
        self.assertIs(sys.modules.get('config'),previous);self.assertEqual(sys.path,old_path)
        self.assertFalse((self.root/'postgres_migration').exists())

    def test_capture_uses_narrow_transport_and_preserves_transcript(self):
        from contextlib import nullcontext
        from tools import collector_pipeline as command
        client=FakeTransport([dict(_scroll_id='one',hits=dict(total=dict(value=0,relation='eq'),hits=[]),_shards=dict(total=1,successful=1,failed=0),timed_out=False)])
        module=SimpleNamespace(INDEX_PATTERN='fixture-*',SCROLL_PAGE_SIZE=10,get_es=lambda:client,
                               fetch_budget=lambda seconds:nullcontext(),_remaining_fetch_time=lambda:None)
        args=SimpleNamespace(target_root=self.root,start=START,end=END,output=self.root/'capture.json',max_runtime_seconds=10)
        with patch.object(command,'load_transport',return_value=module):result=command.collect(args)
        self.assertEqual(result['status'],'captured');self.assertTrue(args.output.exists())
        self.assertEqual(len(client.calls),1)

    def test_requested_native_not_run_is_not_reported_as_overall_pass(self):
        from tools import preflight_replay as command
        output = self.root / "preflight.json"
        args = ["preflight", "--config", "unused.local.py", "--output", str(output)]
        results = [({"status": "PASS"}, 0), ({"status": "NOT_RUN"}, 2)]
        with patch.object(sys, "argv", args), patch.object(command, "run_suite", side_effect=results), redirect_stdout(io.StringIO()):
            self.assertEqual(command.main(), 2)
        self.assertEqual(json.loads(output.read_text())["status"], "NOT_RUN")


class CollectorPipelinePostgresTests(PlanFiles, unittest.TestCase):
    connection = None
    database_config = None

    @classmethod
    def setUpClass(cls):
        if cls.connection is None:
            raise unittest.SkipTest("disposable PostgreSQL configuration required")
        initialize(cls.connection)

    def setUp(self):
        super().setUp()
        self.c = self.connection
        self.namespace = "collector_" + uuid.uuid4().hex
        self.token = issue_test_access_token(self.namespace)
        self.store = FoundationStore(self.c, TEST_KEYS, self.namespace, self.root / "vault",
                                     access_policy=test_access_policy(self.namespace))
        self.pub = ObservationPublisher(self.store)

    def apply(self, packets, *, generation=0, pattern="fixture-*", replacements=None):
        path, raw = self.plan(packets, expected_generation=generation, index_pattern=pattern,
                              event_cutoff="2026-10-20T07:45:00Z")
        for item, replacement in zip(raw["captures"], replacements or [None] * len(packets)):
            if replacement is not None:
                item["replaces"] = {key: replacement[key] for key in ("snapshot_id", "intake_revision")}
        path.write_bytes(canonical(raw))
        return publish_plan(self.store, load_plan(path))

    def fixture_packets(self, name):
        grouped = {}
        for row in fixture(name).records:
            value = row.get("_source", {}).get("@timestamp") or row["fields"]["@timestamp"][0]
            at = parse_time(value).floor
            start = at.replace(minute=(at.minute // 5) * 5, second=0, microsecond=0)
            grouped.setdefault(start, []).append(row)
        return [packet_for(sorted(rows, key=lambda r: r["_id"]), start.isoformat(),
                           (start + timedelta(minutes=5)).isoformat(), "logs-*")
                for start, rows in sorted(grouped.items())]

    def test_native_supervised_children_commit_in_order_and_stale_plan_stops_run(self):
        from p24_foundation.replay import replay_plans, inspect_plan_commit
        keys = self.root / "keys.json"
        keys.write_bytes(canonical(dict(equality=TEST_KEYS.equality.hex(), encryption=TEST_KEYS.encryption.hex(),
                                       version=TEST_KEYS.version)))
        config = self.root / "config.local.py"
        text = ("DATABASE = " + repr(self.database_config) + "\nNAMESPACE = " + repr(self.namespace)
                + "\nKEYS_PATH = " + repr(str(keys)) + "\nVAULT_PATH = " + repr(str(self.root / "vault")) + "\n")
        with os.fdopen(os.open(config, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as stream:
            stream.write(text)
        _, raw = self.plan([capture()])
        first_plan, second_plan = self.root / "first.json", self.root / "second.json"
        first_plan.write_bytes(canonical(raw))
        raw["expected_generation"] = 1
        second_plan.write_bytes(canonical(raw))
        command = [sys.executable, str(ROOT / "tools/collector_pipeline.py")]
        result = replay_plans(config=config, plans=[first_plan, second_plan], max_runtime_seconds=30,
                              output=self.root / "success.json", publish_command=command)
        self.assertEqual(result["status"], "completed")
        self.assertEqual([step["generation"] for step in result["steps"]], [1, 2])
        second = self.pub._current()[0]
        stopped = replay_plans(config=config, plans=[first_plan, second_plan], max_runtime_seconds=30,
                               output=self.root / "stopped.json", publish_command=command)
        self.assertEqual(stopped["status"], "stopped")
        self.assertEqual(len(stopped["steps"]), 1)
        self.assertEqual(self.pub._current(), (second, 2))
        inspected = inspect_plan_commit(self.c, self.namespace, load_plan(first_plan))
        self.assertEqual(inspected["assessment"], "planned_content_observed")
        self.assertEqual(inspected["current_generation"], 2)

    def test_native_session_golden_replay_and_identical_receipts_keep_counts(self):
        packets = self.fixture_packets("session_activity.sanitized.json")
        first = self.apply(packets, pattern="logs-*")
        self.assertEqual((first["distinct_client_requests"], first["selected_request_events"]), (10, 33))
        page = self.pub.session_activity(first["publication_id"], MANIFEST["anchors"]["session_token"], access_token=self.token)
        self.assertEqual(page["total_requests"], 10)
        second = self.apply(packets, generation=1, pattern="logs-*")
        self.assertTrue(all(item["reused"] for item in second["imported"]))
        self.assertEqual((second["distinct_client_requests"], second["selected_request_events"]), (10, 33))
        self.assertFalse(self.pub._header(second["publication_id"])["coverage"]["source_window_complete"])
        from p24_foundation.replay import inspect_plan_commit
        inspected = inspect_plan_commit(self.c, self.namespace, load_plan(self.root / "plan.json"))
        self.assertEqual(inspected["assessment"], "planned_content_observed")
        self.assertEqual(inspected["publication_id"], second["publication_id"])
        first_plan = load_plan(self.root / "plan.json")
        first_plan["expected_generation"] = 0
        historical = inspect_plan_commit(self.c, self.namespace, first_plan)
        self.assertEqual(historical["publication_id"], first["publication_id"])
        self.assertEqual(historical["current_generation"], 2)

    def test_native_explicit_correction_preserves_old_pin_and_source_evidence(self):
        first = self.apply([capture([document()])])
        changed = document()
        changed["_source"]["message"] = "POST https://fixture.invalid/config HTTP/1.1 (G00002 | Unknown)"
        with self.assertRaisesRegex(FoundationError, "collector_explicit_replacement_required"):
            self.apply([capture([changed])], generation=1)
        second = self.apply([capture([changed])], generation=1, replacements=first["imported"])
        self.assertEqual(self.pub.request(first["publication_id"], "request-A", access_token=self.token)["summary"]["final_outcome"], "success")
        self.assertNotEqual(self.pub.request(second["publication_id"], "request-A", access_token=self.token)["summary"]["final_outcome"], "success")
        self.assertEqual(self.c.execute("SELECT count(*) FROM p24_next.source_snapshot WHERE namespace_id=%s", (self.store.namespace_id,)).fetchone()[0], 2)
        self.assertEqual(len(self.pub._header(second["publication_id"])["input_manifest"]["superseded"]), 1)

    def test_native_overlapping_fixture_union_revises_33_to_36_without_new_session(self):
        initial = self.fixture_packets("session_activity.sanitized.json")
        first = self.apply(initial, pattern="logs-*")
        originals = {packet["acquisition"]["window_start"]: (canonical(packet), source)
                     for packet, source in zip(initial, first["imported"])}
        union = self.fixture_packets("ip_activity.sanitized.json")
        replacements = []
        for packet in union:
            old = originals.get(packet["acquisition"]["window_start"])
            replacements.append(old[1] if old and old[0] != canonical(packet) else None)
        second = self.apply(union, generation=1, pattern="logs-*", replacements=replacements)
        self.assertEqual((second["distinct_client_requests"], second["selected_request_events"], second["known_sessions"]), (11, 36, 1))
        old = self.pub.info(first["publication_id"], access_token=self.token)
        self.assertEqual((old["distinct_client_requests"], old["selected_request_events"]), (10, 33))

    def test_native_stale_generation_and_failed_commit_leave_pointer_and_receipts_unchanged(self):
        first = self.apply([capture()])
        before = self.c.execute("SELECT count(*) FROM p24_next.foundation_source_receipt WHERE namespace_id=%s", (self.store.namespace_id,)).fetchone()[0]
        with self.assertRaisesRegex(FoundationError, "stale_publication_generation"):
            self.apply([capture()])
        changed = document(rid="capture-A", oid="capture-origin-A")
        changed["_source"]["ExecutionTime"] = "5.0"
        with patch.object(ObservationPublisher, "publish", side_effect=FoundationError("injected_publish_failure")):
            with self.assertRaisesRegex(FoundationError, "injected_publish_failure"):
                self.apply([capture([changed])], generation=1, replacements=first["imported"])
        self.assertEqual(str(self.pub._current()[0]), first["publication_id"])
        self.assertEqual(self.c.execute("SELECT count(*) FROM p24_next.foundation_source_receipt WHERE namespace_id=%s", (self.store.namespace_id,)).fetchone()[0], before)
        self.assertEqual(self.c.execute("SELECT count(*) FROM p24_next.source_snapshot WHERE namespace_id=%s", (self.store.namespace_id,)).fetchone()[0], 1)
        self.assertEqual(self.c.execute("SELECT count(*) FROM p24_next.foundation_source_replacement WHERE namespace_id=%s", (self.store.namespace_id,)).fetchone()[0], 0)

    def test_native_boundary_chain_crosses_windows_and_keeps_outcome_layers(self):
        packets = self.fixture_packets("boundary.sanitized.json")
        self.assertEqual(len(packets), 2)
        first = self.apply(packets[:1], pattern="logs-*")
        result = self.apply(packets[1:], pattern="logs-*", generation=1)
        old = self.pub.request(first["publication_id"], MANIFEST["anchors"]["boundary_request_id"], access_token=self.token)["summary"]
        self.assertEqual((old["selected_event_count"], old["final_outcome"]), (11, "unknown"))
        summary = self.pub.request(result["publication_id"], MANIFEST["anchors"]["boundary_request_id"], access_token=self.token)["summary"]
        self.assertEqual((summary["selected_event_count"], summary["sql_observation_count"], summary["provider_observation_count"]), (14, 12, 1))
        self.assertEqual((summary["final_outcome"], summary["outcome_code"]), ("failure", "GD2016"))
        self.assertEqual(result["workflow_status"], "unavailable_no_reviewed_adapter")
