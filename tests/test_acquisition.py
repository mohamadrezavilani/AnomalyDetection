import copy
import contextlib
import gzip
import hashlib
import io
import json
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import psycopg

from p24_foundation.errors import FoundationError
from p24_foundation.intake import decode_batch, read_batch
from p24_foundation.privacy import canonical
from p24_foundation.store import FoundationStore, _safe_source_manifest, initialize, jsonb
from tests.acquisition_helpers import START, END, capture, captured, assessment, attempt
from tests.helpers import ROOT, TEST_KEYS, document,issue_test_access_token,test_access_policy


class AcquisitionTests(unittest.TestCase):
    def test_terminal_traversal_is_qualified_separately_from_window_finality(self):
        a = assessment(capture())
        self.assertTrue(a["query_traversal_complete"])
        self.assertTrue(a["window_scope_eligible"])
        self.assertFalse(a["source_window_complete"])
        self.assertEqual(a["source_claim_state"], "unverified_local_capture")
        self.assertEqual(a["source_finality"], "not_established")
        self.assertEqual((a["selected_record_count"], len(a["pages"])), (2, 3))
        self.assertEqual([p["first_selected_row"] for p in a["pages"]], [0, 1, 2])

    def test_matching_hit_count_without_terminal_page_is_partial(self):
        a = assessment(capture(terminal=False))
        self.assertFalse(a["query_traversal_complete"])
        self.assertIn("no_terminal_empty_page", a["issues"])
        self.assertEqual(a["selected_record_count"], 2)

    def test_empty_initial_page_needs_positive_shard_and_request_evidence(self):
        p = capture([])
        self.assertTrue(assessment(p)["query_traversal_complete"])
        attempt(p)["pages"][0]["response"]["_shards"]["total"] = 0
        self.assertFalse(assessment(p)["query_traversal_complete"])
        self.assertEqual(len(captured(p).records), 0)

    def test_total_relation_lower_bound_or_missing_never_becomes_exact(self):
        for relation in ("gte", None):
            with self.subTest(relation=relation):
                p = capture(relation=relation)
                a = assessment(p)
                self.assertTrue(a["query_traversal_complete"])
                self.assertEqual(a["slices"][0]["total_relation"], relation or "unknown")
                self.assertIsNone(a["slices"][0]["exact_total"])
                self.assertFalse(a["source_window_complete"])

    def test_total_mismatch_is_retained_and_disqualifies_traversal(self):
        for relation, issue in (("eq", "exact_total_mismatch"), ("gte", "lower_bound_exceeds_observed")):
            with self.subTest(relation=relation):
                p = capture(relation=relation)
                attempt(p)["pages"][0]["response"]["hits"]["total"]["value"] = 5
                self.assertIn(issue, assessment(p)["issues"])
                self.assertEqual(len(captured(p).records), 2)

    def test_timeout_shard_and_early_termination_signals_preserve_partial_rows(self):
        mutations = [({"timed_out": True}, "timeout_or_missing_signal"),
                     ({"_shards": {"total": 2, "successful": 1, "failed": 1}}, "incomplete_shards"),
                     ({"_shards": {}}, "missing_shard_evidence"),
                     ({"terminated_early": True}, "terminated_early")]
        for fields, issue in mutations:
            with self.subTest(issue=issue):
                p = capture()
                attempt(p)["pages"][1]["response"].update(fields)
                b = captured(p)
                self.assertEqual(len(b.records), 2)
                self.assertIn(issue, b.coverage["acquisition"]["issues"])
        p = capture()
        del attempt(p)["pages"][0]["response"]["timed_out"]
        self.assertIn("timeout_or_missing_signal", assessment(p)["issues"])

    def test_latest_scroll_cursor_is_used_and_repeated_cursor_is_valid(self):
        p = capture()
        attempt(p)["pages"][1]["request_cursor"] = "SYNTHETIC_STALE_CURSOR"
        self.assertIn("cursor_chain_mismatch", assessment(p)["issues"])
        for page in attempt(p)["pages"]:
            page["response"]["_scroll_id"] = "SYNTHETIC_CONSTANT_CURSOR"
        for page in attempt(p)["pages"][1:]:
            page["request_cursor"] = "SYNTHETIC_CONSTANT_CURSOR"
        self.assertTrue(assessment(p)["query_traversal_complete"])

    def test_page_gap_missing_cursor_and_pages_after_terminal_are_detected(self):
        p = capture()
        attempt(p)["pages"][1]["ordinal"] = 2
        self.assertIn("page_sequence_gap", assessment(p)["issues"])
        p = capture()
        del attempt(p)["pages"][0]["response"]["_scroll_id"]
        self.assertIn("missing_scroll_cursor", assessment(p)["issues"])
        p = capture()
        attempt(p)["pages"].append(copy.deepcopy(attempt(p)["pages"][-1]))
        self.assertIn("page_after_terminal", assessment(p)["issues"])

    def test_restart_selects_latest_attempt_without_concatenating_snapshots(self):
        p = capture([document(rid="OLD_ONLY", oid="old-origin")])
        old = attempt(p)
        old["failure_kind"] = "transport_timeout"
        new = copy.deepcopy(attempt(capture()))
        new["number"] = 2
        p["slices"][0]["attempts"].append(new)
        b = captured(p)
        self.assertTrue(b.coverage["query_complete"])
        self.assertEqual([r["_source"]["RequestID"] for r in b.records], ["capture-A", "capture-B"])
        self.assertIn(b"OLD_ONLY", b.original)
        a = b.coverage["acquisition"]
        self.assertEqual((a["all_attempt_record_count"], a["selected_record_count"]), (3, 2))
        self.assertEqual(a["slices"][0]["attempts"][0]["failure_kind"], "transport_timeout")

    def test_failed_latest_attempt_does_not_fall_back_to_earlier_complete_attempt(self):
        p = capture()
        failed = copy.deepcopy(attempt(p))
        failed.update(number=2, pages=[], failure_kind="http_error")
        p["slices"][0]["attempts"].append(failed)
        b = captured(p)
        self.assertEqual(len(b.records), 0)
        self.assertFalse(b.coverage["query_complete"])
        self.assertIn("selected_attempt_failed", b.coverage["acquisition"]["issues"])
        self.assertEqual(b.coverage["acquisition"]["all_attempt_record_count"], 2)

    def test_multi_slice_partitions_have_independent_views_and_missing_slice_is_partial(self):
        p = capture([document(oid="partition-A")])
        p["acquisition"]["expected_slices"] = 2
        attempt(p)["initial_request"]["body"]["slice"] = dict(id=0, max=2)
        self.assertIn("missing_slice", assessment(p)["issues"])
        part = copy.deepcopy(p["slices"][0])
        part["id"] = 1
        part["attempts"][0]["initial_request"]["body"]["slice"] = dict(id=1, max=2)
        part["attempts"][0]["pages"][0]["response"]["hits"]["hits"][0]["_id"] = "partition-B"
        p["slices"].append(part)
        a = assessment(p)
        self.assertTrue(a["query_traversal_complete"])
        self.assertEqual(a["snapshot_consistency"], "independent_slice_views")
        part["attempts"][0]["initial_request"]["body"]["slice"]["id"] = 0
        self.assertIn("initial_slice_mismatch", assessment(p)["issues"])

    def test_duplicate_or_conflicting_origins_do_not_get_overwritten(self):
        d = document()
        p = capture([d, copy.deepcopy(d)])
        a = assessment(p)
        self.assertEqual((a["selected_record_count"], a["distinct_selected_origins"], a["duplicate_origin_rows"]), (2, 1, 1))
        self.assertIn("duplicate_origin_in_traversal", a["issues"])
        attempt(p)["pages"][1]["response"]["hits"]["hits"][0]["_source"]["message"] += " conflicting"
        self.assertIn("conflicting_origin_in_traversal", assessment(p)["issues"])

    def test_retained_request_is_required_and_declared_scope_cannot_hide_extra_filters(self):
        p = capture()
        del attempt(p)["initial_request"]
        self.assertIn("initial_request_not_retained", assessment(p)["issues"])
        p = capture()
        attempt(p)["initial_request"]["body"]["query"]["bool"]["filter"].append({"term": {"IP": "SYNTHETIC_QUERY_VALUE"}})
        a = assessment(p)
        self.assertTrue(a["query_traversal_complete"])
        self.assertFalse(a["window_scope_eligible"])
        self.assertIn("declared_query_scope_mismatch", a["scope_issues"])
        self.assertNotIn("SYNTHETIC_QUERY_VALUE", json.dumps(a))

    def test_recorded_time_bounds_index_and_search_options_are_checked(self):
        p = capture()
        initial = attempt(p)["initial_request"]
        initial["body"]["query"]["bool"]["filter"][0]["range"]["@timestamp"]["lt"] = "2026-10-20T07:29:00Z"
        self.assertIn("initial_time_bounds_mismatch", assessment(p)["scope_issues"])
        initial["index"] = "another-*"
        self.assertIn("initial_index_mismatch", assessment(p)["issues"])
        initial["body"]["terminate_after"] = 1
        self.assertIn("unverified_search_options", assessment(p)["scope_issues"])

    def test_unresolved_index_alias_does_not_assert_complete_window_scope(self):
        p = capture()
        p["acquisition"]["index_pattern"] = "an-alias"
        attempt(p)["initial_request"]["index"] = "an-alias"
        a = assessment(p)
        self.assertTrue(a["query_traversal_complete"])
        self.assertFalse(a["window_scope_eligible"])
        self.assertIn("index_resolution_not_established", a["scope_issues"])

    def test_level_filtered_queries_keep_traversal_and_window_scope_distinct(self):
        p = capture()
        p["acquisition"]["query"].update(scope="filtered", level_filter=["Info"])
        attempt(p)["initial_request"]["body"]["query"]["bool"]["filter"].append({"terms": {"level": ["Info"]}})
        a = assessment(p)
        self.assertTrue(a["query_traversal_complete"])
        self.assertFalse(a["window_scope_eligible"])
        self.assertIn("recorded_query_has_filters", a["scope_issues"])

    def test_submicrosecond_source_times_respect_the_half_open_window(self):
        for at, outside in (("2026-10-20T07:29:59.999999999Z", 0), (END, 1), ("2026-10-20T07:30:00.0000001Z", 1)):
            with self.subTest(at=at):
                a = assessment(capture([document(at=at)]))
                self.assertEqual(a["event_time_outside_rows"], outside)
                self.assertEqual(a["query_traversal_complete"], not outside)
        d = document()
        del d["_source"]["@timestamp"]
        self.assertIn("unknown_event_time", assessment(capture([d]))["issues"])

    def test_capture_clock_is_checked_but_never_used_as_an_intake_receipt(self):
        p = capture()
        attempt(p)["pages"][0]["received_at"] = "2026-10-20T07:30:29Z"
        a = assessment(p)
        self.assertIn("capture_clock_order", a["issues"])
        self.assertNotIn("observed_at", a)

    def test_bounds_and_malformed_structures_raise_safe_errors(self):
        cases = []
        p = capture(); p["slices"].append(copy.deepcopy(p["slices"][0])); cases.append((p, "ambiguous_acquisition_slices"))
        p = capture(); attempt(p)["number"] = 2; cases.append((p, "noncontiguous_acquisition_attempts"))
        p = capture(); p["acquisition"]["attempt_budget"] = 4; cases.append((p, "invalid_acquisition_bounds"))
        p = capture(); attempt(p)["failure_kind"] = {}; cases.append((p, "invalid_acquisition_failure_kind"))
        p = capture(); attempt(p)["pages"][0]["response"]["hits"]["total"] = True; cases.append((p, "invalid_acquisition_total"))
        p = capture(); p["acquisition"]["query"]["scope"] = []; cases.append((p, "invalid_acquisition_query_scope"))
        for p, code in cases:
            with self.subTest(code=code), self.assertRaises(FoundationError) as caught:
                captured(p)
            self.assertEqual(caught.exception.code, code)
        with self.assertRaises(FoundationError) as caught:
            captured(capture(), max_records=1)
        self.assertEqual(caught.exception.code, "record_count_limit")
        with patch("p24_foundation.acquisition.MAX_PAGES", 2), self.assertRaises(FoundationError) as caught:
            captured(capture())
        self.assertEqual(caught.exception.code, "acquisition_page_limit")

    def test_legacy_complete_flag_and_count_never_prove_scroll_completion(self):
        row = document()["_source"]
        row["_source_id"] = "fixture-index:opaque-origin"
        for count in (1, 50):
            p = dict(window_start=START, window_end=END, complete=True, count=count, logs=[row])
            b = captured(p)
            self.assertEqual(b.coverage["legacy_count_matches"], count == 1)
            self.assertFalse(b.coverage["query_complete"])
            self.assertFalse(b.coverage["acquisition"]["source_window_complete"])
            self.assertEqual(b.coverage["legacy_origin_recovered_rows"], 1)
            self.assertEqual((b.records[0]["_index"], b.records[0]["_id"]), ("fixture-index", "opaque-origin"))
        row["_source_id"] = "remote:index:ambiguous"
        self.assertEqual(captured(p).coverage["legacy_origin_recovered_rows"], 0)

    def test_gzip_preserves_exact_original_bytes_and_bounds_expansion(self):
        original = captured(capture()).original
        compressed = gzip.compress(original, mtime=0)
        b = decode_batch(compressed)
        self.assertEqual(b.original, compressed)
        self.assertEqual(b.coverage["compression"], "gzip")
        self.assertEqual(b.records, decode_batch(original).records)
        with self.assertRaises(FoundationError) as caught:
            decode_batch(compressed, max_bytes=len(compressed)+100)
        self.assertEqual(caught.exception.code, "decompressed_input_size_limit")
        with self.assertRaises(FoundationError) as caught:
            decode_batch(compressed[:-8])
        self.assertEqual(caught.exception.code, "invalid_gzip_input")

    def test_duplicate_json_keys_cannot_hide_an_incomplete_signal(self):
        with self.assertRaises(FoundationError) as caught:
            decode_batch(b'{"timed_out":true,"timed_out":false,"hits":{"hits":[]}}')
        self.assertEqual(caught.exception.code, "invalid_json_input")

    def test_safe_manifest_omits_cursor_payload_and_query_values(self):
        p = capture()
        attempt(p)["pages"][0]["response"]["hits"]["hits"][0]["_source"]["password"] = "SYNTHETIC_PASSWORD_98123"
        b = captured(p)
        public = json.dumps(b.coverage)
        for forbidden in ("SYNTHETIC_PASSWORD_98123", "SYNTHETIC_CURSOR", "SESSION_A", "198.51.100.2", "capture-A"):
            self.assertNotIn(forbidden, public)
            self.assertIn(forbidden.encode(), b.original)

    def test_attempt_manifest_covers_retries_without_exposing_cursor_values(self):
        p=capture([document(rid="selected",oid="selected-origin")])
        prior=copy.deepcopy(attempt(capture([document(rid="discarded",oid="discarded-origin")])))
        prior["number"]=1;prior["failure_kind"]="transport_timeout"
        chosen=copy.deepcopy(attempt(p));chosen["number"]=2
        p["acquisition"]["attempt_budget"]=2
        p["slices"][0]["attempts"]=[prior,chosen]
        manifest=assessment(p)["capture_manifest"]
        self.assertEqual([(x["attempt"],x["selected"],x["failure_kind"]) for x in manifest["attempts"]],
                         [(1,False,"transport_timeout"),(2,True,"none")])
        self.assertTrue(all(page["first_selected_row"] is None for page in manifest["attempts"][0]["pages"]))
        self.assertEqual(manifest["attempts"][1]["pages"][0]["first_selected_row"],0)
        self.assertNotIn("SYNTHETIC_CURSOR",json.dumps(manifest))
        self.assertIn("request_cursor_sha256",json.dumps(manifest))
        unsigned={key:value for key,value in manifest.items() if key!="sha256"}
        self.assertEqual(manifest["sha256"],hashlib.sha256(canonical(unsigned)).hexdigest())

    def test_source_manifest_helper_keeps_capture_and_legacy_claims_explicit(self):
        captured_batch=captured(capture())
        acquisition=captured_batch.coverage["acquisition"]
        manifest,version,kind=_safe_source_manifest("a"*64,"scroll_capture","scroll_capture",2,
            datetime(2026,10,20,7,25,tzinfo=timezone.utc),datetime(2026,10,20,7,30,tzinfo=timezone.utc),
            "synthetic_fixture",acquisition)
        self.assertEqual((version,kind),("p24-capture-manifest.1","scroll_capture"))
        self.assertEqual(manifest["sha256"],acquisition["capture_manifest"]["sha256"])
        legacy,legacy_version,legacy_kind=_safe_source_manifest("b"*64,"legacy_unassessed","documents",4,
            datetime(2026,10,20,7,25,tzinfo=timezone.utc),datetime(2026,10,20,7,30,tzinfo=timezone.utc),
            "intake_clock")
        self.assertEqual((legacy_version,legacy_kind),("p24-source-manifest.1","legacy_unassessed"))
        self.assertEqual(legacy["claims"]["query_traversal"],"not_assessed")
        self.assertEqual(legacy["claims"]["source_finality"],"not_established")

    def test_legacy_manifest_is_stable_across_database_timezones(self):
        start=datetime(2026,10,20,7,25,tzinfo=timezone.utc);end=datetime(2026,10,20,7,30,tzinfo=timezone.utc)
        tehran=timezone(timedelta(hours=3,minutes=30))
        utc_manifest,_,_=_safe_source_manifest('c'*64,'legacy_unassessed','documents',4,start,end,'intake_clock')
        local_manifest,_,_=_safe_source_manifest('c'*64,'legacy_unassessed','documents',4,
            start.astimezone(tehran),end.astimezone(tehran),'intake_clock')
        self.assertEqual(canonical(utc_manifest),canonical(local_manifest))

    def test_packaged_capture_fixture_has_recorded_requests_and_is_synthetic(self):
        b = read_batch(ROOT / "fixtures/acquisition/complete_scroll.synthetic.json")
        self.assertTrue(b.coverage["query_complete"])
        self.assertEqual(b.coverage["returned_records"], 2)
        manifest = json.loads((ROOT / "fixtures/MANIFEST.json").read_text())
        f = next(f for f in manifest["supplemental_fixtures"] if f["file"] == "acquisition/complete_scroll.synthetic.json")
        self.assertEqual(f["sha256"], hashlib.sha256(b.original).hexdigest())
        self.assertEqual(f["evidence_authority"], "synthetic_contract_example")

    def test_standalone_inspector_needs_no_database_and_prints_no_raw_rows(self):
        from tools.inspect_acquisition import main
        out = io.StringIO()
        with patch("sys.argv", ["inspect_acquisition", "--input", str(ROOT / "fixtures/acquisition/complete_scroll.synthetic.json")]), contextlib.redirect_stdout(out):
            result = main()
        public = json.loads(out.getvalue())
        self.assertEqual(result, 0)
        self.assertFalse(public["database_used"])
        self.assertFalse(public["network_used"])
        self.assertNotIn("SYNTHETIC_CURSOR", out.getvalue())
        self.assertTrue(public["assessment"]["acquisition"]["query_traversal_complete"])


class AcquisitionPostgresTests(unittest.TestCase):
    connection = None

    @classmethod
    def setUpClass(cls):
        if cls.connection is None:
            raise unittest.SkipTest("disposable PostgreSQL configuration required")
        initialize(cls.connection)

    def setUp(self):
        self.c = self.connection
        self.tmp = tempfile.TemporaryDirectory()
        namespace="capture_"+uuid.uuid4().hex
        self.access_token=issue_test_access_token(namespace)
        self.store = FoundationStore(self.c, TEST_KEYS, namespace, Path(self.tmp.name) / "vault",access_policy=test_access_policy(namespace))

    def tearDown(self):
        self.tmp.cleanup()

    def ingest(self, packet, *, source="captured-window", observed="2026-10-20T07:35:00Z"):
        b = packet if isinstance(packet, bytes) else captured(packet).original
        return self.store.ingest(decode_batch(b), source_key=source, interval_start=START, interval_end=END,
                                 observed_at=observed, receive_time_basis="synthetic_fixture")

    def project(self, *sources, known="2026-10-20T07:45:00Z"):
        return self.store.project([s["snapshot_id"] for s in sources], event_cutoff=END, knowledge_at=known, mode="historical_revised")

    def test_assessment_is_bound_to_original_bytes_and_append_only(self):
        p = capture()
        b = captured(p)
        s = self.ingest(p)
        args = (self.store.namespace_id, uuid.UUID(s["snapshot_id"]))
        row = self.c.execute("SELECT source_digest,query_traversal_complete,source_window_complete,assessment FROM p24_next.foundation_acquisition_assessment WHERE namespace_id=%s AND snapshot_id=%s", args).fetchone()
        self.assertEqual(row[:3], (hashlib.sha256(b.original).hexdigest(), True, False))
        self.assertEqual(row[3], b.coverage["acquisition"])
        self.assertEqual(self.c.execute("SELECT source_complete FROM p24_next.source_snapshot WHERE namespace_id=%s AND snapshot_id=%s", args).fetchone(), (False,))
        self.assertEqual(self.c.execute("SELECT count(*) FROM p24_next.source_head WHERE namespace_id=%s", args[:1]).fetchone(), (0,))
        for mutation in ("UPDATE p24_next.foundation_acquisition_assessment SET query_traversal_complete=false", "DELETE FROM p24_next.foundation_acquisition_assessment"):
            with self.assertRaises(psycopg.Error), self.c.transaction():
                self.c.execute(mutation+" WHERE namespace_id=%s AND snapshot_id=%s", args)
        again = self.ingest(p)
        self.assertTrue(again["reused"])
        self.assertEqual(again["snapshot_id"], s["snapshot_id"])

    def test_gzip_archive_and_selected_page_row_locations_round_trip(self):
        compressed = gzip.compress(captured(capture()).original, mtime=0)
        s = self.ingest(compressed)
        args = (self.store.namespace_id, uuid.UUID(s["snapshot_id"]))
        digest, fmt, rows, n = self.c.execute("SELECT content_sha256,format_key,row_count,byte_count FROM p24_next.raw_object WHERE namespace_id=%s AND snapshot_id=%s", args).fetchone()
        self.assertEqual((fmt, rows, n), ("json_gzip", 2, len(compressed)))
        self.assertEqual(self.store.vault.read(digest, s["snapshot_id"]), compressed)
        run = self.project(s)
        self.assertEqual(run["distinct_client_requests"], 2)
        evidence = self.store.request_evidence(run["run_id"], "capture-B",access_token=self.access_token)
        self.assertNotIn("SYNTHETIC_CURSOR", json.dumps(evidence))
        self.assertEqual(self.c.execute("SELECT row_ordinal FROM p24_next.foundation_row_membership WHERE namespace_id=%s AND snapshot_id=%s ORDER BY row_ordinal", args).fetchall(), [(0,), (1,)])

    def test_interval_mismatch_is_rejected_before_vault_or_database_mutation(self):
        b = captured(capture())
        with self.assertRaises(FoundationError) as caught:
            self.store.ingest(b, source_key="wrong", interval_start=START, interval_end="2026-10-20T07:35:00Z")
        self.assertEqual(caught.exception.code, "acquisition_interval_mismatch")
        self.assertFalse(self.store.vault.directory.exists())
        self.assertEqual(self.c.execute("SELECT count(*) FROM p24_next.source_snapshot WHERE namespace_id=%s", (self.store.namespace_id,)).fetchone(), (0,))

    def test_late_acquisition_replays_a_new_vector_without_rewriting_the_old_run(self):
        rows = [document(rid="late-A", oid="late-origin-A"), document(rid="late-B", oid="late-origin-B")]
        old = self.ingest(capture(rows[:1], terminal=False), observed="2026-10-20T07:32:00Z")
        original = self.project(old, known="2026-10-20T07:33:00Z")
        later = self.ingest(capture(rows), observed="2026-10-20T07:40:00Z")
        with self.assertRaises(FoundationError):
            self.project(old, later, known="2026-10-20T07:33:00Z")
        self.store.replace_source_snapshot(old["snapshot_id"], later["snapshot_id"], expected_prior_revision=1,
            reason_key="late_evidence_supersedes_partial", declared_by="synthetic_reviewer")
        revised = self.project(old, later)
        self.assertEqual((original["distinct_client_requests"], revised["distinct_client_requests"]), (1, 2))
        self.assertEqual(self.store.run_info(original["run_id"],access_token=self.access_token)["distinct_client_requests"], 1)
        self.assertEqual(self.store.session_activity(revised["run_id"], "SESSION_A",access_token=self.access_token)["total_requests"], 2)
        snapshots = self.c.execute("SELECT intake_revision,observed_at,source_complete FROM p24_next.source_snapshot WHERE namespace_id=%s ORDER BY intake_revision", (self.store.namespace_id,)).fetchall()
        self.assertEqual([r[0] for r in snapshots], [1, 2])
        self.assertTrue(all(not r[2] for r in snapshots))
        # Capture's finished_at claim precedes the later local receipt; it must not bypass knowledge bounds.
        self.assertEqual(snapshots[1][1].astimezone(timezone.utc).isoformat(), "2026-10-20T07:40:00+00:00")

    def test_selected_retry_only_is_projected_and_earlier_attempt_remains_archived(self):
        p = capture([document(rid="DISCARDED_ATTEMPT", oid="discarded-origin")])
        new = copy.deepcopy(attempt(capture()))
        new["number"] = 2
        p["slices"][0]["attempts"].append(new)
        s = self.ingest(p)
        self.assertEqual(self.project(s)["distinct_client_requests"], 2)
        self.assertEqual(self.c.execute("SELECT count(*) FROM p24_next.logical_request WHERE namespace_id=%s", (self.store.namespace_id,)).fetchone(), (2,))
        self.assertIn(b"DISCARDED_ATTEMPT", self.store.vault.read(hashlib.sha256(captured(p).original).hexdigest(), s["snapshot_id"]))

    def test_safe_capture_manifest_retains_each_attempt_page_and_only_cursor_hashes(self):
        p=capture([document(rid="selected",oid="selected-origin")])
        prior=copy.deepcopy(attempt(capture([document(rid="discarded",oid="discarded-origin")])))
        prior["number"]=1;prior["failure_kind"]="transport_timeout"
        chosen=copy.deepcopy(attempt(p));chosen["number"]=2
        p["acquisition"]["attempt_budget"]=2
        p["slices"][0]["attempts"]=[prior,chosen]
        manifest=assessment(p)["capture_manifest"]
        self.assertEqual(manifest["version"],"p24-capture-manifest.1")
        self.assertEqual([(x["attempt"],x["selected"],x["failure_kind"]) for x in manifest["attempts"]],
                         [(1,False,"transport_timeout"),(2,True,"none")])
        self.assertTrue(all(page["first_selected_row"] is None for page in manifest["attempts"][0]["pages"]))
        self.assertEqual(manifest["attempts"][1]["pages"][0]["first_selected_row"],0)
        retained=json.dumps(manifest)
        self.assertNotIn("SYNTHETIC_CURSOR",retained)
        self.assertIn("request_cursor_sha256",retained)
        self.assertFalse(manifest["claims"]["source_window_complete"])

    def test_receipt_ledger_and_capture_manifest_survive_store_recreation(self):
        p=capture();s=self.ingest(p)
        repeated=self.ingest(p,observed="2026-10-20T07:36:00Z")
        self.assertTrue(repeated["reused"])
        self.assertNotEqual(s["receipt_id"],repeated["receipt_id"])
        sid=uuid.UUID(s["snapshot_id"]);args=(self.store.namespace_id,sid)
        receipts=self.c.execute("SELECT disposition,received_at FROM p24_next.foundation_source_receipt WHERE namespace_id=%s AND snapshot_id=%s ORDER BY received_at",args).fetchall()
        first=self.c.execute("SELECT observed_at FROM p24_next.source_snapshot WHERE namespace_id=%s AND snapshot_id=%s",args).fetchone()[0]
        self.assertEqual(receipts[0],("accepted",first))
        self.assertEqual(receipts[1][0],"reused_identical")
        fresh=FoundationStore(self.c,TEST_KEYS,self.store.namespace,Path(self.tmp.name)/"vault",access_policy=test_access_policy(self.store.namespace))
        version,kind,digest,manifest=fresh.c.execute("SELECT manifest_version,source_kind,manifest_sha256,safe_manifest FROM p24_next.foundation_source_manifest WHERE namespace_id=%s AND snapshot_id=%s",args).fetchone()
        self.assertEqual((version,kind),("p24-capture-manifest.1","scroll_capture"))
        self.assertEqual(digest,s["manifest_sha256"])
        self.assertEqual(len(manifest["attempts"]),1)
        self.assertEqual(self.c.execute("SELECT count(*) FROM p24_next.foundation_source_receipt WHERE namespace_id=%s AND snapshot_id=%s",args).fetchone(),(2,))
        self.assertEqual(self.c.execute("SELECT source_window_complete,source_finality,producer_authority FROM p24_next.foundation_source_manifest WHERE namespace_id=%s AND snapshot_id=%s",args).fetchone(),(False,"not_established","unverified"))

    def test_repeated_origin_rows_are_retained_but_not_counted_as_two_requests(self):
        d = document()
        s = self.ingest(capture([d, copy.deepcopy(d)]))
        run = self.project(s)
        self.assertEqual((run["distinct_client_requests"], run["selected_request_events"]), (1, 1))
        self.assertEqual(self.c.execute("SELECT count(*) FROM p24_next.foundation_row_membership WHERE namespace_id=%s", (self.store.namespace_id,)).fetchone(), (2,))
        changed = copy.deepcopy(d)
        changed["_source"]["message"] = "POST https://fixture.invalid/config HTTP/1.1 (G00002 | Unknown)"
        conflict = self.ingest(capture([d, changed]), source="conflict-window")
        result = self.store.get_request(self.project(conflict)["run_id"], "request-A",access_token=self.access_token)
        self.assertEqual((result["final_outcome"], result["ambiguous_event_count"], result["distinct_client_request_count"]), ("unknown", 1, 0))

    def test_flattened_legacy_origin_deduplicates_against_original_search_hit(self):
        d = document()
        flat = dict(d["_source"], _source_id=d["_index"]+":"+d["_id"])
        legacy = self.ingest(dict(window_start=START, window_end=END, count=1, complete=True, logs=[flat]))
        search = self.ingest(capture([d]), source="captured-search")
        run = self.project(legacy, search)
        self.assertEqual((run["selected_request_events"], run["distinct_client_requests"]), (1, 1))
        self.assertFalse(legacy["coverage"]["acquisition"]["query_traversal_complete"])

    def test_database_rejects_missing_json_fields_or_a_different_source_digest(self):
        # Use a plain array snapshot so no legitimate assessment exists yet.
        b = decode_batch(json.dumps([document()]).encode())
        s = self.store.ingest(b, source_key="plain-array", interval_start=START, interval_end=END)
        a = assessment(capture())
        params = (self.store.namespace_id, uuid.UUID(s["snapshot_id"]), "p24-scroll-capture.1")
        sql = """INSERT INTO p24_next.foundation_acquisition_assessment
            (namespace_id,snapshot_id,assessment_version,source_digest,capture_claim_state,query_traversal_complete,source_window_complete,assessment)
            VALUES(%s,%s,%s,%s,'unverified_local_capture',true,false,%s)"""
        for digest, content in (("f"*64, a), (hashlib.sha256(b.original).hexdigest(), {})):
            with self.assertRaises(psycopg.Error), self.c.transaction():
                self.c.execute(sql, (*params, digest, jsonb(content)))
