"""Causal personal-reference checks through the existing Request reconstruction."""
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest.mock import Mock
from types import SimpleNamespace

from p24_foundation.behavior import publication_window, score, window
from p24_foundation.errors import FoundationError
from p24_foundation.reconstruction import reconstruct, select_events
from p24_foundation.time import microsecond_cutoff
from tests.helpers import TEST_KEYS, ROOT, document, normalized, fixture, test_access_policy, issue_test_access_token


class BehaviorTests(unittest.TestCase):
    def setUp(self):
        self.at = datetime(2026, 1, 2, tzinfo=timezone.utc)
        self.route_token = lambda value: TEST_KEYS.token("test-contract", "service", value)

    def build(self, offset, count=2, *, actor="SESSION_A", ip="198.51.100.2"):
        start = self.at + timedelta(minutes=5 * offset)
        end = start + timedelta(minutes=5)
        rows = [document(rid=f"{actor}:{offset}:{n}", oid=f"{actor}:{offset}:{n}", session=actor, ip=ip,
                         at=(start + timedelta(seconds=n)).isoformat()) for n in range(count)]
        summaries = reconstruct(select_events(normalized(rows), microsecond_cutoff(end.isoformat()).epoch_ns))
        return window(start.isoformat(), end.isoformat(), microsecond_cutoff(end.isoformat()).epoch_ns,
                      uuid.uuid5(uuid.NAMESPACE_URL, start.isoformat() + actor), summaries, route_token=self.route_token)

    def history(self, count=2):
        return [self.build(offset, count) for offset in range(-19, 0)]

    def test_personal_increase_emits_persian_evidence_and_keeps_priority_unrated(self):
        target = self.build(0, 20)
        result = score(target, self.history(), rank_cutoff="1/20")
        self.assertEqual(len(result["candidates"]), 1)
        finding = result["candidates"][0]
        self.assertEqual((finding["target_requests"], finding["reference_median"]), (20, 2))
        self.assertEqual((finding["rank_numerator"], finding["rank_denominator"]), (1, 20))
        self.assertIn("در این بازه", finding["explanation_fa"])
        self.assertEqual(result["priority"], "unrated")
        self.assertFalse(result["calibrated_error_rate"])
        self.assertEqual(len(finding["sample_request_keys"]), 3)

    def test_high_normal_volume_and_ip_change_do_not_trigger(self):
        for count in (2, 50):
            with self.subTest(count=count):
                result = score(self.build(0, count, ip="203.0.113.77"), self.history(count), rank_cutoff="1/20")
                self.assertEqual(result["candidates"], [])
                self.assertEqual(result["evaluated_units"], 1)

    def test_new_session_and_short_history_abstain_instead_of_borrowing_identity(self):
        for target, refs in [(self.build(0, 20, actor="NEW_LOGIN_SESSION"), self.history()),
                             (self.build(0, 20), self.history()[:18])]:
            result = score(target, refs, rank_cutoff="1/20")
            self.assertEqual(result["evaluated_units"], 0)
            self.assertEqual(result["unsupported_units"], 1)
            self.assertEqual(result["candidates"], [])

    def test_future_events_later_knowledge_and_overlapping_windows_are_rejected(self):
        target, refs = self.build(0), self.history()
        future = self.build(1)
        later_known = copy.deepcopy(refs[0]);later_known["knowledge_at_ns"] = target["knowledge_at_ns"] + 1
        for history in ([future], [later_known], [refs[0], refs[0]]):
            with self.assertRaises(FoundationError):
                score(target, history, rank_cutoff="1/20")
        different_scope = copy.deepcopy(refs[0]);different_scope["source_scope"] = "different_stream"
        with self.assertRaisesRegex(FoundationError, "behavior_source_scope_mismatch"):
            score(target, [different_scope], rank_cutoff="1/20")

    def test_target_reference_request_reuse_is_not_counted_as_prior_history(self):
        target, refs = self.build(0), self.history()
        key = next(iter(target["groups"]))
        refs[0]["groups"][key][0] = target["groups"][key][0]
        target["groups"].update(self.build(0, actor="OTHER_SESSION")["groups"])
        for offset, ref in zip(range(-19, 0), refs):
            ref["groups"].update(self.build(offset, actor="OTHER_SESSION")["groups"])
        result = score(target, refs, rank_cutoff="1/20")
        self.assertEqual(result["reason_counts"], {"overlapping_request_evidence": 1})
        self.assertEqual(result["evaluated_units"], 1)
        self.assertEqual(result["candidates"], [])

    def test_empty_reference_windows_are_not_invented_zero_activity(self):
        refs = self.history()
        refs[0]["groups"] = {}
        result = score(self.build(0, 20), refs, rank_cutoff="1/20")
        self.assertEqual(result["evaluated_units"], 0)
        self.assertEqual(result["evaluations"][0]["reference_active_windows"], 18)

    def test_reference_order_is_deterministic_and_target_changes_change_manifest(self):
        target, refs = self.build(0, 20), self.history()
        first = score(target, refs, rank_cutoff="1/20")
        self.assertEqual(first, score(target, list(reversed(refs)), rank_cutoff="1/20"))
        changed = score(self.build(0, 21), refs, rank_cutoff="1/20")
        self.assertNotEqual(first["evidence_manifest_sha256"], changed["evidence_manifest_sha256"])

    def test_invalid_policy_and_reference_bounds_fail_explicitly(self):
        for value in ("0", "1", "1/0", "NaN", "1e-999999999", True):
            with self.assertRaisesRegex(FoundationError, "invalid_behavior_rank_cutoff"):
                score(self.build(0), self.history()[:1], rank_cutoff=value)
        with self.assertRaisesRegex(FoundationError, "behavior_reference_limit"):
            score(self.build(0), [], rank_cutoff="1/20")

    def test_duplicate_logical_requests_are_rejected(self):
        start, end = self.at.isoformat(), (self.at + timedelta(minutes=5)).isoformat()
        summaries = reconstruct(select_events(normalized([document(at=start)]), microsecond_cutoff(end).epoch_ns))
        with self.assertRaisesRegex(FoundationError, "duplicate_behavior_request"):
            window(start, end, microsecond_cutoff(end).epoch_ns, uuid.uuid4(), summaries * 2, route_token=self.route_token)

    def test_reports_exclude_raw_session_ip_and_log_payload(self):
        result = score(self.build(0, 20, actor="PRIVATE_SESSION_SENTINEL"), self.history(), rank_cutoff="1/20")
        encoded = json.dumps(result)
        for value in ("PRIVATE_SESSION_SENTINEL", "198.51.100.2", "fixture.invalid", "SESSION_A"):
            self.assertNotIn(value, encoded)

    def test_publication_adapter_requires_committed_exact_cutoff_and_bounds_rows(self):
        connection = Mock()
        connection.execute.return_value.fetchone.return_value = None
        with self.assertRaisesRegex(FoundationError, "behavior_publication_not_committed"):
            publication_window(connection, uuid.uuid4(), uuid.uuid4(), self.at.isoformat(),
                (self.at + timedelta(minutes=5)).isoformat(), route_token=self.route_token)

    def test_publication_adapter_requires_one_comparable_unfiltered_capture(self):
        start, end = self.at.isoformat(), (self.at + timedelta(minutes=5)).isoformat()
        cutoff = microsecond_cutoff(end).epoch_ns
        manifest = dict(event_cutoff_ns=str(cutoff), knowledge_at_ns=str(cutoff), effective_sources=[str(uuid.uuid4())])
        acquisition = dict(query_traversal_complete=True, window_scope_eligible=True, expected_slices=1,
            declared_window_start=start, declared_window_end=end, index_pattern="fixture-*", contract_version="p24-scroll-capture.1")
        good_scope = (uuid.uuid4(), "collector:main:1:2", {"acquisition": acquisition})
        for scopes, expected in [([good_scope], True), ([good_scope, good_scope], False),
            ([(good_scope[0], good_scope[1], {"acquisition": dict(acquisition, window_scope_eligible=False)})], False)]:
            connection = Mock()
            connection.execute.side_effect = [SimpleNamespace(fetchone=lambda: (manifest,)),
                SimpleNamespace(fetchall=lambda: scopes), SimpleNamespace(fetchall=lambda: [])]
            if expected:
                result = publication_window(connection, uuid.uuid4(), uuid.uuid4(), start, end, route_token=self.route_token)
                self.assertEqual(result["groups"], {})
            else:
                with self.assertRaisesRegex(FoundationError, "behavior_comparable_capture_required"):
                    publication_window(connection, uuid.uuid4(), uuid.uuid4(), start, end, route_token=self.route_token)
        connection = Mock()
        connection.execute.return_value.fetchone.return_value = ({"event_cutoff_ns": "0"},)
        with self.assertRaisesRegex(FoundationError, "behavior_publication_cutoff_mismatch"):
            publication_window(connection, uuid.uuid4(), uuid.uuid4(), self.at.isoformat(),
                (self.at + timedelta(minutes=5)).isoformat(), route_token=self.route_token)

    def test_real_session_fixture_counts_logical_requests_and_abstains_without_history(self):
        events = normalized(fixture("session_activity.sanitized.json").records)
        end_ns = max(int(event["payload"]["descriptor"]["source_time"]["epoch_ns"]) for event in events) + 1
        summaries = reconstruct(select_events(events, end_ns))
        self.assertEqual(sum(s["distinct_client_request_count"] for s in summaries), 10)
        self.assertEqual(sum(s["selected_event_count"] for s in summaries), 33)
        self.assertTrue(all(s["source_coverage"] == "observed_only" for s in summaries))
        times = [int(s["activity_time_ns"]) for s in summaries if s["client_completion_state"] == "observed"]
        first = datetime.fromtimestamp(min(times) / 1_000_000_000, timezone.utc)
        first = first.replace(minute=(first.minute // 5) * 5, second=0, microsecond=0)
        evaluated = []
        while microsecond_cutoff(first.isoformat()).epoch_ns <= max(times):
            last = first + timedelta(minutes=5)
            target = window(first.isoformat(), last.isoformat(), microsecond_cutoff(last.isoformat()).epoch_ns,
                            uuid.uuid4(), summaries, route_token=self.route_token)
            result = score(target, self.history()[:1], rank_cutoff="1/20")
            self.assertEqual(result["candidates"], [])
            evaluated.append(sum(len(values) for values in target["groups"].values()))
            first = last
        self.assertEqual(sum(evaluated), 10)

    def test_demo_cli_produces_one_personal_candidate_and_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            command = [sys.executable, str(ROOT / "tools/detect_behavior.py"), "--demo", "--output", str(output)]
            process = subprocess.run(command, capture_output=True, text=True, timeout=15)
            self.assertEqual(process.returncode, 0, process.stdout)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(len(report["candidates"]), 1)
            self.assertEqual(report["input_kind"], "synthetic_demo")
            original = output.read_bytes()
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 2)
            self.assertEqual(original, output.read_bytes())

    def test_persian_html_report_escapes_text_and_labels_synthetic_data(self):
        from tools.detect_behavior import demo_report, write_report
        report = demo_report()
        report["candidates"][0]["explanation_fa"] = "<script>alert('PRIVATE')</script>"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.html"
            write_report(path, report, format="html")
            html = path.read_text(encoding="utf-8")
            self.assertIn('lang="fa" dir="rtl"', html)
            self.assertIn("نمونهٔ ساختگی", html)
            self.assertNotIn("<script>", html)
            self.assertIn("&lt;script&gt;", html)


class BehaviorPostgresTests(unittest.TestCase):
    connection = None

    @classmethod
    def setUpClass(cls):
        if cls.connection is None:
            raise unittest.SkipTest("disposable PostgreSQL configuration required")
        from p24_foundation.store import initialize
        initialize(cls.connection)

    def test_native_twenty_committed_capture_windows_to_personal_persian_candidate(self):
        from p24_foundation.collector_pipeline import publish_plan, load_plan
        from p24_foundation.store import FoundationStore
        from p24_foundation.privacy import canonical
        from tests.test_collector_pipeline import packet_for
        import hashlib
        namespace = "behavior_" + uuid.uuid4().hex
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = FoundationStore(self.connection, TEST_KEYS, namespace, root / "vault",access_policy=test_access_policy(namespace))
            references = []
            for generation, offset in enumerate(range(-19, 1)):
                start = datetime(2026, 1, 2, tzinfo=timezone.utc) + timedelta(minutes=5 * offset)
                end = start + timedelta(minutes=5)
                count = 20 if offset == 0 else 2
                rows = [document(rid=f"{offset}:{n}", oid=f"{offset}:{n}",
                    at=(start + timedelta(seconds=n)).isoformat()) for n in range(count)]
                data = canonical(packet_for(rows, start.isoformat(), end.isoformat()))
                capture_path = root / "capture.json";capture_path.write_bytes(data)
                plan = dict(version="p24-collector-import.1", stream="behavior", index_pattern="fixture-*",
                    expected_generation=generation, event_cutoff=end.isoformat(),
                    captures=[dict(path=capture_path.name, sha256=hashlib.sha256(data).hexdigest())])
                plan_path = root / "plan.json";plan_path.write_bytes(canonical(plan))
                published = publish_plan(store, load_plan(plan_path))
                with self.connection.transaction():
                    self.connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                    item = publication_window(self.connection, store.namespace_id, published["publication_id"],
                        start.isoformat(), end.isoformat(), route_token=lambda route: TEST_KEYS.token(namespace, "service", route))
                if offset == 0:
                    target = item
                else:
                    references.append(item)
            report = score(target, references, rank_cutoff="1/20")
            self.assertEqual(len(report["candidates"]), 1)
            self.assertEqual(report["candidates"][0]["target_requests"], 20)
            self.assertIn("در این بازه", report["candidates"][0]["explanation_fa"])
            from p24_foundation.behavior_store import persist_candidates
            from p24_foundation.incidents import IncidentRegistry
            from p24_foundation.store import floor_ns
            from unittest.mock import patch
            target_spec=dict(publication_id=published['publication_id'],start=start.isoformat(),end=end.isoformat())
            reference_specs=[dict(publication_id=item['publication_id'],start=floor_ns(item['start_ns']).isoformat(),
                end=floor_ns(item['end_ns']).isoformat()) for item in references]
            def persist(policy='1/20'):
                return persist_candidates(store,target_spec=target_spec,reference_specs=reference_specs,
                    rank_cutoff=policy,expected_generation=published['generation'])
            saved=persist();incident=saved['persisted_incidents'][0]
            registry=IncidentRegistry(store);token=issue_test_access_token(namespace)
            initial=registry.read(published['publication_id'],incident['incident_id'],access_token=token)
            self.assertEqual(initial['result']['distinct_supported_requests'],20)
            self.assertEqual(initial['result']['priority'],'unrated')
            self.assertTrue(persist()['persisted_incidents'][0]['reused'])
            # A new late request changes the whole target group while the
            # earlier RequestID heads may remain reusable in the publication.
            rows.append(document(rid='late-extra',oid='late-extra',at=(start+timedelta(seconds=30)).isoformat()))
            data=canonical(packet_for(rows,start.isoformat(),end.isoformat()))
            capture_path.write_bytes(data)
            source=published['imported'][0]
            plan.update(expected_generation=20,captures=[dict(path=capture_path.name,
                sha256=hashlib.sha256(data).hexdigest(),replaces={key:source[key] for key in ('snapshot_id','intake_revision')})])
            plan_path.write_bytes(canonical(plan));published=publish_plan(store,load_plan(plan_path))
            current=registry.refresh(published['publication_id'],scope_kind='session',subject_key=initial['result']['subject_key'],
                pattern_key=initial['result']['pattern_key'],expected_generation=incident['generation'])
            changed=registry.read(published['publication_id'],incident['incident_id'],access_token=token)
            self.assertEqual(changed['result']['distinct_supported_requests'],0)
            self.assertTrue({'behavior_target_group_changed','evidence_revision_not_current_in_publication'} &
                            {row['reason'] for row in changed['result']['excluded_findings']})
            target_spec['publication_id']=published['publication_id']
            updated=persist();updated_incident=updated['persisted_incidents'][0]
            current=registry.read(published['publication_id'],incident['incident_id'],access_token=token)
            self.assertEqual(current['result']['distinct_supported_requests'],21)
            historical=registry.read(initial['result']['publication_id'],incident['incident_id'],revision_id=initial['revision_id'],access_token=token)
            self.assertEqual(historical['result']['distinct_supported_requests'],20)
            # A new abstaining assessment removes prior active candidates;
            # an old report replay cannot silently select the old evaluation.
            strict=persist('1/100')
            self.assertEqual(strict['unsupported_units'],1)
            current=registry.read(published['publication_id'],incident['incident_id'],access_token=token)
            self.assertEqual(current['result']['distinct_supported_requests'],0)
            with self.assertRaisesRegex(FoundationError,'behavior_historical_reselection_requires_review'):
                persist()
            before=self.connection.execute('SELECT count(*) FROM p24_next.finding WHERE namespace_id=%s',(store.namespace_id,)).fetchone()[0]
            with patch.object(IncidentRegistry,'refresh',side_effect=FoundationError('injected_incident_failure')):
                with self.assertRaisesRegex(FoundationError,'injected_incident_failure'):
                    persist('1/19')
            after=self.connection.execute('SELECT count(*) FROM p24_next.finding WHERE namespace_id=%s',(store.namespace_id,)).fetchone()[0]
            self.assertEqual(before,after)
