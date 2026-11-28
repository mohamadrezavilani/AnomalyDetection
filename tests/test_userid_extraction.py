"""WP01 synthetic adversarial and integration tests; no production source access."""
from copy import deepcopy
from dataclasses import replace
import gzip
import itertools
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from compact_behavior.extract import instant
from contracts.userid.validate import ContractViolation, validate_record
from userid_product import identity, source
from userid_product.extraction import (
    Extractor, Limits, LimitExceeded, behavior_hash, extract_window,
    fragment, materialize, merge, state_hash, verify_adapter,
)

SCOPE = "pishkhan24:test:core"
RID = "11111111111141118111111111111111"
AT = "2026-11-28T09:50:10.123456789Z"
SEEN = str(instant("2026-11-28T10:20:00Z"))
ABSENT = object()


def hit(uid="9007199254740993", *, rid=RID, doc="one", path="Services.v1/WaterBills", message=None, at=AT):
    data = {"RequestID": rid, "@timestamp": at, "CallPath": path + " Line:32", "ExecutionTime": "12.5",
            "message": message if message is not None else "POST https://example.test/api HTTP/1.1 (G00000 | Successful)"}
    if uid is not ABSENT:
        data["UserID"] = uid
    return {"_index": "test-index", "_id": doc, "_source": data}


def record(row, *, seen=SEEN, scope=SCOPE):
    return source.normalize(row, scope, seen)


def extracted(*rows):
    e = Extractor()
    for row in rows:
        e.add(record(row))
    return next(iter(e.states.values()))


class IdentityTests(unittest.TestCase):
    def test_int64_exact_and_docvalue_singleton(self):
        for uid in (1, 9007199254740993, 9223372036854775807, "9223372036854775807"):
            with self.subTest(value_type=type(uid).__name__):
                row = hit(uid)
                row["fields"] = {"UserID": [str(uid)]}
                r = record(row)
                i = identity.from_record(r)
                self.assertEqual(i["status"], "VALID")
                self.assertEqual(i["user_id"], str(uid))
                validate_record(identity.project(SCOPE, RID, i))

    def test_invalid_values_never_coerce(self):
        for uid in (True, False, 1.0, 1.5, "1e3", "۱۲۳", "01", " 1", "+1", "N/A", "", "****", 0, -1, 2**63, {}, ["1"]):
            with self.subTest(value_type=type(uid).__name__):
                i = identity.from_record(record(hit(uid)))
                self.assertEqual(i["status"], "INVALID")
                self.assertIsNone(i["actor_key"])
                validate_record(identity.project(SCOPE, RID, i))

    def test_missing_null_and_valid_precedence(self):
        for uid in (ABSENT, None):
            state = extracted(hit(uid, doc="missing"), hit("12", doc="valid", message="Input:{}"))
            self.assertEqual(state["identity"]["status"], "VALID")
            self.assertTrue(state["identity"]["missing_observed"])

    def test_valid_plus_invalid_is_invalid(self):
        state = extracted(hit("12"), hit("012", doc="invalid"))
        self.assertEqual(state["identity"]["status"], "INVALID")
        self.assertEqual(state["identity"]["candidate_user_ids"], ["12"])
        validate_record(materialize(state))

    def test_fields_conflict_and_multivalue_preserve_candidates(self):
        for values in (["13"], ["12", "13"]):
            row = hit("12")
            row["fields"] = {"UserID": values}
            i = identity.from_record(record(row))
            self.assertEqual(i["status"], "CONFLICT")
            self.assertEqual(i["candidate_user_ids"], ["12", "13"])
            validate_record(identity.project(SCOPE, RID, i))

    def test_no_uid_from_provider_payload_ip_or_ua(self):
        row = hit(ABSENT, message='Input:{"UserId":"12","Session":"abcd****","IP":"192.0.2.1"}')
        row["_source"].update(IP="192.0.2.1", UserAgent="test-browser")
        b = materialize(extracted(row))
        self.assertEqual(b["identity"]["status"], "MISSING")
        self.assertEqual(b["identity"]["kind"], "UNDETERMINED")
        self.assertIsNone(b["identity"]["actor_key"])

    def test_kind_not_inferred_from_successful_login(self):
        b = materialize(extracted(hit("12", path="Core.v1/Login")))
        self.assertEqual(b["identity"]["kind"], "UNDETERMINED")
        self.assertFalse(b["features"]["account_eligible"])

    def test_request_guid_normalization_and_strict_conflict(self):
        row = hit(rid="AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA")
        self.assertEqual(fragment(record(row))["request_id"], "a"*12 + "4aaa8aaa" + "a"*12)
        for rid in ("req-1", "", None, " 11111111111141118111111111111111", "11111111--1111-4111-8111-111111111111"):
            e = Extractor()
            e.add(record(hit(rid=rid)))
            self.assertFalse(e.states)
            self.assertEqual(sum(e.quarantine.values()), 1)
        row = hit()
        row["fields"] = {"RequestID": ["2" * 32]}
        e = Extractor()
        e.add(record(row))
        self.assertEqual(e.quarantine, {"REQUEST_ID_CONFLICT": 1})

    def test_provenance_bound_preserves_earliest_per_candidate(self):
        e = Extractor()
        for n in range(40):
            row = hit(str(1 + n % 4), doc=str(n), at=f"2026-11-28T09:50:{10+n:02}Z", message="Input:{}")
            e.add(record(row))
        i = e.states[RID]["identity"]
        self.assertEqual(len(i["evidence"]), 16)
        self.assertEqual(i["candidate_user_ids"], ["1", "2", "3", "4"])
        validate_record(identity.project(SCOPE, RID, i))
        before = deepcopy(e.states)
        with self.assertRaisesRegex(identity.BoundaryError, "CANDIDATE_LIMIT"):
            e.add(record(hit("5", doc="overflow")))
        self.assertEqual(before, e.states)

    def test_scope_namespaces_actor_request_behavior(self):
        a = materialize(fragment(record(hit())))
        b = materialize(fragment(record(hit(), scope="another:test:core")))
        self.assertNotEqual(a["identity"]["actor_key"], b["identity"]["actor_key"])
        self.assertNotEqual(a["behavior_key"], b["behavior_key"])
        with self.assertRaises(identity.BoundaryError):
            merge(fragment(record(hit())), fragment(record(hit(), scope="another:test:core")))


class BehaviorTests(unittest.TestCase):
    def test_public_complete_features_independent_of_uid(self):
        for uid in (ABSENT, "12", "012"):
            b = materialize(extracted(hit(uid), hit(uid, doc="input", message='Input:{"BillId":"fixture","Amount":10}')))
            validate_record(b)
            self.assertTrue(b["features"]["service_eligible"])
            self.assertTrue(b["features"]["result_eligible"])
            self.assertTrue(b["features"]["input"]["eligibility"]["targets"])
            self.assertEqual(b["features"]["actor_eligible"], uid == "12")
            self.assertEqual(b["result"]["business_state"], "UNKNOWN")
            self.assertEqual(b["result"]["financial_state"], "OUT_OF_SCOPE")
            self.assertNotIn("session_id", b)

    def test_late_identity_revises_same_behavior_and_enables_retraction(self):
        old = fragment(record(hit(ABSENT)))
        late = fragment(record(hit("12", doc="late", message="Input:{}"), seen=str(int(SEEN)+1)))
        a = materialize(old)
        b = materialize(merge(old, late), revision=2)
        self.assertEqual(a["behavior_key"], b["behavior_key"])
        self.assertNotEqual(behavior_hash(a), behavior_hash(b))
        self.assertFalse(a["features"]["actor_eligible"])
        self.assertTrue(b["features"]["actor_eligible"])
        c = materialize(merge(merge(old, late), fragment(record(hit("13", doc="conflict", message="Input:{}")))))
        self.assertEqual(c["identity"]["status"], "CONFLICT")
        self.assertFalse(c["features"]["actor_eligible"])
        self.assertTrue(c["features"]["service_eligible"])
        validate_record(c)

    def test_future_identity_does_not_enable_past_actor(self):
        b = materialize(extracted(hit(ABSENT), hit("12", doc="future", at="2026-11-28T09:50:20Z", message="Input:{}")))
        self.assertFalse(b["features"]["actor_eligible"])
        self.assertIn("IDENTITY_NOT_KNOWN_AT_OPERATION", b["quality"])
        validate_record(b)

    def test_guest_to_account_keeps_request_and_account_uncertainty(self):
        e = Extractor()
        e.add(record(hit("11", rid="a"*32, path="Core.v1/Login", doc="guest")))
        e.add(record(hit("22", rid="b"*32, doc="account")))
        self.assertEqual(len(e.states), 2)
        self.assertEqual({s["identity"]["user_id"] for s in e.states.values()}, {"11", "22"})
        self.assertTrue(all(materialize(s)["identity"]["kind"] == "UNDETERMINED" for s in e.states.values()))

    def test_same_user_across_requests_retains_one_actor(self):
        e = Extractor()
        e.add(record(hit("12", rid="a"*32, doc="first")))
        e.add(record(hit("12", rid="b"*32, doc="second")))
        self.assertEqual(len(e.states), 2)
        self.assertEqual(len({s["identity"]["actor_key"] for s in e.states.values()}), 1)

    def test_pending_conflicts_and_auxiliary_roles(self):
        b = materialize(extracted(hit(path="ClientAyanCoInquiry.WaterBillInquiry", message="Output:{}")))
        self.assertEqual(b["state"], "PENDING")
        validate_record(b)
        b = materialize(extracted(hit(), hit(doc="other", path="Services.v1/GasBills")))
        self.assertEqual(b["state"], "CONFLICT")
        self.assertFalse(b["features"]["service_eligible"])
        validate_record(b)
        b = materialize(extracted(hit(path="Core.v1/GetUserData")))
        self.assertIn(b["operation_role"], ("support", "system"))
        self.assertFalse(b["features"]["actor_eligible"])
        self.assertEqual(b["features"]["input"]["status"], "OUT_OF_SCOPE")
        validate_record(b)

    def test_terminal_attempts_exact_pairs_not_business_executions(self):
        for kind, code, symbol in (("ACCESS_DENIED", "G00010", "UserAccessObjectsDoesNotContainAccessObject"),
                                   ("INVALID_SESSION", "G00002", "SessionIsNotValid"),
                                   ("VALIDATION_REJECTED", "G00003", "NullCheckError"),
                                   ("RATE_LIMIT", "GR0004", "RequestRateLimiting")):
            row = hit(path="Services.v1/InvoiceRegister", message=f"POST https://example.test/api HTTP/1.1 ({code} | {symbol})")
            action = hit(doc="action", path="DBPath.pishkhan24.application.ud_prc_userSessionHasAccess",
                         message="(SQL Parameters: @action=v1/LandLinePhoneBills)")
            b = materialize(extracted(row, action))
            self.assertEqual(b["observations"]["attempt"]["kind"], kind)
            self.assertEqual(b["observations"]["attempt"]["requested_service"], "Services.v1/LandLinePhoneBills")
            self.assertIsNone(b["service_key"])
            self.assertFalse(b["features"]["actor_eligible"])
            self.assertFalse(b["features"]["service_eligible"])
            validate_record(b)
            bad = deepcopy(b)
            bad["features"]["service_eligible"] = True
            with self.assertRaises(ContractViolation):
                validate_record(bad)
        b = materialize(extracted(hit(message="POST https://example.test/api HTTP/1.1 (G00010 | DifferentError)")))
        self.assertIsNone(b["observations"]["attempt"])

    def test_confirmed_dispatch_never_relabelled_as_denied_intent(self):
        b = materialize(extracted(
            hit(path="Services.v1/InvoiceRegister", message="POST https://example.test/api HTTP/1.1 (G00010 | UserAccessObjectsDoesNotContainAccessObject)"),
            hit(doc="action", path="DBPath.pishkhan24.application.ud_prc_userSessionHasAccess", message="(SQL Parameters: @action=v1/LandLinePhoneBills)"),
            hit(doc="dispatch", path="DBPath.pishkhan24.application.ud_prc_invoiceRequest", message="(SQL Parameters: @serviceID=7001)")))
        self.assertIsNone(b["observations"]["attempt"])
        self.assertEqual(b["state"], "CONFLICT")
        self.assertFalse(b["features"]["actor_eligible"])
        self.assertFalse(b["features"]["service_eligible"])
        validate_record(b)

    def test_context_placeholders_provenance_and_session_scrub(self):
        row = hit()
        row["_source"].update(IP="N/A", UserAgent="N/A")
        b = materialize(extracted(row))
        self.assertNotIn("ip", b["observations"]["request_context"]["values"])
        row["_source"].update(IP="::ffff:192.0.2.1", UserAgent="browser-fixture")
        state = extracted(row, hit(doc="in", message='Input:{"Session":"partial****","Token":"secret","BillId":"fixture"}'))
        serialized = json.dumps(state)
        self.assertNotIn("partial****", serialized)
        self.assertNotIn('"secret"', serialized)
        context = materialize(state)["observations"]["request_context"]
        self.assertEqual(context["values"]["ip"][0]["value"], "192.0.2.1")
        self.assertEqual(context["values"]["ip"][0]["sources"], ["log.IP"])
        self.assertIsInstance(context["values"]["ip"][0]["first_ns"], str)
        validate_record(materialize(state))

    def test_replay_hashes_and_order_independence(self):
        rows = [hit(ABSENT), hit("12", doc="in", message='Input:{"BillId":"fixture"}'),
                hit("12", doc="out", message='Output:{"Amount":10}')]
        hashes = set()
        for order in itertools.permutations(rows):
            state = extracted(*order)
            hashes.add((state_hash(state), behavior_hash(materialize(state))))
            replay = state
            for row in rows:
                replay = merge(replay, fragment(record(row, seen=str(int(SEEN)+1000))))
            self.assertEqual(state_hash(state), state_hash(replay))
            self.assertEqual(state["known_at_ns"], replay["known_at_ns"])
            self.assertEqual(behavior_hash(materialize(state)), behavior_hash(materialize(replay)))
        self.assertEqual(len(hashes), 1)

    def test_budget_failure_is_atomic(self):
        for limits in (replace(Limits(), requests=1), replace(Limits(), total_state_bytes=4000), replace(Limits(), state_bytes=4000)):
            e = Extractor(limits)
            e.add(record(hit()))
            before = deepcopy((e.states, e.sizes, e.state_bytes, e.records, e.quarantine))
            row = hit(doc="large", rid="a"*32, message='Input:{"data":"' + "x"*8000 + '"}')
            with self.assertRaises(LimitExceeded):
                e.add(record(row))
            self.assertEqual(before, (e.states, e.sizes, e.state_bytes, e.records, e.quarantine))

    def test_large_partial_components_keep_independent_eligibility(self):
        value = [{"BillID": str(n) + "x"*512, "Amount": n} for n in range(512)]
        b = materialize(extracted(hit(), hit(doc="large", message="Input:" + json.dumps(value))))
        component = b["features"]["input"]
        self.assertEqual(component["status"], "PARTIAL")
        self.assertFalse(component["eligibility"]["targets"])
        self.assertTrue(component["eligibility"]["numeric"])
        self.assertIn("FEATURE_STORAGE_LIMIT", component["limitations"])
        self.assertTrue(b["features"]["actor_eligible"])
        validate_record(b)

    def test_malformed_selected_input_is_invalid_and_not_eligible(self):
        b = materialize(extracted(hit(), hit(doc="malformed", message='Input:{"BillID":"one","BillID":"two"}')))
        self.assertEqual(b["features"]["input"]["status"], "INVALID")
        self.assertFalse(any(b["features"]["input"]["eligibility"].values()))
        self.assertTrue(b["features"]["service_eligible"])
        validate_record(b)

    def test_business_sql_binding_beats_unreviewed_provider(self):
        b = materialize(extracted(
            hit(path="Services.v1/InvoiceRegister"),
            hit(doc="action", path="DBPath.pishkhan24.application.ud_prc_userSessionHasAccess", message="(SQL Parameters: @action=v1/TopUpProductReserve)"),
            hit(doc="dispatch", path="DBPath.pishkhan24.application.ud_prc_invoiceRequest", message="(SQL Parameters: @serviceID=1202)"),
            hit(doc="sql", path="DBPath.pishkhan24.application.ud_prc_invoiceRegister", message='(SQL Parameters: @queryParameters={"LineNumber":"fixture","Amount":100})'),
            hit(doc="provider", path="ClientAyanCoTopUp.TopUpChargeCustom", message='Output:{"Amount":100}')))
        self.assertTrue(b["features"]["service_eligible"])
        self.assertEqual(b["features"]["input"]["basis"], "BUSINESS_SQL")
        self.assertTrue(b["features"]["input"]["eligibility"]["targets"])
        self.assertEqual(b["features"]["output"]["basis"], "UNCONFIRMED")
        self.assertFalse(any(b["features"]["output"]["eligibility"].values()))
        validate_record(b)

    def test_internal_proxy_support_does_not_split_public_execution(self):
        b = materialize(extracted(hit(), hit(doc="proxy", path="Proxy.CarTaxInquiry")))
        self.assertEqual(b["api"], "Services.v1/WaterBills")
        self.assertEqual(b["state"], "COMPLETE")
        self.assertTrue(b["features"]["actor_eligible"])
        validate_record(b)

    def test_unknown_contract_and_state_version_rejected(self):
        state = extracted(hit())
        b = materialize(state)
        b["contract_version"] = "p24-userid-1"
        with self.assertRaises(ContractViolation):
            validate_record(b)
        state["version"] = "unreviewed-version"
        with self.assertRaises(identity.BoundaryError):
            merge(state, extracted(hit()))
        r = record(hit())
        r["contract_version"] = "p24-userid-1"
        with self.assertRaisesRegex(identity.BoundaryError, "VERSION_MISMATCH"):
            fragment(r)


class SourceTests(unittest.TestCase):
    def export(self, directory, rows, **metadata):
        path = Path(directory) / "fixture.json.gz"
        with gzip.open(path, "wt", encoding="utf-8") as f:
            json.dump(dict(logs=rows, count=len(rows), complete=True,
                           window_start="2026-11-28T09:50:00Z", window_end="2026-11-28T09:55:00Z", **metadata), f)
        return path

    def test_complete_export_and_nanosecond_precision(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.export(directory, [hit()])
            window, e = extract_window(source.WindowFile(path), SCOPE, SEEN)
            validate_record(window)
            self.assertEqual(window["source_records"], 1)
            b = materialize(e.states[RID])
            self.assertTrue(b["occurred_at_ns"].endswith("123456789"))
            validate_record(b)

    def test_certificate_unavailable_until_exhaustion(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.export(directory, [hit()])
            reader = source.WindowFile(path)
            iterator = source.records(reader, SCOPE, SEEN)
            next(iterator)
            with self.assertRaisesRegex(identity.BoundaryError, "NOT_CERTIFIED"):
                source.window(reader, SCOPE)
            self.assertEqual(list(iterator), [])
            validate_record(source.window(reader, SCOPE))

    def test_late_eof_failure_never_returns_window(self):
        with tempfile.TemporaryDirectory() as directory:
            for text in ('{"logs":[' + json.dumps(hit()) + '],"complete":false,"count":1}',
                         '{"logs":[' + json.dumps(hit()) + '],"complete":true,"count":2}',
                         '{"logs":[' + json.dumps(hit()) + ']'):
                path = Path(directory) / "partial.json"
                path.write_text(text, encoding="utf-8")
                with self.assertRaises(ValueError):
                    extract_window(source.WindowFile(path), SCOPE, SEEN)

    def test_duplicate_origins_outside_window_and_bad_time_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            for rows in ([hit(), hit()], [hit(at="2026-11-28T09:55:00Z")], [hit(at="invalid")]):
                path = self.export(directory, rows)
                with self.assertRaises(identity.BoundaryError):
                    extract_window(source.WindowFile(path), SCOPE, SEEN)

    def test_duplicate_json_key_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"logs":[{"_source":{"UserID":"12","UserID":"13"}}]}', encoding="utf-8")
            with self.assertRaisesRegex(identity.BoundaryError, "DUPLICATE"):
                list(source.WindowFile(path).records())

    def test_legacy_profile_rejected_not_reinterpreted(self):
        row = hit()
        row["_source"]["Session"] = "old-session"
        with self.assertRaisesRegex(identity.BoundaryError, "LEGACY_SESSION"):
            record(row)

    def test_flat_metadata_and_missing_origin(self):
        row = hit()
        flat = dict(row["_source"], _id="one", _index="index")
        b = materialize(fragment(record(flat)))
        self.assertEqual(b["identity"]["user_id"], "9007199254740993")
        validate_record(b)
        flat.pop("_id")
        with self.assertRaises(identity.BoundaryError):
            record(flat)

    def test_contract_source_example_is_consumable(self):
        from contracts.userid.validate import ROOT
        example = json.loads((ROOT / "examples.json").read_text(encoding="utf-8"))["SourceRecord"]
        state = fragment(example)
        self.assertEqual(state["identity"]["user_id"], "9007199254740993")
        self.assertEqual(materialize(state)["state"], "COMPLETE")
        self.assertEqual(materialize(state)["occurred_at_ns"], example["event_time_ns"])
        validate_record(materialize(state))

    def test_offline_replay_reports_aggregates_and_cross_window_merge(self):
        from userid_product.replay import replay
        with tempfile.TemporaryDirectory() as directory:
            first = self.export(directory, [hit(ABSENT, at="2026-11-28T09:54:59Z")])
            second = Path(directory) / "second.json"
            second.write_text(json.dumps(dict(logs=[hit("12", doc="late", at="2026-11-28T09:55:01Z", message="Input:{}")],
                count=1, complete=True, window_start="2026-11-28T09:55:00Z", window_end="2026-11-28T10:00:00Z")), encoding="utf-8")
            report = replay([first, second], SCOPE, seen_at_ns=SEEN)
            self.assertEqual(report["logical_requests"], 1)
            self.assertEqual(report["repeated_request_window_memberships"], 1)
            self.assertEqual(report["counts"]["identity_status"], {"VALID":1})
            self.assertNotIn(RID, json.dumps(report))

    def test_elastic_projection_replaces_session_on_search_only(self):
        reader = source.ElasticWindow({"host":"https://example.test", "index_pattern":"logs-*"}, 0, source.FIVE)
        with patch("compact_behavior.source.ElasticWindow.request", return_value={}) as transport:
            reader.request("/_search", {"_source":["Session"], "query":{}})
            body = transport.call_args.args[1]
            self.assertIn("UserID", body["_source"])
            self.assertNotIn("Session", body["_source"])
            reader.request("/_pit", {"id":"fixture"}, method="DELETE")
            self.assertNotIn("_source", transport.call_args.args[1])

    def test_frozen_adapter_manifest(self):
        self.assertEqual(verify_adapter()["build_id"], "COMPACT-BEHAVIOR-20261124-25")

    def test_pit_additional_origin_validation_and_cleanup(self):
        reader = source.ElasticWindow({"host":"https://example.test", "index_pattern":"logs-*"},
                                      instant("2026-11-28T09:50:00Z"), instant("2026-11-28T09:55:00Z"))
        rows = [dict(hit(), sort=[1]), dict(hit(), sort=[2])]
        page = {"timed_out":False, "_shards":{"total":1,"successful":1,"failed":0},
                "hits":{"total":{"relation":"eq","value":2},"hits":rows}}
        with patch.object(reader, "request", side_effect=[{"id":"fixture"}, page, {}]) as transport:
            with self.assertRaisesRegex(identity.BoundaryError, "DUPLICATE_DOCUMENT"):
                extract_window(reader, SCOPE, SEEN)
            self.assertEqual(transport.call_args.args[0], "/_pit")
            self.assertEqual(transport.call_args.kwargs["method"], "DELETE")

    def test_partial_elastic_page_never_returns_complete_window(self):
        reader = source.ElasticWindow({"host":"https://example.test", "index_pattern":"logs-*"},
                                      instant("2026-11-28T09:50:00Z"), instant("2026-11-28T09:55:00Z"))
        page = {"timed_out":True, "_shards":{"total":1,"successful":1,"failed":0},
                "hits":{"total":{"relation":"eq","value":1},"hits":[dict(hit(), sort=[1])]}}
        with patch.object(reader, "request", side_effect=[{"id":"fixture"}, page, {}]):
            with self.assertRaisesRegex(ValueError, "elastic_partial_page"):
                extract_window(reader, SCOPE, SEEN)


if __name__ == "__main__":
    unittest.main()
