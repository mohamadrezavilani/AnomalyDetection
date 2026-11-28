"""WP00 conformance tests; all examples and identities are synthetic."""
from copy import deepcopy
import json
from pathlib import Path
import unittest

from contracts.userid.validate import (
    ROOT, SCHEMA, ContractViolation, Draft202012Validator,
    key, validate_record,
)

EXAMPLES = json.loads((ROOT / "examples.json").read_text(encoding="utf-8"))


class UserIDContracts(unittest.TestCase):
    def sample(self, kind="Behavior"):
        return deepcopy(EXAMPLES[kind])

    def rejected(self, record):
        with self.assertRaises(ContractViolation):
            validate_record(record)

    def replace_uid(self, record, uid):
        i = record["identity"]
        i["user_id"] = uid
        i["candidate_user_ids"] = [uid]
        i["actor_key"] = key("userid-actor-1", record["source_scope"], uid)
        for evidence in i["evidence"]:
            evidence["observed_user_id"] = uid

    def missing(self, record):
        i = record["identity"]
        i.update(status="MISSING", kind="UNDETERMINED", user_id=None, actor_key=None,
                 candidate_user_ids=[], identity_as_of_ns=None, evidence=[], kind_evidence=[])
        if "features" in record:
            record["features"].update(actor_eligible=False, account_eligible=False)

    def anomaly(self, method="actor_rate"):
        r = self.sample("AnalysisResult")
        r.update(status="ANOMALY", method=method, observed=150, threshold=100,
                 reason_code="SYNTHETIC_THRESHOLD_EXCEEDED")
        r["reference"].update(basis="PAST_DATA", windows=12, samples=30,
                              fingerprint="d" * 64)
        return r

    def test_schema_and_all_eight_boundary_examples(self):
        Draft202012Validator.check_schema(SCHEMA)
        self.assertEqual(len(EXAMPLES), 8)
        for name, record in EXAMPLES.items():
            with self.subTest(record_type=name):
                validate_record(deepcopy(record))

    def test_large_and_maximum_int64_remain_exact_strings(self):
        for uid in ("9007199254740993", "9223372036854775807"):
            r = self.sample("RequestIdentity")
            self.replace_uid(r, uid)
            validate_record(r)
            self.assertIsInstance(r["identity"]["user_id"], str)

    def test_out_of_range_and_noncanonical_userids_rejected(self):
        for uid in ("9223372036854775808", "0", "-1", "01", "+1", " 1", "1 ",
                    "1e3", "****", "N/A", "", "۱۲۳", 123, 123.0, True, None):
            with self.subTest(uid_type=type(uid).__name__):
                r = self.sample("RequestIdentity")
                r["identity"]["user_id"] = uid
                self.rejected(r)

    def test_raw_source_invalid_identity_is_not_silently_a_valid_actor(self):
        raw = self.sample("SourceRecord")
        raw["metadata"]["UserID"] = "****"
        validate_record(raw)  # Transport preserves input for the WP01 classifier.
        projected = self.sample("RequestIdentity")
        projected["identity"]["user_id"] = raw["metadata"]["UserID"]
        self.rejected(projected)

    def test_missing_identity_keeps_service_evaluation_available(self):
        r = self.sample()
        self.missing(r)
        validate_record(r)
        self.assertTrue(r["features"]["service_eligible"])
        self.assertFalse(r["features"]["actor_eligible"])

    def test_missing_identity_cannot_select_placeholder_actor(self):
        r = self.sample("RequestIdentity")
        self.missing(r)
        r["identity"]["user_id"] = "1"
        self.rejected(r)

    def test_conflict_keeps_two_candidates_without_winner(self):
        r = self.sample("RequestIdentity")
        i = r["identity"]
        second = deepcopy(i["evidence"][0])
        second["observed_user_id"] = "42"
        second["document_key"] = "d" * 64
        i.update(status="CONFLICT", user_id=None, actor_key=None,
                 identity_as_of_ns=None, candidate_user_ids=[i["user_id"], "42"])
        i["evidence"].append(second)
        validate_record(r)
        i["user_id"] = "42"
        self.rejected(r)

    def test_invalid_identity_needs_reason_and_has_no_actor(self):
        r = self.sample("RequestIdentity")
        self.missing(r)
        r["identity"].update(status="INVALID", invalid_reasons=["MASKED_METADATA"])
        validate_record(r)
        r["identity"]["invalid_reasons"] = []
        self.rejected(r)

    def test_identity_evidence_cannot_be_replaced_by_auth_or_payload(self):
        r = self.sample("RequestIdentity")
        r["identity"]["evidence"][0].update(source="SOURCE_AUTH_STATE", field="source.verified")
        self.rejected(r)
        r = self.sample("RequestIdentity")
        r["identity"]["evidence"][0]["field"] = "payload.UserId"
        self.rejected(r)

    def test_candidate_requires_matching_provenance(self):
        r = self.sample("RequestIdentity")
        r["identity"]["evidence"][0]["observed_user_id"] = "42"
        self.rejected(r)

    def test_account_kind_requires_explicit_matching_auth_state(self):
        r = self.sample("RequestIdentity")
        r["identity"]["kind"] = "ACCOUNT"
        self.rejected(r)
        auth = deepcopy(r["identity"]["evidence"][0])
        auth.update(source="SOURCE_AUTH_STATE", field="source.verified")
        r["identity"]["kind_evidence"] = [auth]
        validate_record(r)
        auth["observed_user_id"] = "42"
        self.rejected(r)

    def test_userid_presence_is_not_account_eligibility(self):
        r = self.sample()
        r["features"]["account_eligible"] = True
        self.rejected(r)

    def test_source_scope_is_part_of_actor_and_request_keys(self):
        r = self.sample("RequestIdentity")
        r["source_scope"] = "pishkhan24:stage:core"
        self.rejected(r)
        r["request_key"] = key("userid-request-1", r["source_scope"], r["request_id"])
        self.rejected(r)  # Actor key still belongs to production.

    def test_guid_canonical_form_is_explicit(self):
        r = self.sample("RequestIdentity")
        r["request_id"] = "11111111-1111-4111-8111-111111111111"
        self.rejected(r)

    def test_behavior_key_does_not_follow_user_or_session(self):
        r = self.sample()
        before = r["behavior_key"]
        self.replace_uid(r, "42")
        validate_record(r)
        self.assertEqual(r["behavior_key"], before)
        self.assertNotIn("session_id", r)

    def test_legacy_session_contract_cannot_be_relabelled(self):
        r = self.sample()
        r["session_id"] = "42"
        self.rejected(r)
        r = self.sample()
        r["features"]["session_eligible"] = True
        self.rejected(r)

    def test_undated_identity_is_not_eligible_for_actor_analysis(self):
        r = self.sample()
        r["identity"]["evidence"][0]["event_time_ns"] = None
        r["identity"]["identity_as_of_ns"] = None
        self.rejected(r)
        r["features"]["actor_eligible"] = False
        validate_record(r)

    def test_identity_after_operation_is_not_backdated(self):
        r = self.sample()
        later = str(int(r["occurred_at_ns"]) + 1)
        r["identity"]["identity_as_of_ns"] = later
        r["identity"]["evidence"][0]["event_time_ns"] = later
        self.rejected(r)

    def test_pending_support_and_unknown_are_not_completed_business(self):
        for change in ({"state": "PENDING"}, {"operation_role": "support"},
                       {"operation_role": "system"}, {"operation_role": "unknown"}):
            r = self.sample()
            r.update(change)
            self.rejected(r)
            for k in ("actor_eligible", "account_eligible", "service_eligible", "result_eligible"):
                r["features"][k] = False
            validate_record(r)

    def test_content_eligibility_needs_dated_reviewed_binding(self):
        for basis, when in (("UNCONFIRMED", "1"), ("REVIEWED_PROVIDER", None)):
            r = self.sample("FeatureSet")
            c = r["input"]
            c.update(status="AVAILABLE", basis=basis, observed_at_ns=when)
            c["eligibility"]["targets"] = True
            self.rejected(r)

    def test_success_needs_exact_terminal_code_and_name(self):
        r = self.sample()
        r["result"]["api_name"] = "OtherStatus"
        self.rejected(r)
        r["result"]["api_outcome"] = "UNKNOWN"
        validate_record(r)

    def test_window_must_be_complete_and_aligned(self):
        r = self.sample("SourceWindow")
        r["complete"] = False
        self.rejected(r)
        r = self.sample("SourceWindow")
        r["window_end_ns"] = str(int(r["window_end_ns"]) + 1)
        self.rejected(r)
        r = self.sample("SourceWindow")
        for field in ("window_start_ns", "window_end_ns"):
            r[field] = str(int(r[field]) + 1)
        self.rejected(r)

    def test_legacy_source_profile_is_not_new_userid_source(self):
        r = self.sample("SourceWindow")
        r["source_profile"] = "legacy-session"
        self.rejected(r)

    def test_nanosecond_precision_and_nonfinite_json(self):
        r = self.sample("AnalysisResult")
        r["window_start_ns"] = int(r["window_start_ns"])
        self.rejected(r)
        for v in (float("nan"), float("inf"), -float("inf")):
            r = self.sample("AnalysisResult")
            r["observed"] = v
            self.rejected(r)

    def test_future_and_wrong_version_references_rejected(self):
        r = self.anomaly()
        r["reference"]["cutoff_ns"] = str(int(r["window_start_ns"]) + 1)
        self.rejected(r)
        r = self.anomaly()
        r["reference"]["model_version"] = "userid-ad-other"
        self.rejected(r)
        r = self.anomaly()
        r["model_version"] = "compact-ad-adaptive-3"
        self.rejected(r)

    def test_anomaly_requires_reference_threshold_and_witness(self):
        for field, value in (("threshold", None), ("observed", None), ("witnesses", [])):
            r = self.anomaly()
            r[field] = value
            self.rejected(r)
        r = self.anomaly()
        r["reference"]["basis"] = "UNAVAILABLE"
        self.rejected(r)
        r = self.anomaly()
        validate_record(r)

    def test_engineering_floor_is_explicit_and_network_is_not_account(self):
        r = self.anomaly()
        r["reference"].update(basis="ENGINEERING_FLOOR", windows=0, samples=0)
        self.rejected(r)
        r.update(method="invalid_session_attempts", entity_type="NETWORK",
                 actor_key=None, entity_key="e" * 64)
        validate_record(r)
        r["entity_key"] = "192.0.2.1"
        self.rejected(r)

    def test_actor_method_without_identity_is_invalid_not_normal(self):
        r = self.sample("AnalysisResult")
        r.update(actor_key=None, entity_key=None, status="INVALID_INPUT")
        validate_record(r)
        r["status"] = "NORMAL"
        self.rejected(r)

    def test_case_scope_and_actor_cannot_mix(self):
        r = self.sample("CaseView")
        r["source_scope"] = "pishkhan24:stage:core"
        self.rejected(r)
        r = self.sample("CaseView")
        r["actor_key"] = "f" * 64
        self.rejected(r)

    def test_warmup_is_not_an_active_anomaly_case(self):
        r = self.sample("CaseView")
        r["state"] = "ACTIVE"
        self.rejected(r)

    def test_current_finding_does_not_erase_prior_revision_feedback(self):
        r = self.sample("CaseView")
        r["findings"][0]["finding_revision"] = 2
        r["feedback"] = [{"finding_key": r["findings"][0]["finding_key"],
                          "finding_revision": 1, "verdict": "NEEDS_REVIEW",
                          "note": "Synthetic previous-revision feedback.",
                          "recorded_at_ns": r["findings"][0]["window_end_ns"]}]
        validate_record(r)

    def test_runtime_cannot_target_legacy_database_or_port(self):
        for field, value in (("database_name", "p24_design_viewer"), ("web_port", 5021),
                             ("task_prefix", "P24-CompactProduct")):
            r = self.sample("RuntimeConfig")
            r[field] = value
            self.rejected(r)

    def test_code_and_mutable_data_paths_are_separate(self):
        r = self.sample("RuntimeConfig")
        r["data_root"] = r["code_root"]
        self.rejected(r)
        for same in ("c:/p24/userid/CODE", "C:/P24/UserID/code/."):
            r["data_root"] = same
            self.rejected(r)

    def test_normalized_contracts_do_not_import_or_bootstrap_runtime(self):
        root = ROOT.parents[2]
        for source in (root / "contracts" / "userid").glob("*.py"):
            text = source.read_text(encoding="utf-8")
            self.assertNotIn("import compact_product", text)
            self.assertNotIn("import psycopg", text)
            self.assertNotIn("subprocess.", text)


if __name__ == "__main__":
    unittest.main()
