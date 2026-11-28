"""Offline conformance checks for WP00 boundaries; no collector or DB startup.

Schema checks use jsonschema 4.25.1. Semantic checks below define boundary
invariants, not a source extractor, SQL migration, detector or production mode.
"""
from __future__ import annotations

import hashlib
import json
import math
import ntpath
import posixpath
from pathlib import Path
import re

from jsonschema import Draft202012Validator, FormatChecker

CONTRACT = "p24-userid-1"
FIVE = 300_000_000_000
MAX_INT64 = 2**63 - 1
ROOT = Path(__file__).with_name("v1")
SCHEMA = json.loads((ROOT / "schema.json").read_text(encoding="utf-8"))
FORMATS = FormatChecker()


@FORMATS.checks("positive-int64-decimal")
def positive_int64(value):
    return (isinstance(value, str)
            and re.fullmatch(r"[1-9][0-9]{0,18}", value) is not None
            and int(value) <= MAX_INT64)


@FORMATS.checks("nonnegative-int64-decimal")
def nonnegative_int64(value):
    return (isinstance(value, str)
            and re.fullmatch(r"0|[1-9][0-9]{0,18}", value) is not None
            and int(value) <= MAX_INT64)


Draft202012Validator.check_schema(SCHEMA)
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FORMATS)


class ContractViolation(ValueError):
    """A fixed code and field path; never echo private field values."""


def require(condition, code):
    if not condition:
        raise ContractViolation(code)


def key(namespace, source_scope, value):
    """Canonical UTF-8 JSON array of three strings, then lowercase SHA-256."""
    data = json.dumps([namespace, source_scope, value], ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _finite(value, depth=0, budget=None):
    budget = [200000] if budget is None else budget
    budget[0] -= 1
    require(depth <= 40 and budget[0] >= 0, "contract_structure_limit")
    if isinstance(value, float):
        require(math.isfinite(value), "nonfinite_json_number")
    elif isinstance(value, dict):
        require(all(isinstance(k, str) for k in value), "json_keys_must_be_strings")
        for child in value.values():
            _finite(child, depth + 1, budget)
    elif isinstance(value, list):
        for child in value:
            _finite(child, depth + 1, budget)


def _identity(identity, scope):
    require(all(e["source"] == "LOG_METADATA" for e in identity["evidence"]),
            "identity_must_come_from_log_metadata")
    for evidence in identity["evidence"] + identity["kind_evidence"]:
        if evidence["source"] == "LOG_METADATA":
            require(evidence["field"] in ("_source.UserID", "fields.UserID", "log.UserID"),
                    "metadata_evidence_field_mismatch")
        else:
            require(evidence["field"] in ("source.verified", "source.identity_kind"),
                    "auth_evidence_field_mismatch")
    candidates = identity["candidate_user_ids"]
    observed = {e["observed_user_id"] for e in identity["evidence"]
                if e["observed_user_id"] is not None}
    require(set(candidates) == observed, "identity_candidates_need_matching_evidence")
    if identity["status"] == "VALID":
        uid = identity["user_id"]
        require(candidates == [uid], "valid_identity_candidate_mismatch")
        require(identity["actor_key"] == key("userid-actor-1", scope, uid),
                "actor_key_scope_or_value_mismatch")
        times = [int(e["event_time_ns"]) for e in identity["evidence"]
                 if e["observed_user_id"] == uid and e["event_time_ns"] is not None]
        expected = str(min(times)) if times else None
        require(identity["identity_as_of_ns"] == expected, "identity_as_of_evidence_mismatch")
        if identity["kind"] != "UNDETERMINED":
            require(all(e["source"] == "SOURCE_AUTH_STATE"
                        and e["observed_user_id"] == uid
                        for e in identity["kind_evidence"]),
                    "identity_kind_needs_matching_auth_evidence")


def _features(features):
    for direction in ("input", "output"):
        component = features[direction]
        if any(component["eligibility"].values()):
            require(component["status"] in ("AVAILABLE", "PARTIAL")
                    and component["observed_at_ns"] is not None
                    and component["basis"] in ("PUBLIC_API", "BUSINESS_SQL", "REVIEWED_PROVIDER"),
                    "eligible_component_needs_dated_bound_evidence")
    require(not features["account_eligible"] or features["actor_eligible"],
            "account_eligibility_requires_actor")


ACTOR_METHODS = {
    "actor_rate", "service_mix", "isolation_forest", "service_sequence",
    "timing_regularization", "repeated_target", "target_diversity",
    "long_target_enumeration", "rate_limit_rejections", "access_denied_attempts",
}


def _analysis(record):
    begin, end = int(record["window_start_ns"]), int(record["window_end_ns"])
    reference = record["reference"]
    entity = record["entity_type"]
    if record["method"] in ACTOR_METHODS:
        require(entity == "ACTOR", "actor_method_entity_mismatch")
    elif record["method"] == "invalid_session_attempts":
        require(entity == "NETWORK", "network_method_entity_mismatch")
    else:
        require(entity == "SERVICE", "service_method_entity_mismatch")
    if entity == "ACTOR":
        require(record["entity_key"] == record["actor_key"], "actor_entity_key_mismatch")
    elif entity == "SERVICE":
        require(record["actor_key"] is None and record["entity_key"] == record["service_key"],
                "service_entity_key_mismatch")
    else:
        require(record["actor_key"] is None, "network_is_not_account")
        if record["entity_key"] is not None:
            require(re.fullmatch(r"[a-f0-9]{64}", record["entity_key"]) is not None,
                    "network_entity_requires_fingerprint")
    if record["status"] in ("NORMAL", "ANOMALY"):
        require(record["entity_key"] is not None, "evaluated_result_needs_entity")
    require(begin < end, "analysis_window_order")
    require(int(reference["cutoff_ns"]) <= begin, "reference_must_not_use_future")
    require(reference["model_version"] == record["model_version"],
            "reference_model_version_mismatch")
    if record["status"] in ("NORMAL", "ANOMALY") and record["method"] in ACTOR_METHODS:
        require(record["actor_key"] is not None, "actor_method_requires_actor")
    if record["status"] == "ANOMALY":
        require(record["observed"] is not None and record["threshold"] is not None
                and record["witnesses"], "anomaly_needs_measurement_threshold_and_witness")
        require(reference["basis"] != "UNAVAILABLE", "anomaly_needs_reference_basis")
        if reference["basis"] == "PAST_DATA":
            require(reference["windows"] > 0 and reference["samples"] > 0,
                    "statistical_anomaly_needs_past_samples")
        else:
            require(record["method"] in ("access_denied_attempts", "invalid_session_attempts"),
                    "engineering_floor_policy_not_defined_for_method")


def validate_record(record):
    _finite(record)
    error = next(VALIDATOR.iter_errors(record), None)
    if error:
        raise ContractViolation("schema_violation")
    kind = record["record_type"]
    if kind == "SourceWindow":
        begin, end = int(record["window_start_ns"]), int(record["window_end_ns"])
        require(begin % FIVE == 0 and end - begin == FIVE, "aligned_five_minute_window_required")
    elif kind == "RequestIdentity":
        require(record["request_key"] == key("userid-request-1", record["source_scope"],
                                            record["request_id"]), "request_key_mismatch")
        _identity(record["identity"], record["source_scope"])
    elif kind == "FeatureSet":
        _features(record)
    elif kind == "Behavior":
        require(record["behavior_key"] == key("userid-behavior-1", record["source_scope"],
                                             record["request_id"]), "behavior_key_mismatch")
        identity, features = record["identity"], record["features"]
        _identity(identity, record["source_scope"])
        _features(features)
        if features["actor_eligible"]:
            require(identity["status"] == "VALID" and record["state"] == "COMPLETE"
                    and record["operation_role"] in ("business", "user_management")
                    and record["api"] is not None and record["occurred_at_ns"] is not None
                    and identity["identity_as_of_ns"] is not None,
                    "actor_eligibility_needs_complete_dated_identity")
            require(int(identity["identity_as_of_ns"]) <= int(record["occurred_at_ns"]),
                    "actor_identity_after_operation")
        if features["account_eligible"]:
            require(identity["kind"] == "ACCOUNT", "account_kind_unverified")
        if features["service_eligible"] or features["result_eligible"]:
            require(record["state"] == "COMPLETE"
                    and record["operation_role"] in ("business", "user_management")
                    and record["api"] is not None and record["occurred_at_ns"] is not None,
                    "service_eligibility_needs_complete_operation")
        if features["result_eligible"]:
            require(record["result"]["api_code"] is not None, "result_code_unavailable")
        if record["result"]["api_outcome"] == "REPORTED_SUCCESS":
            require(record["result"]["api_code"] == "G00000"
                    and (record["result"]["api_name"] or "").lower() == "successful",
                    "reported_success_needs_exact_code_and_name")
    elif kind == "AnalysisResult":
        _analysis(record)
    elif kind == "CaseView":
        for finding in record["findings"]:
            _analysis(finding)
            require(finding["source_scope"] == record["source_scope"], "case_source_scope_mismatch")
            if record["actor_key"] is not None:
                require(finding["actor_key"] == record["actor_key"], "case_actor_mismatch")
        if record["state"] == "ACTIVE":
            require(any(x["status"] == "ANOMALY" for x in record["findings"]),
                    "active_case_needs_anomaly")
    elif kind == "RuntimeConfig":
        def canonical_path(path):
            windows = re.match(r"^[A-Za-z]:", path) or chr(92) in path
            return ntpath.normcase(ntpath.normpath(path)) if windows else posixpath.normpath(path)
        require(canonical_path(record["code_root"]) != canonical_path(record["data_root"]),
                "immutable_code_and_mutable_data_must_be_separate")


def main():
    samples = json.loads((ROOT / "examples.json").read_text(encoding="utf-8"))
    for sample in samples.values():
        validate_record(sample)
    print(json.dumps({"status": "VALID", "contract": CONTRACT, "records": len(samples)}))


if __name__ == "__main__":
    main()
