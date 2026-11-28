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
from pathlib import Path, PurePosixPath, PureWindowsPath
import re

from jsonschema import Draft202012Validator, FormatChecker

from . import CONTRACT_VERSION as CONTRACT

FIVE = 300_000_000_000
MAX_INT64 = 2**63 - 1
ROOT = Path(__file__).with_name("v2")
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


def _digest(parts):
    data = json.dumps(parts, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def key(namespace, source_scope, value):
    return _digest([namespace, source_scope, value])


def canonical_request_id(value):
    """Accepted Core GUID spellings. Separators are removable only at GUID positions."""
    hex_group = r"[0-9a-fA-F]"
    require(isinstance(value, str) and re.fullmatch(
        rf"{hex_group}{{32}}|{hex_group}{{8}}(?:-{hex_group}{{4}}){{3}}-{hex_group}{{12}}", value),
        "invalid_request_guid")
    canonical = value.replace("-", "").lower()
    require(canonical != "0" * 32, "empty_request_guid")
    return canonical


def document_key(scope, index, document_id):
    return _digest(["userid-document-1", scope, index, document_id])


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
    else:
        require(value is None or isinstance(value, (str, bool, int)), "non_json_value")


def _identity(identity, scope, request_key):
    require(all(e["request_key"] == request_key for e in identity["evidence"] + identity["kind_evidence"]),
            "identity_witness_belongs_to_another_request")
    require(all(e["source"] == "LOG_METADATA" for e in identity["evidence"]),
            "identity_must_come_from_log_metadata")
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
        proofs = identity["kind_evidence"]
        if proofs:
            require(all(e["source"] == "SOURCE_AUTH_STATE" and e["observed_user_id"] == uid
                        for e in proofs), "identity_kind_needs_matching_auth_evidence")
            kinds = {e["observed_kind"] for e in proofs}
            expected_kind = next(iter(kinds)) if len(kinds) == 1 else "UNDETERMINED"
            require(identity["kind"] == expected_kind, "identity_kind_evidence_mismatch")


def _features(features):
    for direction in ("input", "output"):
        component = features[direction]
        for summary in component["data"].get("numeric", {}).values():
            low, high, mean = summary["min"], summary["max"], summary["mean"]
            require(low <= high, "numeric_summary_inverted_range")
            # A binary float computed as sum/count can round one ULP past an endpoint.
            inside = low <= mean <= high
            if not inside and isinstance(mean, float):
                inside = (math.nextafter(mean, -math.inf) <= high
                          and math.nextafter(mean, math.inf) >= low)
            require(inside, "numeric_mean_outside_range")
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
    require(begin < end, "analysis_window_order")
    require(int(reference["cutoff_ns"]) <= begin, "reference_must_not_use_future")
    require(reference["model_version"] == record["model_version"],
            "reference_model_version_mismatch")
    if record["status"] in ("NORMAL", "ANOMALY"):
        require(record["entity_key"] is not None, "evaluated_result_needs_entity")
        require(int(record["analyzed_at_ns"]) >= end, "decision_before_window_close")
        require(record["observed"] is not None and record["threshold"] is not None,
                "decision_needs_measurement_and_threshold")
        require(reference["basis"] != "UNAVAILABLE", "decision_needs_reference_basis")
        if reference["basis"] == "PAST_DATA":
            require(reference["windows"] > 0 and reference["samples"] > 0
                    and reference["fingerprint"] is not None,
                    "statistical_decision_needs_pinned_past_samples")
        else:
            require(record["method"] in ("access_denied_attempts", "invalid_session_attempts"),
                    "engineering_floor_policy_not_defined_for_method")
        if record["status"] == "ANOMALY":
            require(record["witnesses"], "anomaly_needs_versioned_witness")


def _case(record):
    revisions = {}
    current = {}
    entities = set()
    for finding in record["findings"]:
        _analysis(finding)
        require(finding["source_scope"] == record["source_scope"], "case_source_scope_mismatch")
        require(finding["actor_key"] == record["actor_key"], "case_actor_mismatch")
        entities.add((finding["entity_type"], finding["entity_key"]))
        fid, rev = finding["finding_key"], finding["finding_revision"]
        seen = revisions.setdefault(fid, set())
        require(rev not in seen, "duplicate_finding_revision")
        seen.add(rev)
        if fid not in current or rev > current[fid]["finding_revision"]:
            current[fid] = finding
    require(len(entities) == 1, "case_entity_mismatch")
    for note in record["feedback"]:
        finding = current.get(note["finding_key"])
        require(finding is not None and note["finding_revision"] <= finding["finding_revision"],
                "feedback_must_reference_case_finding_revision")
    if record["state"] == "ACTIVE":
        require(any(f["status"] == "ANOMALY" for f in current.values()),
                "active_case_needs_current_anomaly")


def _runtime_roots(record):
    paths = (record["code_root"], record["data_root"])
    windows = [bool(PureWindowsPath(p).drive or "\\" in p) for p in paths]
    require(windows[0] == windows[1], "runtime_path_styles_must_match")
    pathmod = ntpath if windows[0] else posixpath
    pure_path = PureWindowsPath if windows[0] else PurePosixPath
    roots = []
    for path in paths:
        root = pure_path(pathmod.normpath(path))
        require(root.is_absolute() and chr(0) not in path, "runtime_path_must_be_absolute")
        if windows[0]:
            require(not root.as_posix().startswith(("//?/", "//./")),
                    "runtime_path_needs_drive_or_unc_share")
            require(all(not part.endswith((" ", ".")) and ":" not in part
                        for part in root.parts[1:]), "ambiguous_windows_path_component")
        roots.append(root)
    code, data = roots
    require(not code.is_relative_to(data) and not data.is_relative_to(code),
            "immutable_code_and_mutable_data_must_be_disjoint")


def validate_record(record):
    _finite(record)
    error = next(VALIDATOR.iter_errors(record), None)
    if error:
        raise ContractViolation("schema_violation")
    kind = record["record_type"]
    if kind == "SourceRecord":
        origin = record["origin"]
        require(record["document_key"] == document_key(record["source_scope"], origin["_index"], origin["_id"]),
                "document_key_mismatch")
    elif kind == "SourceWindow":
        begin, end = int(record["window_start_ns"]), int(record["window_end_ns"])
        require(begin % FIVE == 0 and end - begin == FIVE, "aligned_five_minute_window_required")
    elif kind == "RequestIdentity":
        require(record["request_key"] == key("userid-request-1", record["source_scope"],
                                            record["request_id"]), "request_key_mismatch")
        _identity(record["identity"], record["source_scope"], record["request_key"])
    elif kind == "FeatureSet":
        _features(record)
    elif kind == "Behavior":
        require(record["behavior_key"] == key("userid-behavior-1", record["source_scope"],
                                             record["request_id"]), "behavior_key_mismatch")
        identity, features = record["identity"], record["features"]
        _identity(identity, record["source_scope"],
                  key("userid-request-1", record["source_scope"], record["request_id"]))
        _features(features)
        known = int(record["known_at_ns"])
        require(all(int(e["seen_at_ns"]) <= known
                    for e in identity["evidence"] + identity["kind_evidence"]),
                "identity_witness_not_known_at_revision")
        require(all(int(e["event_time_ns"]) <= known for e in identity["kind_evidence"]),
                "auth_state_not_known_at_revision")
        for side in ("input", "output"):
            observed_at = features[side]["observed_at_ns"]
            require(observed_at is None or int(observed_at) <= known,
                    "feature_not_known_at_revision")
        if record["occurred_at_ns"] is not None:
            require(int(record["occurred_at_ns"]) <= known, "operation_not_known_at_revision")
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
            require(any(int(e["event_time_ns"]) <= int(record["occurred_at_ns"])
                        for e in identity["kind_evidence"]), "account_proof_after_operation")
        if features["service_eligible"]:
            require(record["service_key"] is not None, "eligible_service_needs_service_key")
        if features["service_eligible"] or features["result_eligible"]:
            require(record["state"] == "COMPLETE"
                    and record["operation_role"] in ("business", "user_management")
                    and record["api"] is not None and record["occurred_at_ns"] is not None,
                    "service_eligibility_needs_complete_operation")
        if features["result_eligible"]:
            require(record["result"]["api_code"] is not None, "result_code_unavailable")
        result = record["result"]
        if result["api_outcome"] == "REPORTED_SUCCESS":
            name = result["api_name"] or ""
            require(result["api_code"] == "G00000" and name.isascii() and name.lower() == "successful",
                    "reported_success_needs_exact_code_and_name")
        elif result["api_outcome"] == "REPORTED_FAILURE":
            require(result["api_code"] not in (None, "G00000"),
                    "reported_failure_needs_failure_code")
    elif kind == "AnalysisResult":
        _analysis(record)
    elif kind == "CaseView":
        _case(record)
    elif kind == "RuntimeConfig":
        _runtime_roots(record)


def main():
    samples = json.loads((ROOT / "examples.json").read_text(encoding="utf-8"))
    for sample in samples.values():
        validate_record(sample)
    print(json.dumps({"status": "VALID", "contract": CONTRACT, "records": len(samples)}))


if __name__ == "__main__":
    main()
