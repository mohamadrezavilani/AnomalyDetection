"""Pure request extraction and atomic complete-window preparation for WP02.

The frozen Compact parser supplies reviewed content/service facts only. Its
Session identity, behavior IDs, eligibility and persistence are never exported.
"""
from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
import re

from compact_behavior import extract as content
from compact_behavior import payload, security
from compact_behavior.version import verify
from contracts.userid import CONTRACT_VERSION, FEATURE_VERSION, IDENTITY_POLICY_VERSION
from contracts.userid.validate import key, validate_record
from . import EXTRACTOR_VERSION, STATE_VERSION, OBSERVATIONS_VERSION
from . import identity, source

PINNED_CONTENT_SHA256 = "1eeea74603931361c41a39679bb654cd164497cae549854f46f6739b1103a752"
PINNED_ROLE_CATALOG_SHA256 = "05ebff4db5829cc2f72a73e2813dce3002f7afd26793c9efd61947d246005d92"
Limits = content.Limits
LimitExceeded = content.LimitExceeded
SECRET = re.compile(r"^(?:session|sessionid|session_id)$", re.I)


@lru_cache(maxsize=1)
def verify_adapter():
    result = verify()
    if result["source_sha256"] != PINNED_CONTENT_SHA256:
        raise identity.BoundaryError("CONTENT_ADAPTER_VERSION_MISMATCH")
    from compact_behavior.services import operation_catalog
    catalog = operation_catalog()
    if catalog["source_catalog_sha256"] != PINNED_ROLE_CATALOG_SHA256:
        raise identity.BoundaryError("ROLE_CATALOG_VERSION_MISMATCH")
    return dict(result, source_role_catalog_sha256=PINNED_ROLE_CATALOG_SHA256,
                behavior_policy_version=catalog["policy_version"])


def without_session(value):
    if isinstance(value, dict):
        return {k: without_session(v) for k, v in value.items() if not SECRET.fullmatch(k)}
    if isinstance(value, list):
        return [without_session(v) for v in value]
    return value


def fragment(record):
    verify_adapter()
    if (record.get("record_type") != "SourceRecord" or record.get("contract_version") != CONTRACT_VERSION
            or record.get("source_profile") != source.PROFILE):
        raise identity.BoundaryError("SOURCE_RECORD_VERSION_MISMATCH")
    identity.scope(record["source_scope"])
    identity.nanoseconds(record["seen_at_ns"])
    if record["event_time_ns"] is not None:
        identity.nanoseconds(record["event_time_ns"])
    rid = identity.request_id(record["metadata"])
    # Canonical RequestID is the only identity passed to the reviewed parser.
    row = deepcopy(record["metadata"])
    if not any(k in row for k in ("_source", "fields", "log")):
        row = {"_source": row}
    if "log" in row:
        row["_source"] = row.pop("log")
    for data in row.values():
        data.pop("UserID", None)
        data.pop("Session", None)
        data["RequestID"] = rid
        data["message"] = record["message"]
        data["@timestamp"] = content.iso(int(record["event_time_ns"])) if record["event_time_ns"] is not None else None
    facts = content.facts(row)
    for direction in ("inputs", "outputs"):
        for entry in facts[direction]:
            if entry.get("representation") == "FULL_VALUE_V1":
                cleaned = without_session(entry["value"])
                if cleaned != entry["value"]:
                    entry.update(payload.packed(cleaned, inquiry_input=direction == "inputs"))
    return dict(version=STATE_VERSION, extractor_version=EXTRACTOR_VERSION,
                source_scope=record["source_scope"], request_id=rid,
                known_at_ns=record["seen_at_ns"], identity=identity.from_record(record), facts=facts)


def _check(state):
    if state.get("version") != STATE_VERSION or state.get("extractor_version") != EXTRACTOR_VERSION:
        raise identity.BoundaryError("REQUEST_STATE_VERSION_MISMATCH")
    identity.scope(state["source_scope"])
    identity.nanoseconds(state["known_at_ns"])
    if (state["facts"]["request_id"] != state["request_id"]
            or state["facts"]["sessions"] or state["facts"]["raw_session_ids"]):
        raise identity.BoundaryError("REQUEST_STATE_IDENTITY_MISMATCH")


def state_hash(state):
    """Stable source checkpoint hash; processing-time replay is idempotent."""
    value = {k: v for k, v in state.items() if k != "known_at_ns"}
    value["identity"] = dict(state["identity"], evidence=[
        {k: v for k, v in e.items() if k != "seen_at_ns"} for e in state["identity"]["evidence"]])
    return content.digest(value)


def _source_identity(value):
    return dict(value, evidence=[{k: v for k, v in e.items() if k != "seen_at_ns"}
                                 for e in value["evidence"]])


def merge(left, right, limits=Limits(), *, _check_size=True):
    """Pure merge, including late cross-window fragments. Neither input mutates."""
    _check(right)
    if left is None:
        result = deepcopy(right)
    else:
        _check(left)
        if (left["source_scope"], left["request_id"]) != (right["source_scope"], right["request_id"]):
            raise identity.BoundaryError("REQUEST_STATE_SCOPE_OR_ID_MISMATCH")
        result = dict(right, identity=identity.merge(left["identity"], right["identity"], right["source_scope"]),
                      facts=content.merge(left["facts"], right["facts"], limits,
                                          _check_size=False, _normalized=True))
        # Identical replay never moves knowledge time forward. First-seen time
        # in sampled provenance is also merged by minimum, not the replay clock.
        unchanged = (result["facts"] == left["facts"]
                     and _source_identity(result["identity"]) == _source_identity(left["identity"]))
        result["known_at_ns"] = (left["known_at_ns"] if unchanged
                                 else str(max(int(left["known_at_ns"]), int(right["known_at_ns"]))))
    if _check_size and len(content.canonical(result).encode("utf-8")) > limits.state_bytes:
        raise LimitExceeded("request_state_bytes_limit")
    return result


def _context(facts):
    context = facts.get("request_context", {})
    return dict(version="userid-request-context-1", limited=context.get("limited", []),
                values={name: [dict(value=e["value"], sources=e["sources"],
                                   first_ns=str(e["first_ns"]) if e["first_ns"] is not None else None,
                                   undated=e["undated"]) for e in entries]
                        for name, entries in context.get("values", {}).items()})


def _attempt(facts):
    found = security.project(facts)
    if found:
        return dict(kind={"access_denied": "ACCESS_DENIED", "invalid_session": "INVALID_SESSION",
                          "validation_rejection": "VALIDATION_REJECTED"}[found["kind"]],
                    requested_service=found["requested_service"], result_code=found["result_code"],
                    symbol=found["symbol"], at_ns=str(found["at_ns"]),
                    stage="REJECTED_BEFORE_CONFIRMED_EXECUTION")
    roots = facts["roots"]
    if (len(roots) == 1 and len(facts["apis"]) == 1 and roots[0]["at_ns"] is not None
            and (roots[0]["code"], roots[0]["symbol"]) == ("GR0004", "RequestRateLimiting")
            and not set(facts["issues"]).intersection({"operation_field_conflict", "message_field_conflict",
                                                       "timestamp_unavailable", "prior_fragments_expired"})
            and not any(e["kind"] == "service_request" for e in facts["dispatch"])):
        actions = {e["value"] for e in facts["dispatch"] if e["kind"] == "action"}
        if len(actions) <= 1:
            return dict(kind="RATE_LIMIT", requested_service=next(iter(actions), None),
                        result_code="GR0004", symbol="RequestRateLimiting", at_ns=str(roots[0]["at_ns"]),
                        stage="REJECTED_BEFORE_CONFIRMED_EXECUTION")
    return None


def _component(direction, body, facts, complete):
    f = body["features"] if body else {}
    basis = {"public_api": "PUBLIC_API", "business_parameters": "BUSINESS_SQL",
             "reviewed_same_request_provider": "REVIEWED_PROVIDER",
             "unconfirmed_same_request_provider": "UNCONFIRMED"}.get(f.get(direction + "_basis"), "UNAVAILABLE")
    snapshot = f.get(direction)
    at = f.get(direction + "_asof_ns")
    flags = dict(f.get(direction + "_feature_eligibility", dict.fromkeys(("targets", "numeric", "shape"), False)))
    limitations = []
    if snapshot:
        limitations = sorted({str(code).upper() for dimension in snapshot.get("completeness", {}).values()
                              for code in dimension.get("reasons", [])})
    role = body["operation_role"] if body else "unknown"
    if role in ("support", "system"):
        status = "OUT_OF_SCOPE"
    elif not snapshot:
        status = ("INVALID" if body and set(body["quality"]).intersection(
            {direction + "_conflict", direction + "s_parse_error", direction + "s_content_limit"}) else "MISSING")
    elif basis == "UNCONFIRMED":
        status = "PARTIAL"
        limitations.append("BINDING_UNCONFIRMED")
    else:
        status = "AVAILABLE" if snapshot.get("complete") else "PARTIAL"
    if not complete or status in ("OUT_OF_SCOPE", "MISSING", "INVALID") or basis in ("UNCONFIRMED", "UNAVAILABLE"):
        flags = dict.fromkeys(flags, False)
    if snapshot and not any(flags.values()) and status == "AVAILABLE":
        status = "PARTIAL"
        limitations.append("CONTENT_NOT_ELIGIBLE")
    data = dict(feature_snapshot=deepcopy(snapshot)) if snapshot else {}
    # Reviewed subjects and cache provenance remain explicitly versioned facts.
    for name in ("inquiry_subjects_v1", "postal_contacts", "postal_cache_returned_at_ns"):
        if direction == "input" and name == "inquiry_subjects_v1" or direction == "output" and name != "inquiry_subjects_v1":
            if name in f:
                data[name] = (str(f[name]) if name == "postal_cache_returned_at_ns" else
                              {k: [str(at) for at in v] for k, v in f[name].items()} if name == "postal_contacts"
                              else deepcopy(f[name]))
    return dict(status=status, basis=basis, observed_at_ns=str(at) if at is not None else None,
                eligibility=flags, limitations=sorted(set(limitations)), data=data)


def materialize(state, *, revision=1):
    """Always returns a Behavior, including pending requests with no public API."""
    _check(state)
    facts = state["facts"]
    body = content.materialize(state["source_scope"], facts)
    roots = [r for r in facts["roots"] if body and r["api"] == body["api"]]
    quality = {q.upper() for q in (body["quality"] if body else facts["issues"])
               if not q.startswith("session_")}
    if body is None:
        quality.add("OPERATION_UNAVAILABLE")
    refusal_pairs = set(security.PAIRS) | {("GR0004", "RequestRateLimiting")}
    if (len(roots) == 1 and (roots[0]["code"], roots[0]["symbol"]) in refusal_pairs
            and any(e["kind"] == "service_request" for e in facts["dispatch"])):
        quality.add("EXECUTION_REFUSAL_CONFLICT")
    status = ("CONFLICT" if quality.intersection({"OPERATION_CONFLICT", "OPERATION_FIELD_CONFLICT",
                                                   "MESSAGE_FIELD_CONFLICT", "MULTIPLE_COMPLETION_VARIANTS", "RESULT_CONFLICT",
                                                   "EXECUTION_REFUSAL_CONFLICT"})
              else "EXPIRED" if "PRIOR_FRAGMENTS_EXPIRED" in quality
              else "COMPLETE" if body and len(roots) == 1 and roots[0]["at_ns"] is not None else "PENDING")
    complete = status == "COMPLETE"
    ident = deepcopy(state["identity"])
    if ident["status"] != "VALID":
        quality.add("IDENTITY_" + ident["status"])
    if ident["kind"] == "UNDETERMINED":
        quality.add("IDENTITY_KIND_UNDETERMINED")
    attempt = _attempt(facts)
    f = body["features"] if body else {}
    at = roots[0]["at_ns"] if complete else None
    role = body["operation_role"] if body else "unknown"
    ordinary = complete and not attempt
    actor = bool(ordinary and role in ("business", "user_management") and body["api"]
                 and ident["status"] == "VALID" and ident["identity_as_of_ns"] is not None
                 and int(ident["identity_as_of_ns"]) <= at)
    if complete and ident["status"] == "VALID" and not actor and not attempt and role in ("business", "user_management"):
        quality.add("IDENTITY_NOT_KNOWN_AT_OPERATION")
    features = dict(record_type="FeatureSet", contract_version=CONTRACT_VERSION,
                    feature_version=FEATURE_VERSION, identity_policy_version=IDENTITY_POLICY_VERSION,
                    actor_eligible=actor, account_eligible=False,
                    service_eligible=bool(ordinary and f.get("service_rate_eligible")),
                    result_eligible=bool(ordinary and f.get("result_eligible")),
                    input=_component("input", body, facts, ordinary),
                    output=_component("output", body, facts, ordinary))
    code = body["result_code"] if body else None
    symbol = roots[0]["symbol"] or None if complete else None
    outcome = ("REPORTED_SUCCESS" if code == "G00000" and (symbol or "").lower() == "successful"
               else "REPORTED_FAILURE" if attempt else "UNKNOWN")
    return dict(record_type="Behavior", contract_version=CONTRACT_VERSION, source_scope=state["source_scope"],
                request_id=state["request_id"], behavior_key=key("userid-behavior-1", state["source_scope"], state["request_id"]),
                revision=revision, identity=ident, api=body["api"] if body else None,
                service_key=body["service_key"] if body else None, operation_role=role, state=status,
                occurred_at_ns=str(at) if at is not None else None, known_at_ns=state["known_at_ns"],
                result=dict(api_code=code, api_name=symbol, api_outcome=outcome,
                            business_state="UNKNOWN", financial_state="OUT_OF_SCOPE"),
                features=features, quality=sorted(quality),
                observations=dict(version=OBSERVATIONS_VERSION,
                                  service_binding=body["service_binding"] if body else "UNAVAILABLE",
                                  request_context=_context(facts), attempt=attempt))


def behavior_hash(behavior):
    """WP02 dirty/retraction signature: excludes processing and sampled provenance."""
    value = {k: v for k, v in behavior.items() if k not in ("revision", "known_at_ns")}
    value["identity"] = {k: v for k, v in behavior["identity"].items()
                         if k not in ("evidence", "missing_observed", "invalid_reasons", "kind_evidence")}
    return content.digest(value)


class Extractor:
    """Window-local accumulator. A failed add leaves all accepted state intact."""
    def __init__(self, limits=Limits()):
        verify_adapter()
        self.limits = limits
        self.states = {}
        self.sizes = {}
        self.state_bytes = 0
        self.records = 0
        self.quarantine = {}

    def add(self, record):
        try:
            item = fragment(record)
        except identity.BoundaryError as exc:
            if not str(exc).startswith("REQUEST_ID_"):
                raise
            self.quarantine[str(exc)] = self.quarantine.get(str(exc), 0) + 1
            self.records += 1
            return
        rid = item["request_id"]
        if rid not in self.states and len(self.states) >= self.limits.requests:
            raise LimitExceeded("window_request_limit")
        prepared = merge(self.states.get(rid), item, self.limits, _check_size=False)
        size = len(content.canonical(prepared).encode("utf-8"))
        if size > self.limits.state_bytes:
            raise LimitExceeded("request_state_bytes_limit")
        total = self.state_bytes + size - self.sizes.get(rid, 0)
        if total > self.limits.total_state_bytes:
            raise LimitExceeded("window_state_bytes_limit")
        self.states[rid] = prepared
        self.sizes[rid] = size
        self.state_bytes = total
        self.records += 1


def extract_window(reader, source_scope, seen_at_ns, *, limits=Limits()):
    """Private provisional accumulation; return nothing on any source failure."""
    extractor = Extractor(limits)
    for record in source.records(reader, source_scope, seen_at_ns):
        extractor.add(record)
    completed = source.window(reader, source_scope)
    validate_record(completed)
    return completed, extractor
