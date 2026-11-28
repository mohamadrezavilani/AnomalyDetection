"""Strict metadata identity and bounded, deterministic request evidence.

No payload, token, Session, IP or UserAgent can supply an actor identity.
"""
from __future__ import annotations

from copy import deepcopy
import re

from contracts.userid import CONTRACT_VERSION, IDENTITY_POLICY_VERSION
from contracts.userid.validate import key

MAX_INT64 = 2**63 - 1
SCOPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
GUID = re.compile(r"(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12})")


class BoundaryError(ValueError):
    """Fixed public reason code, never private field values."""


def scope(value):
    if not isinstance(value, str) or not SCOPE.fullmatch(value):
        raise BoundaryError("SOURCE_SCOPE_INVALID")
    return value


def nanoseconds(value):
    if (not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,18}", value)
            or int(value) > MAX_INT64):
        raise BoundaryError("NANOSECONDS_INVALID")
    return value


def locations(metadata, field):
    """Preserve source-vs-docvalue semantics instead of choosing a winner."""
    if not any(k in metadata for k in ("_source", "fields", "log")) and field in metadata:
        yield "log." + field, metadata[field]
    for container, label in (("_source", "_source"), ("fields", "fields"), ("log", "log")):
        data = metadata.get(container, {})
        if isinstance(data, dict) and field in data:
            yield label + "." + field, data[field]


def request_id(metadata):
    values = set()
    for field, value in locations(metadata, "RequestID"):
        if field.startswith("fields.") and isinstance(value, list) and len(value) == 1:
            value = value[0]
        if not isinstance(value, str) or not GUID.fullmatch(value):
            raise BoundaryError("REQUEST_ID_INVALID")
        values.add(value.replace("-", "").lower())
    if not values:
        raise BoundaryError("REQUEST_ID_MISSING")
    if len(values) != 1:
        raise BoundaryError("REQUEST_ID_CONFLICT")
    return next(iter(values))


def user_id(value):
    # bool is deliberately not an integer identity; floats are never coerced.
    if type(value) is int and 0 < value <= MAX_INT64:
        return str(value)
    if (isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,18}", value)
            and int(value) <= MAX_INT64):
        return value
    raise BoundaryError("USER_ID_INVALID_VALUE")


def empty():
    return dict(identity_policy_version=IDENTITY_POLICY_VERSION, status="MISSING",
                kind="UNDETERMINED", user_id=None, actor_key=None,
                candidate_user_ids=[], identity_as_of_ns=None, missing_observed=False,
                invalid_reasons=[], evidence=[], kind_evidence=[])


def from_record(record):
    result = empty()
    found = list(locations(record["metadata"], "UserID"))
    result["missing_observed"] = not found
    for field, value in found:
        if value is None or field == "fields.UserID" and value == []:
            result["missing_observed"] = True
            continue
        values = [value]
        if isinstance(value, list):
            values = value
            if not field.startswith("fields.") or len(value) != 1:
                result["invalid_reasons"].append("USER_ID_INVALID_SHAPE")
            if len(value) > 4:
                raise BoundaryError("USER_ID_CANDIDATE_LIMIT")
        for raw in values:
            try:
                uid = user_id(raw)
            except BoundaryError as exc:
                uid = None
                result["invalid_reasons"].append(str(exc))
            result["evidence"].append(dict(
                source="LOG_METADATA", document_key=record["document_key"], field=field,
                event_time_ns=record["event_time_ns"], seen_at_ns=record["seen_at_ns"],
                observed_user_id=uid))
    return merge(empty(), result, record["source_scope"])


def merge(left, right, source_scope):
    """Bounded semilattice: retain every candidate and its earliest dated proof.

    Up to sixteen deterministic provenance samples are retained. Sampling may
    discard redundant witnesses, never a conflicting candidate or invalid flag.
    """
    scope(source_scope)
    result = empty()
    result["missing_observed"] = left["missing_observed"] or right["missing_observed"]
    result["invalid_reasons"] = sorted(set(left["invalid_reasons"] + right["invalid_reasons"]))
    distinct = {}
    for evidence in left["evidence"] + right["evidence"]:
        e = deepcopy(evidence)
        k = (e["document_key"], e["field"], e["observed_user_id"], e["event_time_ns"])
        previous = distinct.get(k)
        if previous:
            e["seen_at_ns"] = str(min(int(e["seen_at_ns"]), int(previous["seen_at_ns"])))
        distinct[k] = e
    def order(e):
        return (e["event_time_ns"] is None, int(e["event_time_ns"] or "0"),
                e["document_key"] or "", e["field"], e["observed_user_id"] or "")
    ordered = sorted(distinct.values(), key=order)
    candidates = sorted({e["observed_user_id"] for e in ordered if e["observed_user_id"] is not None})
    if len(candidates) > 4:
        raise BoundaryError("USER_ID_CANDIDATE_LIMIT")
    required = [next(e for e in ordered if e["observed_user_id"] == uid) for uid in candidates]
    invalid_witness = next((e for e in ordered if e["observed_user_id"] is None), None)
    if invalid_witness is not None:
        required.append(invalid_witness)
    retained = required + [e for e in ordered if e not in required][:16 - len(required)]
    result["evidence"] = sorted(retained, key=order)
    result["candidate_user_ids"] = candidates
    result["status"] = ("CONFLICT" if len(candidates) > 1 else "INVALID" if result["invalid_reasons"]
                        else "VALID" if candidates else "MISSING")
    if result["status"] == "VALID":
        uid = candidates[0]
        result["user_id"] = uid
        result["actor_key"] = key("userid-actor-1", source_scope, uid)
        times = [int(e["event_time_ns"]) for e in retained
                 if e["observed_user_id"] == uid and e["event_time_ns"] is not None]
        result["identity_as_of_ns"] = str(min(times)) if times else None
    return result


def project(source_scope, rid, identity):
    return dict(record_type="RequestIdentity", contract_version=CONTRACT_VERSION,
                source_scope=scope(source_scope), request_id=rid,
                request_key=key("userid-request-1", source_scope, rid), identity=deepcopy(identity))
