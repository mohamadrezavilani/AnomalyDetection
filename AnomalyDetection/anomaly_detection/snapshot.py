"""Bounded, versioned projection snapshots; never infer customer executions."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

from . import CONTRACT, SOURCE_SHA, CATALOG_SHA, SEMANTIC_SCHEMA, FIVE_NS, KINDS

MAX_REQUESTS = 500
MAX_ROWS = 4000
MAX_BYTES = 8 * 1024 * 1024
KEY = re.compile(r"[0-9a-f]{64}\Z")
TABLES = ("viewer_semantic_occurrences", "viewer_requests",
          "viewer_contract_observations", "viewer_contract_edges",
          "viewer_contract_identifiers", "viewer_service_roles", "viewer_events")


class ContractError(ValueError):
    """Snapshot rejected without advancing a consumer checkpoint."""


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def require(condition, message):
    if not condition:
        raise ContractError(message)


def integer(value, minimum=0):
    return type(value) is int and minimum <= value <= 9_223_372_036_854_775_807


def text_value(value):
    return isinstance(value, str) and 0 < len(value) <= 512


def api_path(value):
    return str(value or "").split(" Line:", 1)[0].strip()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key:" + key)
        result[key] = value
    return result


def load_snapshot(path):
    path = Path(path)
    require(path.stat().st_size <= MAX_BYTES, "snapshot_byte_budget_exceeded")
    with path.open(encoding="utf-8-sig") as stream:
        data = json.load(stream, object_pairs_hook=_unique_object,
                         parse_constant=lambda value: require(False, "nonfinite_json:" + value))
    return Snapshot(data)


def bucket_is_covered(start, intervals):
    """Union of declared complete intervals; a gap never becomes a zero."""
    end = start + FIVE_NS
    cursor = start
    for left, right in sorted(intervals):
        if right <= cursor:
            continue
        if left > cursor:
            return False
        cursor = max(cursor, right)
        if cursor >= end:
            return True
    return False


class Snapshot:
    def __init__(self, data):
        require(isinstance(data, dict), "snapshot_must_be_object")
        self.data = deepcopy(data)
        require(data.get("format") == CONTRACT, "unsupported_snapshot_contract")
        self.source = self.data.get("source", {})
        self.scope = self.data.get("scope", {})
        require(isinstance(self.source, dict) and isinstance(self.scope, dict), "invalid_metadata")
        for field in ("namespace", "stream_key", "keys_fingerprint", "runtime_sha256",
                      "catalog_fingerprint", "semantic_schema", "catalog_status",
                      "semantic_state", "maintenance", "evidence_mode", "source_finality"):
            require(text_value(self.source.get(field)), "invalid_source_field:" + field)
        for field in ("sequence", "generation", "semantic_generation", "captured_at_ns"):
            require(integer(self.source.get(field), 1 if field == "sequence" else 0),
                    "invalid_source_integer:" + field)
        require(self.source.get("consistent_snapshot") is True, "inconsistent_snapshot")
        require(self.source.get("global_origin_versions_complete") is True, "global_origin_version_scope_incomplete")
        require(self.scope.get("complete") is True, "incomplete_scope")
        require(type(self.scope.get("population_complete", False)) is bool, "invalid_population_completeness")
        require(text_value(self.scope.get("id")), "invalid_scope_id")
        keys = self.scope.get("request_keys")
        require(isinstance(keys, list) and len(keys) <= MAX_REQUESTS, "request_scope_budget_exceeded")
        require(all(isinstance(key, str) and KEY.fullmatch(key) for key in keys), "invalid_request_key")
        require(len(keys) == len(set(keys)), "duplicate_scope_request")
        self.keys = set(keys)
        self.scope["request_keys"] = sorted(keys)
        intervals = self.scope.get("complete_intervals_ns")
        require(isinstance(intervals, list) and len(intervals) <= 1000, "invalid_coverage")
        for pair in intervals:
            require(isinstance(pair, list) and len(pair) == 2 and
                    all(integer(v) for v in pair) and pair[0] < pair[1], "invalid_coverage_interval")
        self.scope["complete_intervals_ns"] = sorted(intervals)
        self.tables = self.data.get("tables", {})
        require(isinstance(self.tables, dict) and set(self.tables) == set(TABLES), "invalid_table_contract")
        for name in TABLES:
            rows = self.tables[name]
            require(isinstance(rows, list) and len(rows) <= MAX_ROWS and
                    all(isinstance(row, dict) for row in rows), "table_budget_or_shape:" + name)
            self.tables[name] = sorted(rows, key=canonical)
            require(len({canonical(row) for row in rows}) == len(rows), "duplicate_row:" + name)
            if name not in ("viewer_events", "viewer_service_roles"):
                require(all(row.get("request_key") in self.keys for row in rows), "row_outside_scope:" + name)
        self.requests = self._indexed("viewer_requests", "request_key")
        self.occurrences = self._indexed("viewer_semantic_occurrences", "request_key")
        self.roles = self._indexed("viewer_service_roles", "service_path")
        self._indexed("viewer_events", ("origin_key", "version_key"))
        self._indexed("viewer_contract_edges", "edge_key")
        self._indexed("viewer_contract_observations", ("origin_key", "version_key", "axis", "value", "field_path"))
        self._indexed("viewer_contract_identifiers", ("origin_key", "version_key", "issuer", "kind", "scope", "field_path", "identity_key"))
        self.origins = {}
        for event in self.tables["viewer_events"]:
            require(text_value(event.get("origin_key")) and text_value(event.get("version_key")), "invalid_event_locator")
            require(type(event.get("raw_available")) is bool, "invalid_evidence_availability")
            self.origins.setdefault(event["origin_key"], {})[event["version_key"]] = event
        self._validate_occurrences()
        self.digest = digest(self.data)

    def _indexed(self, name, fields):
        fields = (fields,) if isinstance(fields, str) else fields
        result = {}
        for row in self.tables[name]:
            require(all(field in row for field in fields), "missing_primary_key:" + name)
            require(all(isinstance(row[field], str) and len(row[field]) <= 4096 for field in fields),
                    "invalid_primary_key_type:" + name)
            key = tuple(row[field] for field in fields)
            require(key not in result, "duplicate_primary_key:" + name)
            result[key] = row
        return {key[0]: row for key, row in result.items()} if len(fields) == 1 else result

    def _validate_occurrences(self):
        anchors = set()
        for request_key, row in self.occurrences.items():
            anchor = row.get("anchor_key")
            require(isinstance(anchor, str) and anchor.startswith("ba1:") and
                    KEY.fullmatch(anchor[4:]), "invalid_anchor")
            require(anchor not in anchors, "duplicate_anchor")
            anchors.add(anchor)
            require(row.get("state") in ("active", "withdrawn"), "invalid_semantic_state")
            require(row.get("kind") in KINDS and integer(row.get("revision"), 1), "invalid_semantic_revision_or_kind")
            require(integer(row.get("anchor_ns")), "invalid_anchor_time")
            require(text_value(row.get("occurrence_key")) and row["occurrence_key"].startswith("bo1:") and
                    KEY.fullmatch(row["occurrence_key"][4:]), "invalid_occurrence_key")
            if row["state"] == "active":
                request = self.requests.get(request_key)
                require(request is not None and request.get("conflicted") in (0, False), "active_identity_conflict")
                require(request.get("identity_state") == "assigned" and
                        isinstance(row.get("session_key"), str) and KEY.fullmatch(row["session_key"]) and
                        request.get("session_key") == row["session_key"], "active_identity_not_assigned")

    @property
    def deferred_reasons(self):
        reasons = []
        for field, expected in (("runtime_sha256", SOURCE_SHA), ("catalog_fingerprint", CATALOG_SHA),
                                ("semantic_schema", SEMANTIC_SCHEMA), ("catalog_status", "CURRENT"),
                                ("semantic_state", "ready")):
            if self.source[field] != expected:
                reasons.append("source_not_ready:" + field)
        if self.source["maintenance"] not in ("CLEAR", "OFFLINE_FIXTURE"):
            reasons.append("maintenance_not_cleared")
        if self.source["evidence_mode"] not in ("synthetic_contract", "offline_sqlite_copy", "postgresql_readonly_snapshot"):
            reasons.append("unsupported_evidence_mode")
        return reasons

    @property
    def source_active_anchors(self):
        return sorted(row["anchor_key"] for row in self.occurrences.values() if row["state"] == "active")

    def _evidence(self, origin, version):
        versions = self.origins.get(origin, {})
        event = versions.get(version)
        return dict(origin_key=origin, version_key=version,
                    qualified=len(versions) == 1 and event is not None,
                    origin_version_count=len(versions),
                    raw_available=bool(event and event["raw_available"]))

    def facts(self):
        """Semantic rows determine identity/counts; enrichment never creates an anchor."""
        result = []
        for key, occurrence in self.occurrences.items():
            request = self.requests.get(key, {})
            service = api_path(occurrence.get("root_call"))
            bucket = occurrence["anchor_ns"] // FIVE_NS * FIVE_NS
            covered = bucket_is_covered(bucket, self.scope["complete_intervals_ns"])
            events = [e for e in self.tables["viewer_events"] if e.get("request_key") == key]
            locators = [self._evidence(e["origin_key"], e["version_key"]) |
                        {"field_path": "", "callpath": e.get("callpath"), "at_ns": e.get("at_ns")}
                        for e in events]
            observations = []
            for row in self.tables["viewer_contract_observations"]:
                if row["request_key"] == key:
                    observations.append(deepcopy(row) | self._evidence(row["origin_key"], row["version_key"]))
            edges = []
            for row in self.tables["viewer_contract_edges"]:
                if row["request_key"] == key:
                    evidence = self._evidence(row["evidence_origin"], row["evidence_version"])
                    edges.append(deepcopy(row) | {"evidence_quality": evidence,
                                 "usable": row.get("eligibility") == "eligible" and evidence["qualified"]})
            identifiers = [deepcopy(row) | {"evidence_quality": self._evidence(row["origin_key"], row["version_key"])}
                           for row in self.tables["viewer_contract_identifiers"] if row["request_key"] == key]
            # Keep every axis/value and its evidence. No success/failure reduction.
            axes = {}
            for observation in observations:
                if observation["qualified"]:
                    axes.setdefault(observation["axis"], set()).add(observation["value"])
            axes = {axis: {"values": sorted(values), "conflicting": len(values) > 1}
                    for axis, values in sorted(axes.items())}
            evidence_complete = bool(locators) and all(item["qualified"] and item["raw_available"] for item in locators)
            valid_service = bool(service and service != "Services.v1/InvoiceRegister")
            quality = dict(identity_state=request.get("identity_state", "unavailable"),
                           conflicted=bool(request.get("conflicted", True)), bucket_fully_covered=covered,
                           evidence_available=evidence_complete, source_finality=self.source["source_finality"],
                           history_scope="declared_request_set_only", source_present=True,
                           population_complete=self.scope.get("population_complete", False),
                           learning_eligible=bool(occurrence["state"] == "active" and covered and evidence_complete and
                                                  valid_service and occurrence["anchor_ns"] > 0 and
                                                  self.scope.get("population_complete", False)))
            result.append(dict(anchor_key=occurrence["anchor_key"], request_key=key,
                               source_present=True, semantic=deepcopy(occurrence), service_path=service,
                               transport={field: request.get(field) for field in ("root_call", "root_code", "started_ns", "ended_ns")},
                               role=deepcopy(self.roles.get(service)), quality=quality,
                               outcomes=axes, observations=observations, relations=edges,
                               identifiers=identifiers, evidence=locators,
                               versions={"runtime_sha256": self.source["runtime_sha256"],
                                         "catalog_fingerprint": self.source["catalog_fingerprint"],
                                         "semantic_schema": self.source["semantic_schema"], "adapter": CONTRACT}))
        return sorted(result, key=lambda fact: fact["anchor_key"])

    def summary(self):
        return {"scope_requests": len(self.keys), "source_active_behaviors": len(self.source_active_anchors),
                "active_by_kind": dict(Counter(row["kind"] for row in self.occurrences.values() if row["state"] == "active")),
                "evidence_mode": self.source["evidence_mode"], "source_generation": self.source["generation"],
                "source_finality": self.source["source_finality"]}
