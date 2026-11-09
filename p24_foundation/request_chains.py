"""Sanitized per-RequestID operation-chain snapshots from bounded captures.

RequestID co-observation is a candidate link only. This module deliberately
does not infer causal execution, workflow completion, source completeness, or
service ownership from records that share a RequestID.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from pathlib import Path

from .errors import FoundationError

REQUEST_CHAIN_VERSION = "p24-request-chain-candidate.1"
_LOCATOR = re.compile(r"^[A-Za-z0-9_. -]{1,180}$")
_SAFE_ACTION = re.compile(r"^v\d+/[A-Za-z][A-Za-z0-9_]*$")


def _source_coverage(coverage):
    """Expose only allowlisted capture coverage facts, not source query data."""
    query_complete = coverage.get("query_complete") is True
    window_complete = coverage.get("source_window_complete") is True
    capture_status = "query_and_window_declared_complete" if query_complete and window_complete else "partial_or_unverified_capture"
    return {
        "input_format": coverage.get("input_format", "unknown"),
        "returned_record_count": int(coverage.get("returned_records", 0)),
        "source_query_complete": query_complete,
        "source_query_total_relation": coverage.get("query_total_relation", "unknown"),
        "source_window_complete": window_complete,
        "capture_coverage_status": capture_status,
        "source_finality": "not_established",
        "time_coverage": coverage.get("source_time_coverage", "unknown"),
    }


def _public_outcomes(descriptor):
    result = []
    for item in descriptor.get("outcomes", []):
        if not isinstance(item, dict):
            continue
        code = item.get("code")
        layer = item.get("layer")
        role = item.get("role")
        outcome = item.get("outcome")
        symbol = item.get("symbol")
        result.append({
            "code": str(code) if code is not None else None,
            "evidence_layer": layer if isinstance(layer, str) else "unknown",
            "operation_role": role if isinstance(role, str) else descriptor.get("role", "unknown"),
            "recorded_outcome": outcome if isinstance(outcome, str) else "unknown",
            "recorded_symbol": symbol if isinstance(symbol, str) else None,
        })
    return result


def _observation(event, order, tied):
    descriptor = event["payload"]["descriptor"]
    source_time = descriptor.get("source_time") or {}
    endpoint = descriptor.get("endpoint")
    action = descriptor.get("caller_sql_action")
    is_access_check = (descriptor.get("role") == "sql" and isinstance(endpoint, str)
                       and endpoint.rsplit(".", 1)[-1] == "ud_prc_userSessionHasAccess")
    return {
        "observed_order": order,
        "source_time_utc": source_time.get("floor_utc"),
        "source_time_precision": source_time.get("precision", "unknown"),
        "same_timestamp_tie": bool(tied),
        "operation_role": descriptor.get("role", "unknown"),
        "event_kind": descriptor.get("event_kind", "unknown"),
        "callpath": endpoint,
        "http_method": descriptor.get("method"),
        "duration_ms": descriptor.get("duration_ms"),
        "recorded_operation_outcome": descriptor.get("operation_outcome", "unknown"),
        "outcome_observations": _public_outcomes(descriptor),
        "access_check_action": action if is_access_check and isinstance(action, str) and _SAFE_ACTION.fullmatch(action) else None,
        "access_action_binding": "unverified_caller_context" if is_access_check and action else "not_observed",
        "request_link_basis": "same_request_id_co_observation_candidate",
    }


def _stable_event_key(event):
    """Order equal-time observations using only exported, non-sensitive facts."""
    descriptor = event["payload"]["descriptor"]
    outcomes = _public_outcomes(descriptor)
    return (
        int(descriptor.get("source_time", {}).get("epoch_ns", 0)),
        descriptor.get("endpoint") or "",
        descriptor.get("role") or "",
        descriptor.get("event_kind") or "",
        descriptor.get("method") or "",
        str(descriptor.get("duration_ms")) if descriptor.get("duration_ms") is not None else "",
        descriptor.get("operation_outcome") or "unknown",
        tuple((o["evidence_layer"], o["code"] or "", o["recorded_outcome"], o["recorded_symbol"] or "")
              for o in outcomes),
        descriptor.get("caller_sql_action") or "",
    )


def build_request_chain_candidates(data: bytes, *, locator: str, keys, namespace: str,
                                   catalog_path=None):
    """Build fixture-scoped chain candidates while withholding raw identities.

    Each output row is a RequestID projection within one input capture. The
    returned count must not be summed across overlapping captures.
    """
    if not isinstance(locator, str) or not _LOCATOR.fullmatch(locator):
        raise FoundationError("invalid_document_locator")
    from .intake import decode_batch
    from .parser import Semantics, normalize_event
    from .reconstruction import select_events

    batch = decode_batch(data)
    semantics = Semantics(catalog_path or Path(__file__).resolve().parents[1] / "catalogs/error_code_catalog.json")
    events, unresolved = [], 0
    for ordinal, record in enumerate(batch.records):
        try:
            event = normalize_event(record, keys, namespace, semantics,
                                    fallback_scope=locator, ordinal=ordinal)
            event["event_version_id"] = event["content_digest"]
            events.append(event)
        except FoundationError:
            unresolved += 1

    source_times = [int(event["payload"]["descriptor"]["source_time"]["epoch_ns"])
                    for event in events if event["payload"]["descriptor"].get("source_time")]
    # This cutoff means "after the latest timestamp in this capture" only; it
    # says nothing about records omitted from the capture or upstream finality.
    selection = (select_events(events, max(source_times) + 1)
                 if source_times else {"selected": [], "ambiguous": [], "unavailable": []})
    request_rows = defaultdict(list)
    request_ambiguous = defaultdict(set)
    unlinked_selected = 0
    for event in selection["selected"]:
        request_key = event["payload"]["descriptor"].get("request_key")
        if request_key:
            request_rows[request_key].append(event)
        else:
            unlinked_selected += 1
    for item in selection["ambiguous"]:
        for event in item.get("variants", []):
            request_key = event["payload"]["descriptor"].get("request_key")
            if request_key:
                request_ambiguous[request_key].add(item["event_key"])
    for item in selection["unavailable"]:
        for event in item.get("variants", []):
            request_key = event["payload"]["descriptor"].get("request_key")
            if request_key:
                request_ambiguous[request_key].add(item["event_key"])

    internal = []
    for request_key, rows in request_rows.items():
        rows.sort(key=_stable_event_key)
        descriptors = [event["payload"]["descriptor"] for event in rows]
        completions = [descriptor for descriptor in descriptors
                       if descriptor.get("event_kind") == "client_completion"]
        completion_state = ("observed" if len(completions) == 1 else
                            "conflicting" if len(completions) > 1 else "not_observed")
        client = completions[0] if completion_state == "observed" else None
        raw_actions = sorted({descriptor["caller_sql_action"] for descriptor in descriptors
                              if isinstance(descriptor.get("caller_sql_action"), str)
                              and _SAFE_ACTION.fullmatch(descriptor["caller_sql_action"])})
        times = [int(d["source_time"]["epoch_ns"]) for d in descriptors if d.get("source_time")]
        internal.append((request_key, rows, completion_state, client, raw_actions, times))
    internal.sort(key=lambda item: (
        min(item[5]) if item[5] else 2**63,
        item[3].get("endpoint", "") if item[3] else "",
        item[3].get("method", "") if item[3] else "",
        tuple(_stable_event_key(event) for event in item[1])))

    chains = []
    for number, (request_key, rows, completion_state, client, actions, times) in enumerate(internal, 1):
        observations = []
        previous_time = None
        for index, event in enumerate(rows, 1):
            ns = int(event["payload"]["descriptor"]["source_time"]["epoch_ns"])
            observations.append(_observation(event, index, ns == previous_time))
            previous_time = ns
        selected_descriptors = [r["payload"]["descriptor"] for r in rows]
        roles = defaultdict(int)
        for descriptor in selected_descriptors:
            roles[descriptor.get("role", "unknown")] += 1
        chains.append({
            "chain_ref": f"request_projection_{number:04d}",
            "client_http_completion_state": completion_state,
            "client_http_request_count": 1 if completion_state == "observed" else None,
            "client_http_completion_rows": sum(d.get("event_kind") == "client_completion" for d in selected_descriptors),
            "client_http_endpoint": client.get("endpoint") if client else None,
            "client_http_method": client.get("method") if client else None,
            "client_http_recorded_outcome": client.get("operation_outcome", "unknown") if client else "unknown",
            "client_http_outcome_observations": _public_outcomes(client) if client else [],
            "observed_access_check_actions": [
                {"value": action, "binding_state": "unverified_caller_context"}
                for action in actions
            ],
            "access_check_action_count": len(actions),
            "selected_observation_count": len(rows),
            "ambiguous_or_unavailable_observation_count": len(request_ambiguous[request_key]),
            "role_observation_counts": dict(sorted(roles.items())),
            "observation_order_basis": "source_timestamps_only_ties_do_not_establish_causality",
            "request_link_basis": "same_request_id_co_observation_candidate",
            "execution_or_workflow_finality_proven": False,
            "observations": observations,
        })

    coverage = _source_coverage(batch.coverage)
    return {
        "version": REQUEST_CHAIN_VERSION,
        "locator": locator,
        "source_sha256": hashlib.sha256(data).hexdigest(),
        "source_capture_scope": "input_capture_only_not_a_complete_source_window_claim",
        "coverage": coverage,
        "capture_finality": coverage["source_finality"],
        "source_record_count": len(batch.records),
        "normalized_record_count": len(events),
        "unresolved_record_count": unresolved,
        "selected_event_count": len(selection["selected"]),
        "ambiguous_origin_event_count": len(selection["ambiguous"]),
        "unavailable_time_event_count": len(selection["unavailable"]),
        "unlinked_selected_event_count": unlinked_selected,
        "request_projection_count": len(chains),
        "cross_source_request_union": "not_computed; captures may overlap",
        "chains": chains,
        "raw_request_ids_ip_session_sql_values_or_payloads_exported": False,
    }
