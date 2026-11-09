"""Offline, source-bound error-code/operation co-observation candidates."""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path

from .errors import FoundationError
from .taxonomy import error_catalog_candidates

OBSERVED_CODE_RECONCILIATION_VERSION = "p24-observed-code-operation-candidate.1"
ERROR_CODE = re.compile(r"^[A-Za-z]{1,4}\d{3,6}$")


def observed_code_operation_candidates(data: bytes, *, locator: str, keys, namespace: str,
                                       code_catalog: dict, catalog_path=None):
    """Aggregate code observations by exact event role and RequestID context.

    The output records literal co-observation, not a semantic operation binding.
    Request, IP, Session, SQL parameter and response payload values are never
    exported. SQL execution return code ``1`` is intentionally out of scope;
    code-shaped platform/workflow/provider observations keep their own layers.
    """
    from .intake import decode_batch
    from .parser import Semantics, normalize_event

    if not isinstance(locator, str) or not re.fullmatch(r"[A-Za-z0-9_. -]{1,180}", locator):
        raise FoundationError("invalid_document_locator")
    batch = decode_batch(data)
    safe_catalog = error_catalog_candidates(code_catalog)
    by_code = defaultdict(list)
    for row in safe_catalog["records"]:
        by_code[row["code"]].append(row)
    semantics = Semantics(catalog_path or Path(__file__).resolve().parents[1] / "catalogs/error_code_catalog.json")

    events, unresolved = [], 0
    for ordinal, record in enumerate(batch.records):
        try:
            event = normalize_event(record, keys, namespace, semantics, fallback_scope=locator, ordinal=ordinal)
            event["event_version_id"] = event["content_digest"]
            events.append(event)
        except FoundationError:
            unresolved += 1

    requests = {}
    observations = []
    for event in events:
        descriptor = event["payload"]["descriptor"]
        request_key = descriptor.get("request_key")
        if not request_key:
            continue
        context = requests.setdefault(request_key, {"endpoints": set(), "actions": set()})
        if descriptor.get("role") == "client_http" and descriptor.get("endpoint"):
            context["endpoints"].add(descriptor["endpoint"])
        if descriptor.get("caller_sql_action"):
            context["actions"].add(descriptor["caller_sql_action"])
        for outcome in descriptor.get("outcomes", []):
            code = outcome.get("code")
            if not isinstance(code, str) or not ERROR_CODE.fullmatch(code):
                continue
            observations.append({
                "request_key": request_key,
                "operation_role": descriptor.get("role", "unknown"),
                "operation_callpath": descriptor.get("endpoint"),
                "code": code,
                "layer": outcome.get("layer", "unknown"),
                "recorded_outcome": outcome.get("outcome", "unknown"),
                "recorded_symbol": outcome.get("symbol"),
            })

    grouped = {}
    for observation in observations:
        key = (observation["operation_role"], observation["operation_callpath"], observation["code"],
               observation["layer"], observation["recorded_outcome"], observation["recorded_symbol"])
        item = grouped.setdefault(key, {"event_count": 0, "request_keys": set(), "contexts": defaultdict(set)})
        request_key = observation["request_key"]
        item["event_count"] += 1
        item["request_keys"].add(request_key)
        context = requests[request_key]
        item["contexts"][(tuple(sorted(context["endpoints"])), tuple(sorted(context["actions"])))].add(request_key)

    groups = []
    for key in sorted(grouped, key=lambda value: tuple("" if x is None else str(x) for x in value)):
        role, callpath, code, layer, recorded_outcome, symbol = key
        matches = by_code.get(code, [])
        symbol_matches = [row for row in matches if symbol and row.get("technical_symbol")
                          and str(symbol).strip().casefold() == str(row["technical_symbol"]).strip().casefold()]
        if not matches:
            state = "no_literal_codebook_entry"
        elif len(matches) == 1 and len(symbol_matches) == 1:
            state = "single_code_and_symbol_candidate"
        elif len(matches) == 1 and not symbol:
            state = "single_code_entry_symbol_unavailable"
        elif len(matches) == 1:
            state = "single_code_entry_symbol_disagrees"
        elif len(symbol_matches) == 1:
            state = "symbol_selects_one_candidate_but_code_system_unverified"
        else:
            state = "multiple_codebook_entries_unresolved"
        item = grouped[key]
        contexts = []
        for (endpoints, actions), request_keys in sorted(item["contexts"].items()):
            contexts.append({"client_http_endpoints": list(endpoints), "access_check_actions": list(actions),
                             "distinct_request_count": len(request_keys), "link_state":
                             "same_request_co_observation_candidate"})
        groups.append({
            "operation_role": role,
            "operation_callpath": callpath,
            "code": code,
            "evidence_layer": layer,
            "recorded_outcome": recorded_outcome,
            "recorded_symbol": symbol,
            "observed_event_count": item["event_count"],
            "distinct_request_count": len(item["request_keys"]),
            "codebook_candidate_state": state,
            "codebook_candidates": [{
                "code_system": row["code_system"], "source_file": row["source_file"],
                "source_sha256": row["source_sha256"], "source_sheet": row["source_sheet"],
                "source_row": row["source_row"], "definition_state": row["definition_state"],
                "technical_symbol": row["technical_symbol"],
                "symbol_matches_observation": row in symbol_matches,
                "operation_binding_state": row["operation_binding_state"],
            } for row in matches],
            "same_request_contexts": contexts,
            "semantic_authority": "unverified_candidate",
            "operation_binding_proven": "no",
        })

    return {
        "version": OBSERVED_CODE_RECONCILIATION_VERSION,
        "locator": locator,
        "source_sha256": hashlib.sha256(data).hexdigest(),
        "code_catalog_content_sha256": hashlib.sha256(json.dumps(code_catalog,ensure_ascii=False,sort_keys=True,
            separators=(",",":"),allow_nan=False).encode("utf-8")).hexdigest(),
        "code_catalog_source_files": [{"code_system": system, "source_file": filename,
            "source_sha256": source["content_sha256"]}
            for (system,filename),source in sorted(safe_catalog["sources"].items())],
        "source_record_count": len(batch.records),
        "normalized_record_count": len(events),
        "unresolved_record_count": unresolved,
        "code_observation_count": len(observations),
        "groups": groups,
        "group_count": len(groups),
        "code_systems_globally_assumed": False,
        "raw_request_ids_ips_sessions_parameters_or_payloads_exported": False,
    }
