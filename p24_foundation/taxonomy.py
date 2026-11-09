"""Extract review candidates without copying request payloads or identities."""
from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

from .errors import FoundationError

TAXONOMY_IMPORT_VERSION = "p24-taxonomy-candidate.1"
ACTION_CROSSWALK_VERSION = "p24-action-crosswalk-candidate.1"
ACTION_API_RECONCILIATION_VERSION = "p24-action-api-reconciliation-candidate.1"
MAX_COLLECTION_BYTES = 16 * 1024 * 1024
HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
SAFE_LABEL = re.compile(r"^[A-Za-z0-9 _./():+-]{1,160}$")
SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9_.~-]{1,160}$")
VARIABLE = re.compile(r"\{\{[^{}]{1,80}\}\}")
UUID_SEGMENT = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


@dataclass(frozen=True)
class CandidateSource:
    locator: str
    content_sha256: str
    title: str
    source_kind: str
    mappings: tuple
    unresolved: tuple = ()


@dataclass(frozen=True)
class ObservedCandidateSource:
    locator: str
    content_sha256: str
    title: str
    source_kind: str
    mappings: tuple
    unresolved_record_count: int = 0


def _label(value):
    return value.strip() if isinstance(value, str) and SAFE_LABEL.fullmatch(value.strip()) else None


def _path_from_url(url):
    if isinstance(url, str):
        raw = url.strip()
        if not raw:
            return None, "missing_url", "unknown"
        if raw.startswith("{{"):
            suffix = raw[raw.find("}}") + 2:]
            if suffix and not suffix.startswith("/"):
                return None, "invalid_url", "collection_variable"
            path = urllib.parse.urlsplit("http://candidate.invalid" + (suffix or "/")).path
            origin_kind = "collection_variable"
        else:
            parsed = urllib.parse.urlsplit(raw)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                return None, "invalid_url", "unknown"
            path, origin_kind = parsed.path or "/", "literal_host"
    elif isinstance(url, dict):
        if isinstance(url.get("raw"), str) and url["raw"].strip():
            return _path_from_url(url["raw"])
        if not isinstance(url.get("path"), list):
            return None, "missing_url", "unknown"
        path = "/" + "/".join(str(x) for x in url["path"])
        host = url.get("host")
        origin_kind = "collection_variable" if isinstance(host, list) and any("{{" in str(x) for x in host) else "literal_host_or_path_only"
    else:
        return None, "missing_url", "unknown"
    safe, redacted = [], False
    for segment in urllib.parse.unquote(path).split("/"):
        if not segment:
            continue
        if VARIABLE.fullmatch(segment):
            safe.append(":param")
        elif segment in {".", ".."}:
            return None, "invalid_url", origin_kind
        elif SAFE_SEGMENT.fullmatch(segment) and not re.fullmatch(r"\d{5,}", segment) and not UUID_SEGMENT.fullmatch(segment):
            safe.append(segment)
        else:
            safe.append(":redacted")
            redacted = True
    return "/" + "/".join(safe), "redacted_path_segment" if redacted else "resolved", origin_kind


def postman_candidates(data: bytes, *, locator: str) -> CandidateSource:
    if not isinstance(data, bytes) or len(data) > MAX_COLLECTION_BYTES:
        raise FoundationError("postman_collection_size_limit")
    if not isinstance(locator, str) or not re.fullmatch(r"[A-Za-z0-9_. -]{1,180}", locator):
        raise FoundationError("invalid_document_locator")
    try:
        collection = json.loads(data.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise FoundationError("invalid_postman_collection") from None
    if not isinstance(collection, dict) or not isinstance(collection.get("item"), list):
        raise FoundationError("invalid_postman_collection")
    info = collection.get("info") if isinstance(collection.get("info"), dict) else {}
    title = _label(info.get("name")) or locator
    mappings, unresolved = [], []

    def walk(items, indexes=(), folders=()):
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            position = indexes + (index,)
            name = _label(item.get("name"))
            if isinstance(item.get("item"), list):
                walk(item["item"], position, folders + ((name,) if name else ()))
                continue
            request = item.get("request")
            if not isinstance(request, dict):
                continue
            raw_method = request.get("method")
            method = raw_method.upper() if isinstance(raw_method, str) and raw_method.upper() in HTTP_METHODS else None
            route, endpoint_state, origin_kind = _path_from_url(request.get("url"))
            # A real JSON pointer retains the repeated item keys for folders.
            pointer = "".join("/item/" + str(i) for i in position)
            row = dict(item_path=pointer, request_name=name, folder_path=list(folders), method=method,
                       exact_endpoint=route, endpoint_state=endpoint_state, origin_kind=origin_kind,
                       classification_state="unresolved")
            mappings.append(row)
            if route is None or method is None or endpoint_state != "resolved":
                unresolved.append(row)

    walk(collection["item"])
    return CandidateSource(locator, hashlib.sha256(data).hexdigest(), title, "postman_example",
                           tuple(mappings), tuple(unresolved))


def error_catalog_candidates(data: dict, *, locator="error_code_catalog.json"):
    if not isinstance(data, dict) or not isinstance(data.get("records"), list) or not isinstance(data.get("sources"), list):
        raise FoundationError("invalid_error_catalog")
    sources = {}
    for source in data["sources"]:
        if not isinstance(source, dict):
            raise FoundationError("invalid_error_catalog_source")
        system, digest, filename = source.get("code_system"), source.get("sha256"), source.get("file_name")
        if not all(isinstance(v, str) and v for v in (system, filename)) or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise FoundationError("invalid_error_catalog_source")
        sources[(system, filename)] = dict(content_sha256=digest, title=filename, locator=filename, source_kind="error_catalog")
    entries = []
    for row in data["records"]:
        if not isinstance(row, dict):
            raise FoundationError("invalid_error_catalog_entry")
        system, filename = row.get("code_system"), row.get("source_file")
        source = sources.get((system, filename))
        code, state = row.get("code"), row.get("definition_state")
        if source is None or not isinstance(code, str) or not code or state not in {
            "complete_definition", "partial_definition", "code_only", "reserved_marker"
        }:
            raise FoundationError("invalid_error_catalog_entry")
        entries.append(dict(
            code_system=system, code=code,
            user_message_fa=row.get("user_message_fa") if isinstance(row.get("user_message_fa"), str) and row.get("user_message_fa") else None,
            technical_symbol=row.get("log_symbol") if isinstance(row.get("log_symbol"), str) and row.get("log_symbol") else None,
            definition_state=state,
            meaning_authority="supplied_catalog_definition" if state in {"complete_definition", "partial_definition"} and (row.get("user_message_fa") or row.get("log_symbol")) else "no_definition_supplied",
            operation_binding_state="not_established_by_workbook", source_file=filename,
            source_sha256=source["content_sha256"], source_sheet=str(row.get("source_sheet") or "unknown"),
            source_row=int(row.get("source_row") or 1),
            source_cells=row.get("source_cells") if isinstance(row.get("source_cells"), dict) else {},
        ))
    return dict(locator=locator, records=tuple(entries), sources=sources)


def observed_callpath_candidates(data: bytes, *, locator: str, keys, namespace: str, catalog_path=None):
    from .intake import decode_batch
    from .parser import Semantics, normalize_event

    if not isinstance(locator, str) or not re.fullmatch(r"[A-Za-z0-9_. -]{1,180}", locator):
        raise FoundationError("invalid_document_locator")
    batch = decode_batch(data)
    semantics = Semantics(catalog_path or Path(__file__).resolve().parents[1] / "catalogs/error_code_catalog.json")
    groups, unresolved = {}, 0
    for ordinal, record in enumerate(batch.records):
        try:
            event = normalize_event(record, keys, namespace, semantics, fallback_scope=locator, ordinal=ordinal)
        except FoundationError:
            unresolved += 1
            continue
        descriptor = event["descriptor"]
        endpoint, role = descriptor.get("endpoint"), descriptor.get("role", "unknown")
        if not endpoint or role not in {"client_http", "sql", "internal", "provider", "cache", "background", "unknown"}:
            unresolved += 1
            continue
        method = descriptor.get("method") if role == "client_http" else None
        group = groups.setdefault((role, endpoint, method), dict(source_role=role, exact_endpoint=endpoint,
            method=method, logged_action=endpoint, event_count=0, request_keys=set(), event_kinds=set()))
        group["event_count"] += 1
        if descriptor.get("request_key"):
            group["request_keys"].add(descriptor["request_key"])
        if descriptor.get("event_kind"):
            group["event_kinds"].add(descriptor["event_kind"])
    mappings = tuple(dict(source_role=g["source_role"], exact_endpoint=g["exact_endpoint"],
        method=g["method"], logged_action=g["logged_action"], observed_event_count=g["event_count"],
        distinct_request_count=len(g["request_keys"]), event_kinds=sorted(g["event_kinds"]),
        endpoint_basis="CallPath") for g in groups.values())
    return ObservedCandidateSource(locator, hashlib.sha256(data).hexdigest(), locator, "retained_log", mappings, unresolved)


def observed_request_action_candidates(data: bytes, *, locator: str, keys, namespace: str, catalog_path=None):
    """Pair a unique Client HTTP endpoint with same-RequestID Access-check @action.

    These are co-observation candidates only. No endpoint/service meaning or
    successful target execution is inferred. Output contains no request, IP,
    Session, parameter or response-body values.
    """
    from collections import Counter, defaultdict
    from .intake import decode_batch
    from .parser import Semantics, normalize_event
    from .reconstruction import reconstruct, select_events

    if not isinstance(locator, str) or not re.fullmatch(r"[A-Za-z0-9_. -]{1,180}", locator):
        raise FoundationError("invalid_document_locator")
    batch = decode_batch(data)
    semantics = Semantics(catalog_path or Path(__file__).resolve().parents[1] / "catalogs/error_code_catalog.json")
    events, unresolved = [], 0
    for ordinal, record in enumerate(batch.records):
        try:
            event=normalize_event(record, keys, namespace, semantics, fallback_scope=locator, ordinal=ordinal)
            # Only an internal deterministic tie-breaker for source-version selection.
            event["event_version_id"]=event["content_digest"]
            events.append(event)
        except FoundationError:
            unresolved += 1
    source_times = [int(e["payload"]["descriptor"]["source_time"]["epoch_ns"])
                    for e in events if e["payload"]["descriptor"].get("source_time")]
    cutoff = max(source_times, default=0) + 1
    selection = select_events(events, cutoff) if events else dict(selected=[], ambiguous=[], unavailable=[])
    summaries = reconstruct(selection)
    pairs, ambiguous = {}, Counter()
    for summary in summaries:
        actions = summary.get("access_check_actions", [])
        if not actions:
            continue
        endpoint = summary.get("endpoint")
        if not endpoint:
            ambiguous["access_action_without_unique_client_endpoint"] += 1
            continue
        if len(actions) != 1:
            ambiguous["multiple_access_actions_in_request"] += 1
            continue
        action = actions[0]
        key = (endpoint, action["value"])
        item = pairs.setdefault(key, dict(client_http_endpoint=endpoint, access_check_action=action["value"],
            request_projections=0, distinct_client_http_requests=0, access_check_sql_observations=0,
            client_http_outcomes=dict(success=0, failure=0, unknown_or_conflicting=0)))
        item["request_projections"] += 1
        item["distinct_client_http_requests"] += int(summary.get("distinct_client_request_count", 0))
        item["access_check_sql_observations"] += int(action.get("sql_observations", 0))
        outcome = summary.get("final_outcome")
        bucket = outcome if outcome in {"success", "failure"} else "unknown_or_conflicting"
        item["client_http_outcomes"][bucket] += int(summary.get("distinct_client_request_count", 0))
    return dict(version=ACTION_CROSSWALK_VERSION, locator=locator,
        source_sha256=hashlib.sha256(data).hexdigest(), source_record_count=len(batch.records),
        normalized_record_count=len(events), unresolved_record_count=unresolved,
        unavailable_time_event_count=len(selection["unavailable"]),
        ambiguous_origin_event_count=len(selection["ambiguous"]),
        request_projections=len(summaries), pair_count=len(pairs),
        pairs=[dict(**pairs[k], mapping_state="same_request_co_observation_candidate",
                    mapping_authority="unverified", execution_proven="no") for k in sorted(pairs)],
        ambiguous_request_counts=dict(sorted(ambiguous.items())),
        semantic_classifications_inferred=False,
        raw_request_ids_ip_sessions_sql_parameters_and_payloads_exported=False)


def reconcile_action_candidates_with_postman(action_catalog, postman_catalog, conflict_catalog=None):
    """Compare observed Access-check strings to Postman paths without asserting authority."""
    items = postman_catalog.get("items", [])
    conflict_keys = set()
    if conflict_catalog:
        for conflict in conflict_catalog.get("conflicts", []):
            endpoint = conflict.get("endpoint")
            if isinstance(endpoint, str):
                conflict_keys.add(endpoint.rstrip("/").casefold())

    def route_suffix(endpoint):
        if not isinstance(endpoint, str):
            return None
        lower = endpoint.casefold()
        index = lower.find(".svc")
        if index < 0:
            return None
        return endpoint[index + 4:].lstrip("/").rstrip("/")

    def request_leaf(value):
        if not isinstance(value, str):
            return None
        return value.rstrip("/").rsplit("/", 1)[-1].casefold()

    reconciled = []
    for source in action_catalog.get("sources", []):
        pairs = []
        for pair in source.get("pairs", []):
            action = pair.get("access_check_action")
            suffix_matches = [item for item in items
                if route_suffix(item.get("endpoint")) is not None
                and route_suffix(item.get("endpoint")).casefold() == str(action or "").strip("/").casefold()]
            leaf_matches = [item for item in items
                if request_leaf(item.get("request_name")) == request_leaf(action)]
            if len(suffix_matches) == 1:
                state = "exact_documented_path_suffix_candidate"
                candidates = suffix_matches
            elif len(suffix_matches) > 1:
                state = "multiple_documented_path_suffix_candidates"
                candidates = suffix_matches
            elif leaf_matches:
                leaf_versions = sorted({
                    (route_suffix(item.get("endpoint")) or "").split("/", 1)[0]
                    for item in leaf_matches
                })
                if any((item.get("endpoint") or "").rstrip("/").casefold() in conflict_keys for item in leaf_matches):
                    state = "request_name_match_with_documented_route_conflict"
                elif len(leaf_versions) > 1 or (leaf_versions and leaf_versions[0] != str(action or "").strip("/").split("/", 1)[0].casefold()):
                    state = "request_name_match_version_or_path_unresolved"
                else:
                    state = "request_name_only_candidate"
                candidates = leaf_matches
            else:
                state = "no_literal_postman_candidate"
                candidates = []

            endpoint = pair.get("client_http_endpoint")
            observed_suffix = str(endpoint or "").split(".", 1)[1] if "." in str(endpoint or "") else None
            action_suffix = str(action or "").strip("/")
            relation = "same_suffix_candidate" if observed_suffix and observed_suffix.casefold() == action_suffix.casefold() else "endpoint_action_disagree_or_unparseable"
            pairs.append({
                "client_http_endpoint": endpoint,
                "access_check_action": action,
                "distinct_client_http_requests": pair.get("distinct_client_http_requests", 0),
                "endpoint_action_relation": relation,
                "postman_candidate_state": state,
                "postman_candidates": [
                    {"collection": item.get("collection"), "item_path": item.get("item_path"),
                     "request_name": item.get("request_name"), "method": item.get("method"),
                     "endpoint": item.get("endpoint"), "endpoint_state": item.get("endpoint_state")}
                    for item in candidates
                ],
                "authority": "candidate_only",
                "execution_proven": "no"
            })
        reconciled.append({"source": source.get("locator"), "source_sha256": source.get("source_sha256"),
            "pairs": pairs, "pair_count": len(pairs)})
    return {
        "version": ACTION_API_RECONCILIATION_VERSION,
        "status": "unpublished_candidate_reconciliation",
        "interpretation": "literal API route comparison only; Postman examples and same-RequestID observations do not establish runtime authority or target execution",
        "semantic_classifications_inferred": False,
        "source_counts_must_not_be_summed": action_catalog.get("source_counts_must_not_be_summed"),
        "sources": reconciled,
        "identity_values_or_payloads_exported": False
    }
