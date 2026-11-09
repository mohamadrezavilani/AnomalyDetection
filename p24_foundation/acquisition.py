"""Assess a bounded recorded scroll transcript without trusting its producer.

Exhausting an index view, source-window finality and authenticated producer
authority are separate claims. This module can check only the first from
caller-supplied request/response evidence.
"""
from __future__ import annotations

import hashlib
import re
from fnmatch import fnmatchcase

from .errors import FoundationError
from .privacy import canonical
from .time import microsecond_cutoff, parse_time

CAPTURE_VERSION = "p24-scroll-capture.1"
CAPTURE_MANIFEST_VERSION = "p24-capture-manifest.1"
MAX_SLICES = 32
MAX_ATTEMPTS = 3
MAX_PAGES = 2048
FAILURE_KINDS = {"none", "transport_timeout", "http_error", "cancelled", "decode_error"}


def _integer(value, low=0, high=2**63-1):
    return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high


def _time(value):
    try:
        return parse_time(value)
    except FoundationError:
        raise FoundationError("invalid_acquisition_time") from None


def _total(response):
    value = response.get("hits", {}).get("total")
    if isinstance(value, dict):
        n, relation = value.get("value"), value.get("relation")
    elif _integer(value):
        n, relation = value, "eq"
    elif value is None:
        return None, "unknown"
    else:
        raise FoundationError("invalid_acquisition_total")
    if not _integer(n) or not isinstance(relation, str) or relation not in {"eq", "gte"}:
        raise FoundationError("invalid_acquisition_total")
    return n, relation


def _source_time(hit):
    source = hit.get("_source") if isinstance(hit.get("_source"), dict) else {}
    value = source.get("@timestamp")
    if value is None:
        value = (hit.get("fields") or {}).get("@timestamp") if isinstance(hit.get("fields"), dict) else None
        if isinstance(value, list):
            value = value[0] if len(value) == 1 else None
    try:
        return parse_time(value)
    except FoundationError:
        return None


def _initial_request(attempt, header, start, end, slice_id, expected):
    """Check the retained request; header intent alone never verifies scope."""
    reasons, scope_issues = set(), set()
    initial = attempt.get("initial_request")
    if not isinstance(initial, dict):
        return {"initial_request_not_retained"}, {"unverified_query_scope"}, None
    body = initial.get("body")
    if initial.get("index") != header["index_pattern"]:
        reasons.add("initial_index_mismatch")
    if not isinstance(initial.get("scroll"), str) or not re.fullmatch(r"[1-9][0-9]{0,4}[smh]", initial["scroll"]):
        reasons.add("unverified_scroll_request")
    if not isinstance(body, dict):
        return reasons | {"initial_body_not_retained"}, {"unverified_query_scope"}, None
    if set(body) - {"query", "sort", "size", "_source", "slice", "track_total_hits"}:
        scope_issues.add("unverified_search_options")
    if body.get("sort") != ["_doc"] or body.get("_source") is not True or not _integer(body.get("size"), 1, 10000):
        reasons.add("unverified_scroll_request")
    partition = body.get("slice")
    valid_partition = (expected == 1 and partition is None) or (
        isinstance(partition, dict) and set(partition) == {"id", "max"}
        and _integer(partition["id"]) and _integer(partition["max"])
        and partition == {"id": slice_id, "max": expected})
    if not valid_partition:
        reasons.add("initial_slice_mismatch")
    query = body.get("query")
    filters = None
    if isinstance(query, dict) and set(query) == {"bool"} and isinstance(query["bool"], dict) and set(query["bool"]) == {"filter"}:
        filters = query["bool"]["filter"]
    if not isinstance(filters, list):
        return reasons, scope_issues | {"unverified_query_shape"}, hashlib.sha256(canonical(initial)).hexdigest()
    ranges, levels, other = [], [], []
    for item in filters:
        if isinstance(item, dict) and set(item) == {"range"} and isinstance(item["range"], dict) and set(item["range"]) == {"@timestamp"}:
            ranges.append(item["range"]["@timestamp"])
        elif isinstance(item, dict) and set(item) == {"terms"} and isinstance(item["terms"], dict) and set(item["terms"]) == {"level"}:
            levels.append(item["terms"]["level"])
        else:
            other.append(item)
    window_matches = False
    if len(ranges) == 1 and isinstance(ranges[0], dict) and set(ranges[0]) == {"gte", "lt"}:
        try:
            window_matches = (parse_time(ranges[0]["gte"]).epoch_ns, parse_time(ranges[0]["lt"]).epoch_ns) == (start.epoch_ns, end.epoch_ns)
        except FoundationError:
            pass
    if not window_matches:
        scope_issues.add("initial_time_bounds_mismatch")
    if levels or other:
        scope_issues.add("recorded_query_has_filters")
    declared = header["query"]
    if not levels and declared.get("level_filter") != [] or levels and (len(levels) != 1 or levels[0] != declared.get("level_filter")):
        scope_issues.add("declared_level_filter_mismatch")
    if declared["scope"] == "window_only" and (levels or other):
        scope_issues.add("declared_query_scope_mismatch")
    return reasons, scope_issues, hashlib.sha256(canonical(initial)).hexdigest()


def assess_scroll_capture(root, *, max_records):
    """Return selected-attempt rows and a safe, source-bound assessment.

    All attempts remain in the archived bytes. Only the latest attempt for
    each slice supplies selected rows, so restarting from page zero never
    concatenates two different scroll views.
    """
    header = root.get("acquisition")
    if not isinstance(header, dict) or header.get("version") != CAPTURE_VERSION:
        raise FoundationError("unsupported_acquisition_contract")
    try:
        start = microsecond_cutoff(header["window_start"])
        end = microsecond_cutoff(header["window_end"])
    except (KeyError, FoundationError):
        raise FoundationError("invalid_acquisition_window") from None
    if start.epoch_ns >= end.epoch_ns:
        raise FoundationError("invalid_acquisition_window")
    began, finished = _time(header.get("started_at")), _time(header.get("finished_at"))
    if began.epoch_ns > finished.epoch_ns:
        raise FoundationError("invalid_acquisition_clock_order")
    pattern = header.get("index_pattern")
    if not isinstance(pattern, str) or not re.fullmatch(r"[A-Za-z0-9_.?*,:-]{1,240}", pattern):
        raise FoundationError("invalid_acquisition_index_pattern")
    expected, budget = header.get("expected_slices"), header.get("attempt_budget")
    if not _integer(expected, 1, MAX_SLICES) or not _integer(budget, 1, MAX_ATTEMPTS):
        raise FoundationError("invalid_acquisition_bounds")
    query = header.get("query")
    if not isinstance(query, dict) or not isinstance(query.get("scope"), str) or query["scope"] not in {"window_only", "filtered"}:
        raise FoundationError("invalid_acquisition_query_scope")
    reasons, scope_issues = set(), set()
    if query.get("time_field") != "@timestamp" or query.get("range_mode") != "gte_lt":
        scope_issues.add("unverified_time_query")
    if query.get("scope") != "window_only":
        scope_issues.add("filtered_query_scope")
    if query.get("level_filter") != []:
        scope_issues.add("filtered_or_unspecified_levels")
    slices = root.get("slices")
    if not isinstance(slices, list) or len(slices) > MAX_SLICES:
        raise FoundationError("invalid_acquisition_slices")
    ids = [s.get("id") if isinstance(s, dict) else None for s in slices]
    if any(not _integer(i, 0, expected-1) for i in ids) or len(set(ids)) != len(ids):
        raise FoundationError("ambiguous_acquisition_slices")
    if set(ids) != set(range(expected)):
        reasons.add("missing_slice")
    rows, page_manifest, slice_manifest, attempt_manifest = [], [], [], []
    page_count = 0
    all_attempt_rows = 0
    seen = {}
    duplicate_origins = conflicts = missing_origins = outside = unknown_time = 0
    for part in sorted(slices, key=lambda x:x["id"]):
        attempts = part.get("attempts")
        if not isinstance(attempts, list) or not 1 <= len(attempts) <= budget:
            raise FoundationError("invalid_acquisition_attempts")
        numbers = [a.get("number") if isinstance(a, dict) else None for a in attempts]
        if numbers != list(range(1, len(attempts)+1)):
            raise FoundationError("noncontiguous_acquisition_attempts")
        # Bound ignored retries too, before selecting the final attempt.
        for attempt in attempts:
            kind = attempt.get("failure_kind", "none")
            if not isinstance(kind, str) or kind not in FAILURE_KINDS:
                raise FoundationError("invalid_acquisition_failure_kind")
            pages = attempt.get("pages")
            if not isinstance(pages, list):
                raise FoundationError("invalid_acquisition_pages")
            page_count += len(pages)
            if page_count > MAX_PAGES:
                raise FoundationError("acquisition_page_limit")
            for page in pages:
                response = page.get("response") if isinstance(page, dict) else None
                hits = response.get("hits", {}).get("hits") if isinstance(response, dict) and isinstance(response.get("hits"), dict) else None
                if not isinstance(hits, list) or not all(isinstance(h, dict) for h in hits):
                    raise FoundationError("invalid_acquisition_page_response")
                all_attempt_rows += len(hits)
                if all_attempt_rows > max_records:
                    raise FoundationError("record_count_limit")
            initial = attempt.get("initial_request")
            initial_digest = hashlib.sha256(canonical(initial)).hexdigest() if isinstance(initial, dict) else None
            attempt_manifest.append(dict(slice_id=part["id"], attempt=attempt["number"],
                selected=attempt is attempts[-1], failure_kind=kind,
                initial_request_sha256=initial_digest, page_count=len(pages),
                record_count=sum(len(p["response"]["hits"]["hits"]) for p in pages)))
            for fallback_position, page in enumerate(pages):
                response = page["response"]
                hits = response["hits"]["hits"]
                cursor_in = page.get("request_cursor")
                cursor_out = response.get("_scroll_id")
                try:
                    total_value, total_relation = _total(response)
                except FoundationError:
                    total_value, total_relation = None, "invalid"
                try:
                    received_claim = page.get("received_at")
                    if not isinstance(received_claim, str) or len(received_claim) > 128:
                        received_claim = None
                    else:
                        _time(received_claim)
                except FoundationError:
                    received_claim = None
                ordinal = page.get("ordinal")
                if not _integer(ordinal, 0, MAX_PAGES):
                    ordinal = None
                shards = response.get("_shards")
                shard_summary = {key: (shards.get(key) if isinstance(shards, dict) and _integer(shards.get(key)) else None)
                                 for key in ("total", "successful", "failed")}
                attempt_manifest[-1].setdefault("pages", []).append(dict(
                    page_ordinal=ordinal if ordinal is not None else fallback_position,
                    recorded_ordinal=ordinal,
                    selected=attempt is attempts[-1],
                    row_count=len(hits),
                    first_selected_row=None,
                    received_at_claim=received_claim,
                    request_cursor_sha256=hashlib.sha256(cursor_in.encode("utf-8")).hexdigest() if isinstance(cursor_in, str) else None,
                    response_cursor_sha256=hashlib.sha256(cursor_out.encode("utf-8")).hexdigest() if isinstance(cursor_out, str) else None,
                    response_sha256=hashlib.sha256(canonical(response)).hexdigest(),
                    timed_out=response.get("timed_out") if isinstance(response.get("timed_out"), bool) else None,
                    shards=shard_summary,
                    terminated_early=response.get("terminated_early") if isinstance(response.get("terminated_early"), bool) else None,
                    query_total=total_value, query_total_relation=total_relation))
        selected = attempts[-1]
        pages = selected["pages"]
        local, query_issues, initial_digest = _initial_request(selected, header, start, end, part["id"], expected)
        scope_issues.update(query_issues)
        if selected.get("failure_kind", "none") != "none":
            local.add("selected_attempt_failed")
        if not pages:
            local.add("no_pages")
        expected_cursor = None
        last_received = began.epoch_ns
        terminal = False
        slice_origins = set()
        totals = []
        for position,page in enumerate(pages):
            response = page["response"]
            hits = response["hits"]["hits"]
            if page.get("ordinal") != position or isinstance(page.get("ordinal"), bool):
                local.add("page_sequence_gap")
            request_cursor = page.get("request_cursor")
            if request_cursor is not None and (not isinstance(request_cursor, str) or len(request_cursor) > 65536):
                raise FoundationError("invalid_acquisition_cursor")
            if request_cursor != expected_cursor:
                local.add("cursor_chain_mismatch")
            received = _time(page.get("received_at")).epoch_ns
            if received < last_received or received > finished.epoch_ns:
                local.add("capture_clock_order")
            last_received = received
            if response.get("timed_out") is not False:
                local.add("timeout_or_missing_signal")
            shards = response.get("_shards")
            if not isinstance(shards, dict) or not all(_integer(shards.get(k)) for k in ("total","successful","failed")):
                local.add("missing_shard_evidence")
            elif shards["total"] < 1 or shards["failed"] != 0 or shards["successful"] != shards["total"]:
                local.add("incomplete_shards")
            if response.get("terminated_early") is True:
                local.add("terminated_early")
            total = _total(response)
            totals.append(total)
            if terminal:
                local.add("page_after_terminal")
            terminal = not hits
            first = len(rows)
            for hit in hits:
                origin = (hit.get("_index"),hit.get("_id"))
                if not all(isinstance(v,str) and v for v in origin):
                    missing_origins += 1
                else:
                    # Aliases, remote index selectors and exclusions need a
                    # resolved-index manifest before claiming window scope.
                    patterns = pattern.split(",")
                    if any(not p or p.startswith("-") or ":" in p for p in patterns) or not any(fnmatchcase(origin[0], p) for p in patterns):
                        scope_issues.add("index_resolution_not_established")
                    content = canonical(hit.get("_source") if isinstance(hit.get("_source"),dict) else hit)
                    if origin in seen:
                        duplicate_origins += 1
                        conflicts += int(seen[origin] != content)
                    seen.setdefault(origin,content)
                    slice_origins.add(origin)
                source_time = _source_time(hit)
                if source_time is None:
                    unknown_time += 1
                elif not start.epoch_ns <= source_time.epoch_ns < end.epoch_ns:
                    outside += 1
                rows.append(hit)
            page_manifest.append(dict(slice_id=part["id"],attempt=selected["number"],page_ordinal=position,
                first_selected_row=first,row_count=len(hits),terminal_empty_page=not hits,
                response_sha256=hashlib.sha256(canonical(response)).hexdigest(),
                received_at_claim=page["received_at"],query_total=total[0],query_total_relation=total[1]))
            cursor = response.get("_scroll_id")
            if hits:
                if not isinstance(cursor,str) or not cursor or len(cursor)>65536:
                    local.add("missing_scroll_cursor")
                    expected_cursor = None
                else:
                    expected_cursor = cursor
        if not terminal:
            local.add("no_terminal_empty_page")
        exact = {n for n,rel in totals if rel=="eq"}
        lower = [n for n,rel in totals if rel=="gte"]
        if len(exact)>1 or exact and next(iter(exact)) != len(slice_origins):
            local.add("exact_total_mismatch")
        if lower and max(lower)>len(slice_origins):
            local.add("lower_bound_exceeds_observed")
        reasons.update(local)
        for item in attempt_manifest:
            if item["slice_id"] == part["id"] and item["attempt"] == selected["number"]:
                selected_row = 0
                for page_detail in item.get("pages", []):
                    page_detail["first_selected_row"] = selected_row
                    selected_row += page_detail["row_count"]
        slice_manifest.append(dict(slice_id=part["id"],attempts_observed=len(attempts),selected_attempt=selected["number"],
            initial_request_sha256=initial_digest,
            attempts=[dict(number=a["number"],page_count=len(a["pages"]),
                           record_count=sum(len(p["response"]["hits"]["hits"]) for p in a["pages"]),
                           failure_kind=a.get("failure_kind", "none")) for a in attempts],
            selected_pages=len(pages),terminal_empty_page=terminal,traversal_consistent=not local,
            exact_total=next(iter(exact)) if len(exact)==1 else None,
            total_relation="eq" if exact else "gte" if lower else "unknown",issues=sorted(local)))
    if duplicate_origins:reasons.add("duplicate_origin_in_traversal")
    if conflicts:reasons.add("conflicting_origin_in_traversal")
    if missing_origins:reasons.add("missing_origin_identity")
    if outside:reasons.add("event_outside_declared_window")
    if unknown_time:reasons.add("unknown_event_time")
    manifest = dict(version=CAPTURE_MANIFEST_VERSION,contract_version=CAPTURE_VERSION,
        declared_window_start=header["window_start"],declared_window_end=header["window_end"],
        index_pattern=pattern,query_scope=query["scope"],time_field=query["time_field"],range_mode=query["range_mode"],
        capture_started_at_claim=header["started_at"],capture_finished_at_claim=header["finished_at"],
        expected_slices=expected,attempt_budget=budget,
        claims=dict(producer_authority="unverified",source_window_complete=False,source_finality="not_established"),
        attempts=attempt_manifest)
    manifest["sha256"] = hashlib.sha256(canonical(manifest)).hexdigest()
    assessment = dict(contract_version=CAPTURE_VERSION,source_claim_state="unverified_local_capture",
        query_traversal_complete=not reasons,source_window_complete=False,source_finality="not_established",
        window_scope_eligible=not scope_issues,scope_issues=sorted(scope_issues),
        snapshot_consistency="single_scroll_view" if expected==1 else "independent_slice_views",
        declared_window_start=header["window_start"],declared_window_end=header["window_end"],
        index_pattern=pattern,query_scope=query["scope"],capture_started_at_claim=header["started_at"],
        capture_finished_at_claim=header["finished_at"],expected_slices=expected,observed_slices=len(slices),
        attempt_budget=budget,all_attempt_page_count=page_count,all_attempt_record_count=all_attempt_rows,
        selected_record_count=len(rows),distinct_selected_origins=len(seen),
        duplicate_origin_rows=duplicate_origins,conflicting_origin_rows=conflicts,
        missing_origin_rows=missing_origins,event_time_unknown_rows=unknown_time,event_time_outside_rows=outside,
        issues=sorted(reasons),slices=slice_manifest,pages=page_manifest,capture_manifest=manifest,
        cursors_or_query_values_exposed=False)
    return rows, assessment
