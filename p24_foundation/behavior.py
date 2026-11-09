"""Observed Session/service activity deviations against causal personal history.

Empirical ranks are descriptive, not calibrated false-positive probabilities.
Only active five-minute windows are comparable; absent traffic is not zero.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from fractions import Fraction
import hashlib
import re
import statistics
import uuid

from .errors import FoundationError
from .privacy import canonical
from .time import microsecond_cutoff

VERSION = "p24-session-service-volume.1"
MAX_REQUESTS = 100_000
MAX_REFERENCES = 128


def window(start, end, knowledge_at_ns, publication_id, summaries, *, route_token, source_scope="offline_selected_requests"):
    """Build one window from existing reconstructed logical-request summaries."""
    first, last = microsecond_cutoff(start).epoch_ns, microsecond_cutoff(end).epoch_ns
    if last - first != 300_000_000_000:
        raise FoundationError("behavior_requires_five_minute_window")
    if isinstance(knowledge_at_ns, bool) or not isinstance(knowledge_at_ns, int) or knowledge_at_ns < last:
        raise FoundationError("invalid_behavior_knowledge_cutoff")
    if len(summaries) > MAX_REQUESTS:
        raise FoundationError("behavior_request_limit")
    groups, skipped, seen = defaultdict(list), Counter(), set()
    for item in summaries:
        key = item["request_key"]
        token_pattern = r"[A-Za-z_]+:[A-Za-z0-9_-]+:[a-f0-9]{64}"
        if not isinstance(key, str) or not re.fullmatch(token_pattern, key):
            raise FoundationError("invalid_behavior_request_key")
        if key in seen:
            raise FoundationError("duplicate_behavior_request")
        seen.add(key)
        at = item.get("activity_time_ns")
        if isinstance(at, bool) or at is None:
            skipped["activity_time_unavailable"] += 1
            continue
        try:
            at = int(at)
        except (ValueError, TypeError):
            raise FoundationError("invalid_behavior_activity_time") from None
        if not first <= at < last:
            continue
        if (item.get("identity_state") != "known" or not item.get("session_key")
                or item.get("client_completion_state") != "observed"
                or item.get("distinct_client_request_count") != 1 or not item.get("endpoint")
                or item.get("ambiguous_event_count", 0)):
            skipped["identity_or_client_evidence_ineligible"] += 1
            continue
        if not re.fullmatch(token_pattern, item["session_key"]):
            raise FoundationError("invalid_behavior_session_key")
        groups[(item["session_key"], route_token(item["endpoint"]))].append(key)
    return dict(start_ns=first, end_ns=last, knowledge_at_ns=knowledge_at_ns,
        publication_id=str(uuid.UUID(str(publication_id))),
        source_scope=source_scope,
        groups={key: sorted(values) for key, values in groups.items()},
        excluded=dict(sorted(skipped.items())))


def score(target, references, *, rank_cutoff):
    """Score upper-tail activity within each Session/route's active-window history."""
    try:
        if not isinstance(rank_cutoff, str) or not re.fullmatch(r"(?:[0-9]{1,6}/[0-9]{1,6}|[01](?:\.[0-9]{1,6})?)", rank_cutoff):
            raise ValueError()
        cutoff = Fraction(rank_cutoff)
        if not 0 < cutoff < 1:
            raise ValueError()
    except (ValueError, ZeroDivisionError):
        raise FoundationError("invalid_behavior_rank_cutoff") from None
    if not 1 <= len(references) <= MAX_REFERENCES:
        raise FoundationError("behavior_reference_limit")
    minimum = (cutoff.denominator + cutoff.numerator - 1) // cutoff.numerator - 1
    references = sorted(references, key=lambda item: (item["start_ns"], item["end_ns"], item["publication_id"]))
    last_end, reference_requests, contaminated = None, {}, set()
    target_requests = {request: group for group, requests in target["groups"].items() for request in requests}
    if sum(len(values) for values in target["groups"].values()) > MAX_REQUESTS:
        raise FoundationError("behavior_request_limit")
    for ref in references:
        if ref["source_scope"] != target["source_scope"]:
            raise FoundationError("behavior_source_scope_mismatch")
        if ref["end_ns"] > target["start_ns"] or ref["knowledge_at_ns"] > target["knowledge_at_ns"]:
            raise FoundationError("behavior_future_reference")
        if last_end is not None and ref["start_ns"] < last_end:
            raise FoundationError("behavior_overlapping_reference_windows")
        last_end = ref["end_ns"]
        requests = {request: group for group, values in ref["groups"].items() for request in values}
        for request, group in requests.items():
            for prior in (reference_requests, target_requests):
                if request in prior:
                    contaminated.update((group, prior[request]))
        reference_requests.update(requests)
        if len(reference_requests) > MAX_REQUESTS:
            raise FoundationError("behavior_reference_request_limit")
    evaluations, candidates, reasons = [], [], Counter()
    for (session, service), requests in sorted(target["groups"].items()):
        history = [len(ref["groups"][(session, service)]) for ref in references if (session, service) in ref["groups"]]
        common = dict(session_key=session, service_key=service, target_requests=len(requests), reference_active_windows=len(history))
        if (session, service) in contaminated:
            evaluations.append(dict(**common, status="abstained", reason="overlapping_request_evidence"))
            reasons["overlapping_request_evidence"] += 1
            continue
        if len(history) < minimum:
            evaluations.append(dict(**common, status="abstained", reason="insufficient_personal_history"))
            reasons["insufficient_personal_history"] += 1
            continue
        count = len(requests)
        rank = Fraction(1 + sum(value >= count for value in history), 1 + len(history))
        median = statistics.median(history)
        candidate = rank <= cutoff and count > median
        result = dict(**common, status="candidate" if candidate else "within_reference",
            score_unit="empirical_upper_tail_rank", rank_numerator=rank.numerator,
            rank_denominator=rank.denominator, reference_median=median,
            reference_max=max(history), excess_over_median=count - median,
            target_support_sha256=hashlib.sha256(canonical(requests)).hexdigest(),
            sample_request_keys=requests[:3], sample_is_navigation_only=True)
        if candidate:
            result["explanation_fa"] = (f"در این بازهٔ پنج‌دقیقه‌ای {count} درخواست منطقی برای این نشست و مسیر ثبت شده است؛ "
                f"میانهٔ {len(history)} بازهٔ فعال قبلی همین نشست و مسیر {median:g} درخواست بوده است. "
                "این افزایش در شواهد مشاهده‌شده نیازمند بررسی است؛ علت، تقلب و اولویت از این اندازه‌گیری تعیین نمی‌شوند.")
            candidates.append(result)
        evaluations.append(result)
    manifest = dict(version=VERSION, target_publication_id=target["publication_id"],
        target_start_ns=str(target["start_ns"]), target_end_ns=str(target["end_ns"]),
        target_knowledge_at_ns=str(target["knowledge_at_ns"]),
        target_capture_snapshot_id=target.get("capture_snapshot_id"),
        source_scope_sha256=hashlib.sha256(canonical(target["source_scope"])).hexdigest(),
        target_groups_sha256=hashlib.sha256(canonical(sorted((list(key), values) for key, values in target["groups"].items()))).hexdigest(),
        references=[dict(publication_id=ref["publication_id"], start_ns=str(ref["start_ns"]),
            end_ns=str(ref["end_ns"]), knowledge_at_ns=str(ref["knowledge_at_ns"]),
            capture_snapshot_id=ref.get("capture_snapshot_id"),
            excluded_requests=ref["excluded"],
            groups_sha256=hashlib.sha256(canonical(sorted((list(key), values) for key, values in ref["groups"].items()))).hexdigest())
            for ref in references], rank_cutoff=str(cutoff))
    return dict(version=VERSION, evidence_manifest=manifest,
        evidence_manifest_sha256=hashlib.sha256(canonical(manifest)).hexdigest(),
        scope="observed_personal_session_route_active_windows", mode="historical_revised",
        evaluated_units=sum(item["status"] != "abstained" for item in evaluations),
        unsupported_units=sum(reasons.values()), reason_counts=dict(reasons),
        reference_resolution_required=minimum, candidates=candidates, evaluations=evaluations,
        excluded_target_requests=target["excluded"], calibrated_error_rate=False,
        fraud_verdict="not_established", priority="unrated", source_window_complete=False)


def publication_window(connection, namespace_id, publication_id, start, end, *, route_token):
    """Read one committed publication; the caller supplies a read-only transaction."""
    publication_id = uuid.UUID(str(publication_id))
    row = connection.execute("""SELECT p.input_manifest FROM p24_next.foundation_observation_publication p
        JOIN p24_next.foundation_observation_commit c USING(namespace_id,publication_id)
        WHERE p.namespace_id=%s AND p.publication_id=%s AND p.state='sealed'""",
        (namespace_id, publication_id)).fetchone()
    if row is None:
        raise FoundationError("behavior_publication_not_committed")
    manifest = row[0]
    if int(manifest["event_cutoff_ns"]) != microsecond_cutoff(end).epoch_ns:
        raise FoundationError("behavior_publication_cutoff_mismatch")
    sources = manifest["effective_sources"]
    if not 1 <= len(sources) <= 128:
        raise FoundationError("behavior_source_limit")
    scopes = connection.execute("""SELECT s.snapshot_id,s.window_key,m.coverage FROM p24_next.source_snapshot s
        JOIN p24_next.source_window w USING(namespace_id,window_key)
        JOIN p24_next.foundation_snapshot_metadata m USING(namespace_id,snapshot_id)
        WHERE s.namespace_id=%s AND s.snapshot_id=ANY(%s) AND w.window_start<%s AND w.window_end>%s""",
        (namespace_id, [uuid.UUID(str(value)) for value in sources], end, start)).fetchall()
    if len(scopes) != 1:
        raise FoundationError("behavior_comparable_capture_required")
    snapshot_id, source_key, coverage = scopes[0]
    acquisition = coverage.get("acquisition", {})
    if (not source_key.startswith("collector:") or not acquisition.get("query_traversal_complete")
            or not acquisition.get("window_scope_eligible") or acquisition.get("expected_slices") != 1
            or microsecond_cutoff(acquisition["declared_window_start"]).epoch_ns != microsecond_cutoff(start).epoch_ns
            or microsecond_cutoff(acquisition["declared_window_end"]).epoch_ns != microsecond_cutoff(end).epoch_ns):
        raise FoundationError("behavior_comparable_capture_required")
    source_scope = (source_key.rsplit(":", 2)[0], acquisition["index_pattern"], acquisition["contract_version"])
    rows = connection.execute("""SELECT s.summary FROM p24_next.foundation_observation_heads(%s,%s,NULL) h
        JOIN p24_next.foundation_request_summary s ON s.namespace_id=%s AND s.run_id=h.run_id AND s.request_key=h.request_key
        LIMIT %s""", (namespace_id, publication_id, namespace_id, MAX_REQUESTS + 1)).fetchall()
    result = window(start, end, int(manifest["knowledge_at_ns"]), publication_id,
                    [row[0] for row in rows], route_token=route_token, source_scope=source_scope)
    result["capture_snapshot_id"] = str(snapshot_id)
    return result
