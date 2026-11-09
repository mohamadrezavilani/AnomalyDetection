"""Deterministic Persian incident briefs from pinned, typed evidence only."""
from __future__ import annotations

VERSION = "p24-persian-incident-brief.3"
MAX_SAMPLE_REQUESTS = 3


def _as_ns(value):
    if isinstance(value,bool) or not isinstance(value,(int,str)):
        return None
    try:
        return int(value)
    except (TypeError,ValueError,OverflowError):
        return None


def _request_order(item):
    key=item.get("request_key","")
    value=_as_ns(item.get("first_event_ns"))
    return (0,value,key) if value is not None else (1,0,key)


def build_incident_brief(saved, *, is_latest_revision):
    """Build a compact, source-bound brief without inventing service semantics.

    Request identifiers are used only as opaque application keys for internal
    navigation. The brief contains aggregate counts and a small linked sample.
    """
    result=saved["result"]
    # A bad optional timestamp must not take down the incident page. Keep only
    # linkable rows and collapse duplicate keys deterministically.
    by_key={}
    for row in result.get("requests",[]):
        if not isinstance(row,dict):
            continue
        key=row.get("request_key")
        if not isinstance(key,str) or not key:
            continue
        prior=by_key.get(key)
        if prior is None or _request_order(row)<_request_order(prior):
            by_key[key]=row
    requests=sorted(by_key.values(),key=_request_order)
    # Select a small spread across the available support set, without claiming
    # that the chosen rows are statistically representative.
    if len(requests)<=MAX_SAMPLE_REQUESTS:
        selected=requests
    else:
        selected=[requests[0],requests[(len(requests)-1)//2],requests[-1]]
    first=result.get("first_event_ns")
    last=result.get("last_event_ns")
    first_ns,last_ns=_as_ns(first),_as_ns(last)
    elapsed_span_ns=last_ns-first_ns if first_ns is not None and last_ns is not None else None
    if elapsed_span_ns is not None and elapsed_span_ns<0:
        elapsed_span_ns=None
    excluded_reasons={}
    for finding in result.get("excluded_findings",[]):
        reason=finding.get("reason") if isinstance(finding,dict) else None
        reason=reason if isinstance(reason,str) and reason else "unspecified"
        excluded_reasons[reason]=excluded_reasons.get(reason,0)+1
    brief = {
        "version":VERSION,
        "incident_id":saved["incident_id"],
        "revision_id":saved["revision_id"],
        "publication_id":result["publication_id"],
        "revision_state":"latest" if is_latest_revision else "historical",
        "pattern_key":result["pattern_key"],
        "scope_kind":result["scope_kind"],
        "failure_family":result.get("failure_family"),
        "supported_requests":result["distinct_supported_requests"],
        "client_http_requests":result["distinct_client_http_requests"],
        "occurrences":result["occurrence_count"],
        "first_event_ns":first,
        "last_event_ns":last,
        "elapsed_span_ns":elapsed_span_ns,
        "active_findings":len(result.get("active_findings",[])),
        "excluded_findings":len(result.get("excluded_findings",[])),
        "excluded_finding_reasons":dict(sorted(excluded_reasons.items())),
        "coverage":result.get("coverage") or "پوشش شواهد در این نسخه مشخص نشده است.",
        "root_cause_state":result.get("root_cause","not_established"),
        "sample_requests":[dict(request_key=row["request_key"],first_event_ns=row.get("first_event_ns"),
                                 last_event_ns=row.get("last_event_ns")) for row in selected],
        "sample_request_count":len(selected),
        "sample_request_limit":MAX_SAMPLE_REQUESTS,
        "sample_selection_note":"نمونه‌ها فقط برای ناوبری به شواهد انتخاب شده‌اند و نمایندهٔ آماری کل نیستند.",
    }
    if result.get('behavior_evaluation_selection'):
        evaluations={row['behavior_evaluation_id']:row['behavior_observation']
            for row in result.get('active_findings',[]) if row.get('behavior_evaluation_id') and row.get('behavior_observation')}
        brief['behavior']={
            'evaluation_count':len(evaluations),
            'sample':[dict(evaluation_id=key,**value) for key,value in sorted(evaluations.items())[:3]],
            'sample_limit':3,
            'scope_note':'این یافته‌ها نامزدهای تجربیِ تغییر رفتار در شواهد مشاهده‌شده هستند؛ تقلب، علت و اولویت از آن‌ها تعیین نمی‌شود.'}
    return brief
