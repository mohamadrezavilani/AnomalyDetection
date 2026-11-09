"""Pure deterministic reconstruction of selected evidence, independent of DB I/O."""
from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import defaultdict

from .time import parse_time, compatible_times

RESOLVER_VERSION = "p24-resolver.2b.1"

def select_events(events, cutoff_ns):
    """Input versions are already restricted to selected, knowledge-eligible sources.

    Select a compatible most-precise representation before applying event
    cutoff. Conflicting original versions never get a last-arrival winner.
    """
    by_key = defaultdict(list)
    for event in events:
        by_key[event["event_key"]].append(event)
    selected, ambiguous, unavailable = [], [], []
    for key, variants in sorted(by_key.items()):
        relevant = [v for v in variants if v["payload"]["descriptor"]["source_time"] is not None]
        if not relevant:
            unavailable.append(dict(event_key=key, reason="unknown_source_time", variants=variants))
            continue
        signatures = {v["payload"]["facts_signature"] for v in variants}
        times = [parse_time(v["payload"]["raw_time"]) for v in relevant]
        if len(signatures) != 1 or len(relevant) != len(variants) or any(not compatible_times(times[0], t) for t in times[1:]):
            # A wholly future origin must not create an earlier request projection.
            if any(t.epoch_ns < cutoff_ns for t in times):
                ambiguous.append(dict(event_key=key, reason="conflicting_origin_variants", variants=variants))
            continue
        best = sorted(relevant, key=lambda v: (
            -v["payload"]["descriptor"]["source_time"]["fraction_digits"],
            v["payload"]["descriptor"]["time_basis"] != "source", v.get("content_digest", ""), str(v["event_version_id"])))
        chosen = best[0]
        if int(chosen["payload"]["descriptor"]["source_time"]["epoch_ns"]) < cutoff_ns:
            selected.append(chosen)
    return dict(selected=selected, ambiguous=ambiguous, unavailable=unavailable)

def candidate_classification(endpoint, rows):
    if not endpoint:
        return dict(phase="unknown", activity_group="unknown", security_relevant=False, state="unknown")
    action = endpoint.split(".", 1)[-1]
    if action in {"v1/DeviceRegister", "v2/DeviceRegister"}:
        phase, group, security = "session_establishment", "security", True
    elif action in {"v1/ConfigBasic", "v1/UserQuickAccessItems", "v1/UserBasketGetItemCount"}:
        phase, group, security = "application_support", "application_support", False
    elif action == "v1/LoginByOTP":
        paths = {r["payload"]["descriptor"]["endpoint"] for r in rows}
        generation = any(p and p.endswith("ud_prc_oneTimePasswordGenerate") for p in paths)
        verification = any(p and p.endswith(("ud_prc_oneTimePasswordValidate", "ud_prc_oneTimePasswordConsume", "ud_prc_userSessionVerify")) for p in paths)
        phase = "otp_generation" if generation and not verification else "otp_verification" if verification and not generation else "context_dependent"
        group, security = "security", True
    elif action == "v1/LoginByUserCredential":
        phase, group, security = "credential_authentication", "security", True
    elif endpoint == "Services.v3/ElectricBillsExport":
        phase, group, security = "direct_inquiry", "business_candidate", False
    else:
        return dict(phase="unknown", activity_group="unknown", security_relevant=False, state="unknown")
    return dict(phase=phase, activity_group=group, security_relevant=security, state="candidate")

def reconstruct(selection):
    groups, ambiguous_groups = defaultdict(list), defaultdict(list)
    for event in selection["selected"]:
        request = event["payload"]["descriptor"]["request_key"]
        if request:
            groups[request].append(event)
    for item in selection["ambiguous"]:
        for request in {v["payload"]["descriptor"]["request_key"] for v in item["variants"]} - {None}:
            ambiguous_groups[request].append(item["event_key"])
    summaries = []
    for request in sorted(set(groups) | set(ambiguous_groups)):
        rows = sorted(groups[request], key=lambda e: (int(e["payload"]["descriptor"]["source_time"]["epoch_ns"]), e["event_key"]))
        ds = [r["payload"]["descriptor"] for r in rows]
        sessions = sorted({s for d in ds for s in d["session_candidates"]})
        conflict = any(d["identity_conflict"] for d in ds) or len(sessions) > 1
        identities = "conflicting" if conflict else "known" if sessions else "missing"
        completions = [r for r in rows if r["payload"]["descriptor"]["event_kind"] == "client_completion"]
        state = "observed" if len(completions) == 1 else "conflicting" if completions else "not_observed"
        client = completions[0] if state == "observed" else None
        descriptor = client["payload"]["descriptor"] if client else None
        outcome = descriptor["operation_outcome"] if descriptor else "conflicting" if completions else "unknown"
        code = next((o["code"] for o in descriptor["outcomes"] if o["layer"] == "platform_log"), None) if descriptor else None
        classification = candidate_classification(descriptor["endpoint"] if descriptor else None, rows)
        times = [int(d["source_time"]["epoch_ns"]) for d in ds]
        # This is the literal route parameter recorded by the access-check
        # procedure. It is useful caller context, not an authoritative service
        # mapping or proof that the target operation ran.
        access_actions = defaultdict(int)
        for d in ds:
            if (d["role"] == "sql" and
                    (d["endpoint"] or "").rsplit(".", 1)[-1] == "ud_prc_userSessionHasAccess" and
                    d.get("caller_sql_action")):
                access_actions[d["caller_sql_action"]] += 1
        ranked_actions = sorted(access_actions.items(), key=lambda item: (-item[1], item[0]))
        action_limit = 20
        summary = dict(request_key=request, identity_state=identities,
                       session_key=sessions[0] if identities == "known" else None,
                       session_candidates=sessions, selected_event_count=len(rows),
                       ambiguous_event_count=len(set(ambiguous_groups[request])),
                       origin_identity_ambiguous_count=sum(r["identity_kind"] != "origin_document" for r in rows),
                       observed_client_completion_rows=len(completions), distinct_client_request_count=int(bool(completions)),
                       client_completion_state=state, client_event_version_id=str(client["event_version_id"]) if client else None,
                       endpoint=descriptor["endpoint"] if descriptor else None,
                       final_outcome=outcome, outcome_code=code,
                       client_duration_ms=descriptor["duration_ms"] if descriptor else None,
                       sql_observation_count=sum(d["role"] == "sql" for d in ds),
                       provider_observation_count=sum(d["role"] == "provider" for d in ds),
                       unknown_role_count=sum(d["role"] == "unknown" for d in ds),
                       ip_keys=sorted({d["ip_key"] for d in ds if d["ip_key"]}),
                       client_contexts=sorted({d["client_context_key"] for d in ds if d["client_context_key"]}),
                       first_time_ns=str(min(times)) if times else None,
                       last_time_ns=str(max(times)) if times else None,
                       activity_time_ns=(descriptor["source_time"]["epoch_ns"] if descriptor else str(min(times)) if times else None),
                       classification=classification, initiation="unknown", source_coverage="observed_only",
                       access_check_actions=[dict(value=value, sql_observations=count,
                                                  evidence_basis="ud_prc_userSessionHasAccess.SQL.Parameters.action",
                                                  mapping_state="unverified_call_context")
                                             for value, count in ranked_actions[:action_limit]],
                       access_check_action_observations=sum(access_actions.values()),
                       access_check_action_omitted_distinct=max(0, len(ranked_actions)-action_limit),
                       timing_order="timestamps_only; ties_do_not_establish_causality",
                       outcomes=[dict(event_key=r["event_key"], observation=o) for r in rows for o in r["payload"]["descriptor"]["outcomes"]],
                       operations=[dict(event_key=r["event_key"], event_version_id=str(r["event_version_id"]),
                                        endpoint=r["payload"]["descriptor"]["endpoint"], role=r["payload"]["descriptor"]["role"],
                                        outcome=r["payload"]["descriptor"]["operation_outcome"],
                                        time_ns=r["payload"]["descriptor"]["source_time"]["epoch_ns"],
                                        identity_basis="unresolved_observation")
                                   for r in rows if r["payload"]["descriptor"]["event_kind"] != "client_completion"])
        summaries.append(summary)
    return summaries

def registration_candidates(summaries, *, horizon_seconds=300, limit_per_registration=1000):
    """Bounded search context, never a detector threshold or identity assignment."""
    by_ip = defaultdict(list)
    for summary in summaries:
        if summary["identity_state"] == "known" and summary["activity_time_ns"] is not None:
            for ip in summary["ip_keys"]:
                by_ip[ip].append((int(summary["activity_time_ns"]), summary["request_key"], summary))
    for entries in by_ip.values():
        entries.sort(key=lambda row: (row[0], row[1]))
    result, truncated = [], []
    for registration in summaries:
        if registration["classification"]["phase"] != "session_establishment" or registration["identity_state"] != "missing" or registration["activity_time_ns"] is None:
            continue
        start = int(registration["activity_time_ns"])
        candidates = {}
        for ip in registration["ip_keys"]:
            entries = by_ip.get(ip, [])
            times = [entry[0] for entry in entries]
            left, right = bisect_left(times, start), bisect_right(times, start + horizon_seconds * 1_000_000_000)
            for at, _, other in entries[left:right]:
                key = other["session_key"]
                if key not in candidates:
                    candidates[key] = dict(registration_request_key=registration["request_key"], session_key=key,
                        support_request_key=other["request_key"],
                        basis=dict(state="inferred_candidate", same_ip=True,
                                   same_parsed_client_context=bool(set(registration["client_contexts"]) & set(other["client_contexts"])),
                                   elapsed_ns=str(at - start), search_horizon_seconds=horizon_seconds,
                                   verified_session_issuance=False, policy_version="ip_context_candidates.2a.1"))
        ordered = sorted(candidates.values(), key=lambda c: (int(c["basis"]["elapsed_ns"]), c["session_key"]))
        if len(ordered) > limit_per_registration:
            truncated.append(registration["request_key"])
        result.extend(ordered[:limit_per_registration])
    return result, truncated

