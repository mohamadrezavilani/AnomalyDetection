"""Source-bound Session lifecycle observations on immutable request summaries."""
from collections import Counter

LIFECYCLE_VERSION = "p24-session-lifecycle.2r.1"
PROCEDURES = {
    "ud_prc_userSessionCreate": ("session_create", "اجرای رویهٔ ایجاد Session"),
    "ud_prc_oneTimePasswordGenerate": ("otp_generate", "اجرای رویهٔ تولید رمز یک‌بارمصرف"),
    "ud_prc_oneTimePasswordValidate": ("otp_validate", "اجرای رویهٔ بررسی رمز یک‌بارمصرف"),
    "ud_prc_oneTimePasswordConsume": ("otp_consume", "اجرای رویهٔ مصرف رمز یک‌بارمصرف"),
    "ud_prc_userSessionVerify": ("session_verify", "اجرای رویهٔ تأیید Session"),
}


def request_lifecycle(summary):
    """Describe co-observed phases; never infer accounts or a logout boundary.

    The input must be a selected immutable request summary. All markers cite
    the exact source observation and preserve its SQL execution outcome.
    """
    phase = (summary.get("classification") or {}).get("phase", "unknown")
    markers, seen = [], set()
    for operation in summary.get("operations", []):
        if operation.get("role") != "sql":
            continue
        procedure = (operation.get("endpoint") or "").rsplit(".", 1)[-1]
        definition = PROCEDURES.get(procedure)
        if not definition:
            continue
        identity = operation.get("event_key"), operation.get("event_version_id"), definition[0]
        if identity in seen:
            continue
        seen.add(identity)
        markers.append(dict(kind=definition[0], label_fa=definition[1],
            source_event_key=operation.get("event_key"), source_event_version_id=operation.get("event_version_id"),
            time_ns=operation.get("time_ns"), sql_execution_outcome=operation.get("outcome", "unknown"),
            evidence_basis="selected_same_request_sql_observation", request_key=summary["request_key"]))
    markers.sort(key=lambda row: (int(row["time_ns"]) if row["time_ns"] is not None else 10**40,
                                 row["source_event_key"] or "", row["source_event_version_id"] or ""))
    times = Counter(row["time_ns"] for row in markers if row["time_ns"] is not None)
    for row in markers:
        row["timestamp_tied"] = row["time_ns"] is not None and times[row["time_ns"]] > 1
    all_counts = Counter(row["kind"] for row in markers)
    successes = Counter(row["kind"] for row in markers if row["sql_execution_outcome"] == "success")
    verification_chain = all(successes[name] for name in ("otp_validate", "otp_consume", "session_verify"))
    identity = summary.get("identity_state", "missing")
    coverage = "ambiguous_source_evidence" if summary.get("ambiguous_event_count", 0) else "observed_only"
    if identity == "conflicting":
        flow = "conflicting_session_identity"
    elif coverage == "ambiguous_source_evidence":
        flow = "conflicting_source_observations"
    elif all_counts["otp_generate"] and verification_chain:
        flow = "generation_and_verification_co_observed"
    elif verification_chain:
        flow = "verification_sql_chain_observed"
    elif all_counts["otp_generate"]:
        flow = "otp_generation_procedure_observed"
    elif all_counts["session_create"]:
        flow = "session_creation_procedure_observed"
    elif markers:
        flow = "partial_security_observations"
    else:
        flow = "no_reviewed_lifecycle_marker"
    return dict(version=LIFECYCLE_VERSION, phase_observation=phase,
                procedure_observations=dict(all_counts), successful_sql_executions=dict(successes),
                sql_otp_verification_chain_observed=verification_chain, flow_evidence_state=flow,
                authentication_state="not_established", account_binding="not_available",
                logout_boundary="not_observed", source_coverage=coverage, markers=markers,
                session_assignment_state=identity, assigned_session_key=summary.get("session_key") if identity == "known" else None,
                observed_client_result=summary.get("final_outcome", "unknown"),
                basis="selected_request_phase_and_source_bound_sql_observations",
                order_basis="source_timestamps; ties_and_same_RequestID_do_not_prove_causality")
