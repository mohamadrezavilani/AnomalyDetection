"""Bounded visits to candidate scopes with a durable descending rotation."""
from . import FIVE_NS
from .input_subjects import CONTRACTS,VERSION

INPUT_SERVICES="("+",".join("'"+service+"'" for service in sorted(CONTRACTS))+")"
STATE='candidate_audit_scope_v4'
VISIT_NS=60_000_000_000
FACT_SCOPE=("f.session_key=%s AND f.at_ns>=%s AND f.at_ns<%s AND f.eligible=TRUE "
            "AND f.source_present=TRUE AND f.state='active' AND f.next_audit_ns<=%s AND ")

def needed():
    return ("(f.details IS NULL OR f.details::jsonb->>'source_present' IS DISTINCT FROM 'true' "
        "OR f.details::jsonb->'quality'->>'evidence_available' IS DISTINCT FROM 'true' "
        "OR f.details::jsonb->'quality'->>'conflicted'='true' "
        "OR f.details::jsonb->'semantic'->>'state' IS DISTINCT FROM 'active' "
        "OR f.details::jsonb->'semantic'->>'revision' IS DISTINCT FROM f.revision::text "
        "OR f.details::jsonb->'semantic'->>'anchor_key' IS DISTINCT FROM f.anchor_key "
        "OR (f.service_path IN "+INPUT_SERVICES+" AND "
        "(f.details::jsonb->'input_subject'->>'version' IS DISTINCT FROM '"+VERSION+"' "
        "OR f.details::jsonb->'input_subject'->>'status'='READ_DEFERRED')))")


def due_requests(store,state,now,limit):
    session,target=state['session_key'],state['target_ns']
    rows=store.raw.execute('SELECT f.request_key FROM anomaly_detection.adp_facts f WHERE '+FACT_SCOPE+
        needed()+' ORDER BY f.next_audit_ns,f.request_key LIMIT %s',
        (session,target,target+FIVE_NS,now,limit)).fetchall()
    return [r['request_key'] for r in rows]


def keys(store,now,limit=1):
    state=store.state(STATE)
    if state and now<state['visit_until_ns']:
        current=due_requests(store,state,now,limit)
        if current:return current
    after=(state['target_ns'],state['session_key']) if state else None
    for cursor in ((after,None) if after else (None,)):
        fence='AND (s.target_ns,s.job_session)<(%s,%s) ' if cursor else ''
        # A prior canonical-rate finding is a hint to audit a supported
        # service. Evidence can be completed even after a partial audit
        # invalidates the rate version. Publication still requires a fresh job.
        row=store.raw.execute(
            "SELECT s.job_session,s.target_ns FROM anomaly_detection.adp_case_signals s "
            "WHERE s.source_kind='actor' AND s.state='ACTIVE' AND "
            "(s.review_eligible=TRUE OR (s.family='peer_service_rate_5m' AND (("
            "s.body::jsonb->>'baseline_unit'='canonical_service_executions' "
            "AND s.body::jsonb->>'service_path' IN "+INPUT_SERVICES+") OR EXISTS("
            "SELECT 1 FROM anomaly_detection.adp_jobs j WHERE j.session_key=s.job_session "
            "AND j.target_ns=s.target_ns AND j.primary_version=s.primary_version)))) "
            "AND EXISTS(SELECT 1 FROM anomaly_detection.adp_source_windows sw "
            "WHERE sw.start_ns=s.target_ns AND sw.complete=TRUE) "
            "AND EXISTS(SELECT 1 FROM anomaly_detection.adp_facts f WHERE f.session_key=s.job_session "
            "AND f.at_ns>=s.target_ns AND f.at_ns<s.target_ns+%s AND f.eligible=TRUE "
            "AND f.source_present=TRUE AND f.state='active' AND f.next_audit_ns<=%s AND "+needed()+") "+
            fence+"ORDER BY s.target_ns DESC,s.job_session DESC LIMIT 1",(FIVE_NS,now,*(cursor or ()))).fetchone()
        if row:
            state={'session_key':row['job_session'],'target_ns':row['target_ns'],'visit_until_ns':now+VISIT_NS}
            store.save_state(STATE,state)
            return due_requests(store,state,now,limit)
    if state:store.save_state(STATE,{})
    return []
