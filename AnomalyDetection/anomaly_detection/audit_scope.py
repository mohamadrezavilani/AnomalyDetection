"""Bounded visits to candidate scopes with a durable descending rotation."""
from . import FIVE_NS
from .input_subjects import CONTRACTS,VERSION

INPUT_SERVICES="("+",".join("'"+service+"'" for service in sorted(CONTRACTS))+")"
STATE='candidate_audit_scope_v4'
VISIT_NS=60_000_000_000
PASS_STATE='candidate_audit_pass_v1'
PAGE_SIZE=32
FACT_SCOPE=("f.session_key=%s AND f.at_ns>=%s AND f.at_ns<%s "
            "AND (f.at_ns/300000000000)*300000000000=%s AND f.eligible=TRUE "
            "AND f.source_present=TRUE AND f.state='active' AND f.next_audit_ns<=%s AND ")

def needed(alias='f'):
    expression=("(f.details IS NULL OR f.details::jsonb->>'source_present' IS DISTINCT FROM 'true' "
        "OR f.details::jsonb->'quality'->>'evidence_available' IS DISTINCT FROM 'true' "
        "OR f.details::jsonb->'quality'->>'conflicted'='true' "
        "OR f.details::jsonb->'semantic'->>'state' IS DISTINCT FROM 'active' "
        "OR f.details::jsonb->'semantic'->>'revision' IS DISTINCT FROM f.revision::text "
        "OR f.details::jsonb->'semantic'->>'anchor_key' IS DISTINCT FROM f.anchor_key "
        "OR (f.service_path IN "+INPUT_SERVICES+" AND "
        "(f.details::jsonb->'input_subject'->>'version' IS DISTINCT FROM '"+VERSION+"' "
        "OR f.details::jsonb->'input_subject'->>'status'='READ_DEFERRED')))")
    return expression.replace('f.',alias+'.' if alias else '')


DDL=[
    "CREATE INDEX IF NOT EXISTS adp_signal_candidate_scan_v1 ON anomaly_detection.adp_case_signals"
    "(target_ns DESC,job_session DESC,signal_key DESC) WHERE source_kind='actor' AND state='ACTIVE' "
    "AND job_session IS NOT NULL AND target_ns IS NOT NULL",
    "CREATE INDEX IF NOT EXISTS adp_fact_candidate_needed_v1 ON anomaly_detection.adp_facts"
    "(session_key,((at_ns/300000000000)*300000000000),next_audit_ns,request_key) "
    "WHERE eligible=TRUE AND source_present=TRUE AND state='active' AND "+needed(''),
]


def due_requests(store,state,now,limit):
    session,target=state['session_key'],state['target_ns']
    rows=store.raw.execute('SELECT f.request_key FROM anomaly_detection.adp_facts f WHERE '+FACT_SCOPE+
        needed()+' ORDER BY f.next_audit_ns,f.request_key LIMIT %s',
        (session,target,target+FIVE_NS,target,now,limit)).fetchall()
    return [r['request_key'] for r in rows]


def candidate_page(store,after):
    from .history_scope import target_scope
    fence='AND (s.target_ns,s.job_session,s.signal_key)<(%s,%s,%s) ' if after else ''
    # Bound parent rows BEFORE JSON predicates and lookups. An empty page is
    # progress, never a reason to fall back to searching the whole history.
    return store.raw.execute("WITH page AS MATERIALIZED (SELECT s.* "
        "FROM anomaly_detection.adp_case_signals s WHERE s.source_kind='actor' AND s.state='ACTIVE' "
        "AND s.job_session IS NOT NULL AND s.target_ns IS NOT NULL "+target_scope(store,'s.target_ns')+' '+
        fence+"ORDER BY s.target_ns DESC,s.job_session DESC,s.signal_key DESC LIMIT 32) "
        "SELECT s.signal_key,s.job_session,s.target_ns,s.family,s.review_eligible,s.primary_version,"
        "s.body::jsonb->>'baseline_unit' AS baseline_unit,s.body::jsonb->>'service_path' AS service_path,"
        "j.primary_version AS job_primary_version,sw.complete AS source_complete FROM page s "
        "LEFT JOIN LATERAL (SELECT j.primary_version FROM anomaly_detection.adp_jobs j "
        "WHERE j.session_key=s.job_session AND j.target_ns=s.target_ns LIMIT 1) j ON TRUE "
        "LEFT JOIN LATERAL (SELECT sw.complete FROM anomaly_detection.adp_source_windows sw "
        "WHERE sw.start_ns=s.target_ns LIMIT 1) sw ON TRUE "
        "ORDER BY s.target_ns DESC,s.job_session DESC,s.signal_key DESC",tuple(after or ())).fetchall()


def keys(store,now,limit=1):
    state=store.state(STATE)
    if state and state.get('target_ns',0)<getattr(store,'history_floor_ns',0):state={}
    if state and now<state['visit_until_ns']:
        current=due_requests(store,state,now,limit)
        if current:return current
    scan=store.state(PASS_STATE) or {}
    pending=scan.get('pending',[])
    if not pending:
        page=candidate_page(store,scan.get('after'))
        scan={'after':([page[-1][k] for k in ('target_ns','job_session','signal_key')] if page else None),
              'pending':[]}
        seen=set()
        for row in page:
            current=(row['job_primary_version'] is not None and
                     row['job_primary_version']==row['primary_version'])
            canonical=(row['baseline_unit']=='canonical_service_executions' and
                       row['service_path'] in CONTRACTS)
            hint=row['review_eligible'] or (row['family']=='peer_service_rate_5m' and (canonical or current))
            scope=(row['job_session'],row['target_ns'])
            if hint and row['source_complete'] and scope not in seen:
                seen.add(scope);scan['pending'].append(list(scope))
        pending=scan['pending']
    while pending:
        session,target=pending.pop(0)
        if target<getattr(store,'history_floor_ns',0):continue
        state={'session_key':session,'target_ns':target,'visit_until_ns':now+VISIT_NS}
        current=due_requests(store,state,now,limit)
        if current:
            store.save_state(PASS_STATE,scan)
            store.save_state(STATE,state)
            return current
    store.save_state(PASS_STATE,scan)
    if state:store.save_state(STATE,{})
    return []
