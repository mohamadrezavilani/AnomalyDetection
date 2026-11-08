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



# P0 candidate only, NOT deployed. Namespaced continuation persists across cycles.
WALK_STATE='candidate_audit_walk_v1'
WALK_PAGE_SIZE=24
# Candidate scopes SQL is sourced from source-pinned audit_scope.keys() by
# the build script and checked against source query fingerprints.
SCOPE_SELECT="SELECT DISTINCT s.job_session,s.target_ns FROM anomaly_detection.adp_case_signals s WHERE s.source_kind='actor' AND s.state='ACTIVE' AND (s.review_eligible=TRUE OR (s.family='peer_service_rate_5m' AND ((s.body::jsonb->>'baseline_unit'='canonical_service_executions' AND s.body::jsonb->>'service_path' IN ('Services.v1/CellPhoneBills','Services.v1/ElectricBills','Services.v1/GasBills','Services.v1/LandLinePhoneBills','Services.v1/WaterBills','Services.v2/GasBills')) OR EXISTS(SELECT 1 FROM anomaly_detection.adp_jobs j WHERE j.session_key=s.job_session AND j.target_ns=s.target_ns AND j.primary_version=s.primary_version)))) AND EXISTS(SELECT 1 FROM anomaly_detection.adp_source_windows sw WHERE sw.start_ns=s.target_ns AND sw.complete=TRUE) ORDER BY s.target_ns DESC,s.job_session DESC LIMIT %s"
SCOPE_ORDER='ORDER BY s.target_ns DESC,s.job_session DESC LIMIT %s'


def _read_scope_page(store,after,seek,limit):
    sql=SCOPE_SELECT
    args=[]
    if after is not None:
        sql=sql.replace(SCOPE_ORDER,'AND (s.target_ns,s.job_session)<(%s,%s) '+SCOPE_ORDER)
        args.extend(after)
    if seek is not None:
        sql=sql.replace(SCOPE_ORDER,'AND (s.target_ns,s.job_session)<(%s,%s) '+SCOPE_ORDER)
        args.extend(seek)
    args.append(limit)
    return store.raw.execute(sql,tuple(args)).fetchall()


def _valid_key(value):
    return (isinstance(value,(tuple,list)) and len(value)==2 and
            type(value[0]) is int and isinstance(value[1],str))


def _restore_walk(store,after):
    """Don't trust a continuation with a different primary rotation anchor."""
    saved=store.state(WALK_STATE)
    expected=list(after) if after else None
    if (not isinstance(saved,dict) or saved.get('anchor')!=expected or
        saved.get('phase') not in ('after','all') or
        (saved.get('phase')=='after' and after is None)):
        return {'anchor':expected,'phase':'after' if after else 'all','seek':None}
    seek=saved.get('seek')
    if seek is not None and not _valid_key(seek):
        return {'anchor':expected,'phase':'after' if after else 'all','seek':None}
    return {'anchor':expected,'phase':saved['phase'],'seek':seek}


def keys(store,now,limit=1):
    """Fair bounded audit selection; never report full exhaustion on partial scan.

    Each call visits at most 24 qualified signal scopes; an exact exclusive
    keyset cursor resumes the scan on the next Worker cycle. Late data in a
    previously traversed scope is rechecked on the following complete lap.
    """
    state=store.state(STATE)
    if state and now<state['visit_until_ns']:
        current=due_requests(store,state,now,limit)
        if current:return current
    after=(state['target_ns'],state['session_key']) if state else None
    walk=_restore_walk(store,after)
    budget=WALK_PAGE_SIZE
    while budget>0:
        original_after=after if walk['phase']=='after' else None
        seek=tuple(walk['seek']) if walk['seek'] is not None else None
        page_limit=budget
        rows=_read_scope_page(store,original_after,seek,page_limit)
        previous=seek
        for row in rows:
            key=(row['target_ns'],row['job_session'])
            if (not _valid_key(key) or
                (previous is not None and not key<previous) or
                (original_after is not None and not key<original_after)):
                raise RuntimeError('AUDIT_P0_SCOPE_ORDER_INVALID')
            previous=key
            due=due_requests(store,{'session_key':key[1],'target_ns':key[0]},now,limit)
            if due:
                store.save_state(STATE,{'session_key':key[1],'target_ns':key[0],
                                       'visit_until_ns':now+VISIT_NS})
                store.save_state(WALK_STATE,{})
                return due
        budget-=len(rows)
        if len(rows)<page_limit:
            # Reached the end of this branch. Do NOT wrap before exhausting
            # all of the original-fence branch.
            if walk['phase']=='after':
                walk.update(phase='all',seek=None)
                continue
            if state:store.save_state(STATE,{})
            store.save_state(WALK_STATE,{})
            return []
        if rows:
            walk['seek']=list(previous)
        store.save_state(WALK_STATE,walk)
        return []
    store.save_state(WALK_STATE,walk)
    return []
