"""Separate descriptive rarity from qualification for operator review."""
from collections import defaultdict

VERSION=3


def corroborated_scopes(values):
    from .input_subjects import FAMILY
    dimensions=defaultdict(set)
    explained=set()
    for value in values:
        service=value.get('service_path','*')
        if value.get('peer_activity_can_explain'):
            explained.add(service)
        if value.get('dimension') not in (None,'context') and value.get('family')!=FAMILY:
            dimensions[service].add(value['dimension'])
    return {service for service,items in dimensions.items() if len(items)>=2 and service not in explained}


def eligible(value):
    if value.get('single_signal_review_eligible') is not True:return False
    if value.get('family')=='rate_60m' and value.get('span_evidence_verified') is not True:return False
    if value.get('review_basis')=='QUALIFIED_INDEPENDENT_DIMENSIONS':return True
    if value.get('family') in ('peer_service_rate_5m','continuous_rate'):
        observed=value.get('observed')
        bound=value.get('upper') if value['family']=='peer_service_rate_5m' else value.get('reference_max')
        return type(observed) in (int,float) and type(bound) in (int,float) and observed>bound
    return True


def sql(alias='s',*,qualified=True):
    # Fixed internal alias only, never a user-controlled SQL identifier.
    assert alias in ('s',)
    b=alias+'.body::jsonb'
    return ("s.review_eligible AND "+("s.qualified AND " if qualified else '')+"s.state='ACTIVE' "
      "AND (s.family<>'rate_60m' OR "+b+"->>'span_evidence_verified'='true') AND ("
      +b+"->>'review_basis'='QUALIFIED_INDEPENDENT_DIMENSIONS' OR "
      "s.family NOT IN ('peer_service_rate_5m','continuous_rate') OR ("
      "jsonb_typeof("+b+"->'observed')='number' AND jsonb_typeof("+b+"->(CASE WHEN s.family='peer_service_rate_5m' THEN 'upper' ELSE 'reference_max' END))='number' "
      "AND ("+b+"->>'observed')::numeric>("+b+"->>(CASE WHEN s.family='peer_service_rate_5m' THEN 'upper' ELSE 'reference_max' END))::numeric))")


def warm(store,limit=128):
    """Reassess old method results in finite pages, preserving decisions."""
    state=store.state('rate_history_requalification_v3')
    if state.get('done'):return state
    with store.transaction():
        if 'through' not in state:
            row=store.raw.execute('SELECT session_key,target_ns FROM anomaly_detection.adp_jobs WHERE last_evaluated_ns IS NOT NULL ORDER BY session_key DESC,target_ns DESC LIMIT 1').fetchone()
            state['through']=[row['session_key'],row['target_ns']] if row else None
        rows=[]
        if state['through']:
            after='';params=list(state['through'])
            if state.get('after'):after=' AND (session_key,target_ns)>(%s,%s)';params.extend(state['after'])
            rows=store.raw.execute('SELECT session_key,target_ns,dirty,evaluation FROM anomaly_detection.adp_jobs WHERE last_evaluated_ns IS NOT NULL AND (session_key,target_ns)<=(%s,%s)'+after+' ORDER BY session_key,target_ns LIMIT %s',(*params,limit)).fetchall()
        import json
        from .snapshot import canonical
        changed=[{'actor':r['session_key'],'target':r['target_ns']} for r in rows if not r['dirty'] and json.loads(r['evaluation'] or '{}').get('rate_history_policy_version')!=VERSION]
        if changed:store.raw.execute('UPDATE anomaly_detection.adp_jobs j SET dirty=TRUE,version=version+1,due_ns=0 FROM jsonb_to_recordset(%s::jsonb) AS x(actor TEXT,target BIGINT) WHERE j.session_key=x.actor AND j.target_ns=x.target',(canonical(changed),))
        state.update(scanned=state.get('scanned',0)+len(rows),requeued=state.get('requeued',0)+len(changed),done=len(rows)<limit)
        if rows:state['after']=[rows[-1]['session_key'],rows[-1]['target_ns']]
        store.save_state('rate_history_requalification_v3',state)
    return state
