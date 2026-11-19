"""Compute outside write transactions and commit version-checked results."""
from .product_models import evaluate
from .snapshot import digest,require
from .temporal import Point,fit
from . import FIVE_NS,EVALUATOR_VERSION
from collections import Counter
from copy import deepcopy
from .snapshot import api_path


def evaluate_job(store,job,context,now, *, progress=None,mode='full'):
    from .behavior_scope import fact as scope_fact
    active_scope=store.state('input_contract') if callable(getattr(store,'state',None)) else {}
    if active_scope:context=dict(context,source=dict(context['source'],**active_scope))
    if mode=='primary':
        from .primary_pipeline import evaluate as evaluate_primary
        return evaluate_primary(store,job,context,now,progress)
    def stage(name):
        if progress:progress(name)
    stage('history')
    require(context['session_key']==job['session_key'] and context['target_ns']==job['target_ns'],'PRODUCT_CONTEXT_SCOPE_MISMATCH')
    history=store.history(job)
    excluded=store.excluded_windows(job)
    # Current source summaries supersede imported summaries in the same model scope.
    merged={row['start_ns']:row for row in history}
    for row in context['windows']:
        if row['start_ns']<job['target_ns'] and row['start_ns'] not in excluded:merged[row['start_ns']]=row
    stage('actor_evidence')
    details,details_complete=store.details(job)
    details=[row for row in details if row['at_ns']//FIVE_NS*FIVE_NS not in excluded]
    context=dict(context,events=[event for event in context.get('events',[]) if event['anchor_ns']//FIVE_NS*FIVE_NS not in excluded])
    current_keys={event['request_key'] for event in context.get('events',[]) if job['target_ns']<=event['anchor_ns']<job['target_ns']+300_000_000_000}
    expected={event['request_key']:event for event in context.get('events',[])}
    verified={row['request_key'] for row in details if row['request_key'] in expected and row['details'] and row['details'].get('source_present') and
        row['details'].get('quality',{}).get('evidence_available') and not row['details'].get('quality',{}).get('conflicted') and
        row['details']['semantic']['state']=='active' and
        row['details']['semantic']['revision']==expected[row['request_key']]['revision'] and
        row['details']['semantic']['anchor_key']==expected[row['request_key']]['anchor_key']}
    counted=Counter(api_path(e.get('root_call')) for e in context.get('events',[]) if e['request_key'] in current_keys)
    target_counts=next((w.get('counts') for w in context['windows'] if w['start_ns']==job['target_ns']),None)
    scope_matches=target_counts is not None and dict(counted)==target_counts
    context=dict(context,details_history_truncated=not details_complete,semantic_event_counts_match=scope_matches,
        evidence_verified=bool(scope_matches and current_keys and current_keys<=verified and context.get('target_events_complete')))
    cache={}
    peer_inputs={}
    def peer(service,target):
        if service not in cache:
            from .product_dependencies import peer_model
            cache[service],peer_inputs[service]=peer_model(store,service,target)
        return cache[service]
    stage('behavior_models')
    decisions=evaluate(context,[merged[key] for key in sorted(merged)],details,peer_provider=peer)
    from .context_models import FAMILIES as CONTEXT_FAMILIES,evaluate as evaluate_context
    context_details={r['request_key']:r for r in details}
    context_read_failed=False
    stage('service_evidence')
    if callable(getattr(store,'service_details',None)):
        try:
            shared,context_inputs=store.service_details(job,next((w.get('counts') or {} for w in context['windows'] if w['start_ns']==job['target_ns']),{}))
        except Exception as exc:
            if getattr(exc,'sqlstate',None) not in ('57014','55P03'):raise
            context_read_failed=True
        else:
            peer_inputs.update(context_inputs)
            for row in shared:context_details.setdefault(row['request_key'],row)
    stage('context_models')
    if context_read_failed:
        session,target=job['session_key'],job['target_ns']
        decisions.extend({'finding_key':'pf1:'+digest([session,target,family,'*']),
            'session_key':session,'target_ns':target,'family':family,'dimension':'context','service_path':'*',
            'status':'INSUFFICIENT_DATA','reason':'CONTEXT_REFERENCE_READ_RETRY',
            'explanation_fa':'خواندن مرجع این روش کامل نشد؛ ارزیابی دوباره در صف می‌ماند.'}
            for family in CONTEXT_FAMILIES)
        context=dict(context,pending_families=list(CONTEXT_FAMILIES))
    else:
        decisions+=evaluate_context(context,list(context_details.values()))
    from .service_reference import decisions as reference_decisions
    sparse_services={s for w in context['windows'] if w['start_ns']==job['target_ns'] for s,k in w.get('count_kinds',{}).items() if k=='service_execution'}
    if callable(getattr(store,'reference_services',None)):sparse_services.update(store.reference_services(job))
    stage('service_reference')
    added,reference_inputs=reference_decisions(store,job,context,details,sparse_services)
    require(all(peer_inputs.get(k,v)==v for k,v in reference_inputs.items()),'PRODUCT_CONTEXT_INPUT_CHANGED_RETRY')
    decisions+=added;peer_inputs.update(reference_inputs)
    from .input_subjects import decisions as subject_decisions
    decisions.extend(subject_decisions(job,context,details,added))
    if callable(getattr(store,'continuous_models',None)):
        stage('continuous_models')
        continuous,inputs=store.continuous_models(job,context)
        require(all(peer_inputs.get(k,v)==v for k,v in inputs.items()),'PRODUCT_CONTEXT_INPUT_CHANGED_RETRY')
        decisions+=continuous;peer_inputs.update(inputs)
    # Method changes must neither reuse an old model receipt nor leave a
    # completed job looking current solely because its input version matches.
    # Providers may return cached model objects. Naming a receipt must not
    # mutate those inputs or re-hash the already-renamed cache on the next job.
    decisions=deepcopy(decisions)
    renamed={d['model']['model_id']:'am2:'+digest([EVALUATOR_VERSION,d['model']['model_id']])
             for d in decisions if d.get('model')}
    for decision in decisions:
        model=decision.get('model')
        if model:
            # Copy each node separately too: two emitted decisions can share
            # the same provider model object within one cached batch.
            model=dict(model,model_id=renamed[model['model_id']],implementation_version=EVALUATOR_VERSION)
            if model.get('reference_model_id') in renamed:model['reference_model_id']=renamed[model['reference_model_id']]
            decision['model']=model
        for field in ('model_id','reference_model_id'):
            if decision.get(field) in renamed:decision[field]=renamed[decision[field]]
        decision['evaluator_version']=EVALUATOR_VERSION
    context=dict(context,peer_inputs=peer_inputs,evaluator_version=EVALUATOR_VERSION)
    stage('commit_result')
    return store.complete(job,context,decisions,now)


def warm_model_references(store,now,limit=64):
    """Requeue old model-bearing results in finite, restartable parent pages.

    Old receipts remain immutable. The new evaluator namespace prevents an
    existing broken child receipt winning ON CONFLICT DO NOTHING. Requalifying
    results does not alter source cursors, baselines or human feedback.
    """
    import json
    from .model_queue import schedule
    key='model_reference_requalification_v2'
    require(type(limit) is int and 1<=limit<=128,'MODEL_REFERENCE_RECHECK_LIMIT')
    with store.transaction():
        state=store.state(key)
        if state.get('done'):return state
        if 'through' not in state:
            row=store.raw.execute('SELECT session_key,target_ns FROM anomaly_detection.adp_jobs ORDER BY session_key DESC,target_ns DESC LIMIT 1').fetchone()
            state['through']=[row['session_key'],row['target_ns']] if row else None
        rows=[]
        if state['through']:
            after=' AND (session_key,target_ns)>(%s,%s)' if state.get('after') else ''
            rows=store.raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE (session_key,target_ns)<=(%s,%s)'+after+
                ' ORDER BY session_key,target_ns LIMIT %s',(*state['through'],*(state.get('after') or ()),limit)).fetchall()
        changed=0
        for row in rows:
            evaluation=json.loads(row['evaluation'] or '{}')
            if row['target_ns']<getattr(store,'history_floor_ns',0):continue
            if row['dirty'] or row['processed_version']!=row['version'] or not row['last_evaluated_ns'] or evaluation.get('evaluator_version')==EVALUATOR_VERSION:continue
            families={d['family'] for d in evaluation.get('decisions',[]) if d.get('model_id') or d.get('reference_model_id')}
            if not families:continue
            queued=store.raw.execute('SELECT families FROM anomaly_detection.adp_model_queue WHERE session_key=%s AND target_ns=%s',
                (row['session_key'],row['target_ns'])).fetchone()
            if queued:families.update(json.loads(queued['families']))
            schedule(store,row,sorted(families),now);changed+=1
        state.update(scanned=state.get('scanned',0)+len(rows),requeued=state.get('requeued',0)+changed,done=len(rows)<limit)
        if rows:state['after']=[rows[-1]['session_key'],rows[-1]['target_ns']]
        store.save_state(key,state)
    return state
