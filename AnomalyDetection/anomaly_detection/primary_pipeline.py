"""Small, target-local primary evaluation before secondary historical models."""
import json
from . import FIVE_NS
from .snapshot import api_path

FAMILIES=('rate_5m','rate_60m','service_mix','isolation_forest','service_sequence','timing_regularization',
 'business_result_change','request_latency','otp_result_change','payment_result_change','typed_target_diversity','journey_profile_change','continuous_rate')


def counts_proof(store,session,target):
    return store.raw.execute("SELECT f.service_path,COUNT(*) AS n,COUNT(*) FILTER(WHERE f.details::jsonb->>'source_present'='true' AND f.details::jsonb->'quality'->>'evidence_available'='true' AND COALESCE(f.details::jsonb->'quality'->>'conflicted','false')='false' AND f.details::jsonb->'semantic'->>'state'='active' AND f.details::jsonb->'semantic'->>'revision'=f.revision::text AND f.details::jsonb->'semantic'->>'anchor_key'=f.anchor_key) AS qualified FROM anomaly_detection.adp_facts f JOIN anomaly_detection.adp_window_members m ON m.start_ns=%s AND m.request_key=f.request_key WHERE f.session_key=%s AND f.at_ns>=%s AND f.at_ns<%s AND f.state='active' AND f.source_present=TRUE AND f.eligible=TRUE GROUP BY f.service_path",(target,session,target,target+FIVE_NS)).fetchall()


def context(store,job):
    session,target=job['session_key'],job['target_ns']
    row=store.raw.execute('SELECT w.body,sw.source,sw.complete FROM anomaly_detection.adp_windows w JOIN anomaly_detection.adp_source_windows sw ON sw.start_ns=w.start_ns WHERE w.session_key=%s AND w.start_ns=%s',(session,target)).fetchone()
    if not row or not row['complete']:return None
    window=json.loads(row['body']);source=json.loads(row['source'])
    facts=store.raw.execute('SELECT f.body,f.details,f.revision,f.anchor_key FROM anomaly_detection.adp_facts f JOIN anomaly_detection.adp_window_members m ON m.start_ns=%s AND m.request_key=f.request_key WHERE f.session_key=%s AND f.at_ns>=%s AND f.at_ns<%s AND f.source_present=TRUE AND f.eligible=TRUE AND f.state=\'active\' ORDER BY f.at_ns,f.request_key LIMIT 2049',(target,session,target,target+FIVE_NS)).fetchall()
    events=[json.loads(r['body']) for r in facts[:2048]];details=[]
    for row in facts[:2048]:
        value=json.loads(row['details'] or '{}')
        details.append({'request_key':value.get('request_key',json.loads(row['body'])['request_key']),'at_ns':json.loads(row['body'])['anchor_ns'],'details':value})
    return {'source':source,'primary_count_proof':[dict(r) for r in counts_proof(store,session,target)] if len(facts)>2048 else None,
        'session_key':session,'target_ns':target,'windows':[window],'events':events,'target_complete':bool(window.get('coverage_complete')),
        'target_events_complete':len(facts)<=2048,'history_truncated':False,'event_history_truncated':len(facts)>2048,
        'owned_snapshot':True,'target_local':True,'primary_details':details}


def evaluate(store,job,ctx,now,progress=None):
    from .service_reference import decisions as reference_decisions
    from collections import Counter
    events=ctx.get('events',[]);details=ctx.get('primary_details')
    if details is None:
        details,_=store.details(job)
        details=[r for r in details if job['target_ns']<=r['at_ns']<job['target_ns']+FIVE_NS]
    expected={e['request_key']:e for e in events if job['target_ns']<=e['anchor_ns']<job['target_ns']+FIVE_NS}
    qualified={r['request_key'] for r in details if r['request_key'] in expected and r.get('details',{}).get('source_present') and r['details'].get('quality',{}).get('evidence_available') and not r['details'].get('quality',{}).get('conflicted') and r['details'].get('semantic',{}).get('state')=='active' and r['details'].get('semantic',{}).get('revision')==expected[r['request_key']]['revision'] and r['details'].get('semantic',{}).get('anchor_key')==expected[r['request_key']]['anchor_key']}
    counts=next((w.get('counts') for w in ctx['windows'] if w['start_ns']==job['target_ns']),None)
    counted=dict(Counter(api_path(e.get('root_call')) for e in expected.values()))
    exact=ctx.get('primary_count_proof')
    verified=bool(expected and counted==counts and set(expected)<=qualified and ctx.get('target_events_complete'))
    total_expected=len(expected);total_qualified=len(qualified)
    if exact is not None:
        total_expected=sum(r['n'] for r in exact);total_qualified=sum(r['qualified'] for r in exact)
        verified=bool(total_expected>0 and total_expected==total_qualified and {r['service_path']:r['n'] for r in exact}==counts)
    ctx=dict(ctx,evidence_verified=verified)
    if progress:progress('primary_service_reference')
    decisions,inputs=reference_decisions(store,job,ctx,details,counts or {})
    for decision in decisions:
        if decision.get('model'):decision['model_id']=decision['model']['model_id']
    from .input_subjects import decisions as subject_decisions
    decisions.extend(list(subject_decisions(job,ctx,details,decisions)))
    from .snapshot import digest
    decisions += [{'finding_key':'pf1:'+digest([job['session_key'],job['target_ns'],family,'pending']),
        'session_key':job['session_key'],'target_ns':job['target_ns'],'family':family,'dimension':'context','service_path':'*',
        'status':'INSUFFICIENT_DATA','reason':'SECONDARY_MODELS_PENDING','explanation_fa':'بررسی این روش در صف مستقل ادامه دارد؛ نتیجهٔ روش تکمیل‌شده منتظر آن نمی‌ماند.'} for family in FAMILIES]
    ctx.update(peer_inputs=inputs,pending_families=list(FAMILIES),primary_evaluation=True,primary_qualified_requests=total_qualified,primary_expected_requests=total_expected)
    return store.complete(job,ctx,decisions,now)
