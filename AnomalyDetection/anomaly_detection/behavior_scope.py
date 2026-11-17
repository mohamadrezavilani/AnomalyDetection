"""Versioned observed-behavior adapter; finance absence is OUT_OF_SCOPE.

Unchanged behavior feature contracts can reuse their qualified history. The
three removed relation-dependent families never run against historical finance
materializations. Models, evidence versions and human feedback are retained.
"""
from copy import deepcopy
from .snapshot import require,canonical,digest

FULL='viewer-full-relations-1'
BEHAVIOR='viewer-behavior-1'
FEATURES='observed-behavior-features-1'
DISABLED=frozenset(('payment_result_change','typed_target_diversity','journey_profile_change'))


def source_scope(q):
    present=q("SELECT to_regclass('public.viewer_product_scope') AS present",cap=1)
    rows=q('SELECT contract,epoch,state FROM public.viewer_product_scope WHERE id=1',cap=1) if present and present[0]['present'] else []
    row=rows[0] if rows else dict(contract=FULL,epoch=0,state='READY')
    require(row['contract'] in (FULL,BEHAVIOR) and row['state']=='READY','SOURCE_PRODUCT_SCOPE_NOT_READY')
    return dict(input_contract=row['contract'],scope_epoch=row['epoch'],
                behavioral_features=FEATURES,financial_relations='OUT_OF_SCOPE' if row['contract']==BEHAVIOR else 'COMPLETE')


def behavioral(source):
    return (source or {}).get('input_contract')==BEHAVIOR


def fact(value,source):
    if not value or not behavioral(source):return value
    value=dict(value)
    value.update(relations=[],identifiers=[],financial_relations='OUT_OF_SCOPE')
    value['observations']=[r for r in value.get('observations',[]) if r.get('axis','').startswith('service_dispatch.')]
    value['outcomes']={k:v for k,v in value.get('outcomes',{}).items() if k.startswith('service_dispatch.')}
    value['viewer_journey']={'status':'OUT_OF_SCOPE','input_contract':BEHAVIOR}
    value['versions']=dict(value.get('versions') or {},input_contract=BEHAVIOR,behavioral_features=FEATURES)
    return value


def decisions(values,source):
    if not behavioral(source):return values
    result=[]
    for item in values:
        value=dict(item,input_contract=BEHAVIOR,behavioral_features=FEATURES)
        if value.get('family') in DISABLED:
            value={k:v for k,v in value.items() if k not in ('model','model_id','reference_model_id','score')}
            value.update(status='OUT_OF_SCOPE',reason='FINANCIAL_RELATIONS_OUT_OF_SCOPE',
                evidence_verified=False,single_signal_review_eligible=False,
                explanation_fa='این تحلیل به روابط مالی وابسته است و در نسخهٔ رفتاری خارج از دامنه است.')
        elif value.get('model'):
            # Same feature definition, explicit compatibility, no mixing an
            # affected financial model into a behavior-only model receipt.
            model_id=value['model']['model_id']
            if not model_id.startswith('bm1:'):model_id='bm1:'+digest([FEATURES,model_id])
            value['model']=dict(value['model'],model_id=model_id,input_contract=BEHAVIOR,behavioral_features=FEATURES,
                compatible_history_contracts=[FULL,BEHAVIOR])
            value['model_id']=model_id
        result.append(value)
    return result


def bind(store,source):
    if 'input_contract' not in source:return
    current={k:source[k] for k in ('input_contract','scope_epoch','behavioral_features','financial_relations')}
    old=store.state('input_contract')
    require(not old or current['scope_epoch']>=old.get('scope_epoch',0),'PRODUCT_INPUT_CONTRACT_EPOCH_REGRESSED')
    if old==current:return
    store.save_state('input_contract',current)
    store.save_state('input_contract_history:'+str(current['scope_epoch']),current)
    if not behavioral(current):return
    # This is a one-time scope migration, not a reset/retraining of behavior
    # history. Existing finding/case versions and feedback remain untouched.
    changed=store.raw.execute("UPDATE anomaly_detection.adp_case_signals SET state='OUT_OF_SCOPE',qualified=FALSE,review_eligible=FALSE "
        "WHERE family=ANY(%s) AND state<>'OUT_OF_SCOPE' RETURNING case_key",(list(DISABLED),)).fetchall()
    findings=store.raw.execute("SELECT * FROM anomaly_detection.adp_findings WHERE family=ANY(%s) AND state<>'OUT_OF_SCOPE'",(list(DISABLED),)).fetchall()
    import time,json
    now=time.time_ns()
    for row in findings:
        body=decisions([json.loads(row['body'])],current)[0]|dict(state='OUT_OF_SCOPE')
        revision=row['revision']+1
        store.raw.execute("UPDATE anomaly_detection.adp_findings SET state='OUT_OF_SCOPE',revision=%s,body=%s,content_digest=%s,updated_ns=%s WHERE finding_key=%s",(revision,canonical(body),digest(body),now,row['finding_key']))
        store.raw.execute('INSERT INTO anomaly_detection.adp_finding_versions VALUES(%s,%s,%s,%s)',(row['finding_key'],revision,canonical(body),now))
    from .cases import refresh
    import time,json
    now=time.time_ns()
    for key in sorted({r['case_key'] for r in changed}):
        refresh(store,key,now)
        active=store.raw.execute("SELECT 1 FROM anomaly_detection.adp_case_signals WHERE case_key=%s AND state='ACTIVE' LIMIT 1",(key,)).fetchone()
        if not active:
            row=store.raw.execute('SELECT * FROM anomaly_detection.adp_cases WHERE case_key=%s',(key,)).fetchone()
            if row:
                body=json.loads(row['body'])|dict(state='OUT_OF_SCOPE',input_contract=BEHAVIOR,reason='FINANCIAL_RELATIONS_OUT_OF_SCOPE')
                version=row['revision']+1
                store.raw.execute('UPDATE anomaly_detection.adp_cases SET state=%s,revision=%s,body=%s,content_digest=%s,updated_ns=%s WHERE case_key=%s',
                    ('OUT_OF_SCOPE',version,canonical(body),digest(body),now,key))
                store.raw.execute('INSERT INTO anomaly_detection.adp_case_versions VALUES(%s,%s,%s,%s)',(key,version,canonical(body),now))
