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


def current_fact(value,source,requalification=None):
    if value and requalification and not behavioral(source) and value.get('versions',{}).get('scope_epoch',0)<requalification['scope_epoch']:
        value=dict(value,identifiers=[],relations=[],viewer_journey={},financial_relations='REQUALIFICATION_REQUIRED')
    return fact(value,source)


def decisions(values,source):
    if not behavioral(source):return values
    # References are a graph: an input-subject model can cite the peer model
    # emitted elsewhere in this batch. Namespace both nodes and edges, even
    # when the referenced receipt already exists and is not emitted again.
    def model_key(key):
        return key if not key or key.startswith('bm1:') else 'bm1:'+digest([FEATURES,key])
    def project_model(model):
        value=deepcopy(model)
        for field in ('model_id','reference_model_id'):
            if value.get(field):value[field]=model_key(value[field])
        value.update(input_contract=BEHAVIOR,behavioral_features=FEATURES,
                     compatible_history_contracts=[FULL,BEHAVIOR])
        return value
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
            value['model']=project_model(value['model'])
            value['model_id']=value['model']['model_id']
        if value.get('family') not in DISABLED:
            for field in ('model_id','reference_model_id'):
                if value.get(field):value[field]=model_key(value[field])
        result.append(value)
    return result


MIGRATION='behavior_scope_migration_v2'


def bind(store,source):
    """Bind the active contract immediately; schedule bounded legacy cleanup.

    Every new decision observes the active contract, even while old rows are
    being converted. Migration completion is a separate durable receipt.
    """
    if 'input_contract' not in source:return
    current={k:source[k] for k in ('input_contract','scope_epoch','behavioral_features','financial_relations')}
    old=store.state('input_contract')
    require(not old or current['scope_epoch']>=old.get('scope_epoch',0),'PRODUCT_INPUT_CONTRACT_EPOCH_REGRESSED')
    require(not old or current['scope_epoch']!=old.get('scope_epoch',0) or old==current,
            'PRODUCT_INPUT_CONTRACT_CHANGED_WITHOUT_NEW_EPOCH')
    changed=old!=current
    if changed:
        if hasattr(store,'model_cache'):store.model_cache.clear()
        store.save_state('input_contract',current)
        store.save_state('input_contract_history:'+str(current['scope_epoch']),current)
        if not behavioral(current) and behavioral(old):
            import time
            store.save_state('finance_requalification',dict(scope_epoch=current['scope_epoch'],
                required_since_ns=time.time_ns(),jobs_after=None,facts_after=None,jobs_done=False,facts_done=False))
    migration=store.state(MIGRATION)
    needs=behavioral(current) or changed and behavioral(old) or bool(migration and not migration.get('complete'))
    if needs and (not migration or migration.get('scope_epoch')!=current['scope_epoch']):
        if migration:store.save_state(MIGRATION+':'+str(migration['scope_epoch']),migration)
        store.save_state(MIGRATION,dict(scope_epoch=current['scope_epoch'],input_contract=current['input_contract'],
            phase='signals',status='IN_PROGRESS',complete=False,pages=0,scanned=0,changed=0))


def advance_migration(store,limit=32):
    """One PK-bounded parent page, atomically committed with its cursor.

    Predicates are evaluated only AFTER a finite parent page. A sparse finance
    subset cannot make a LIMIT query rescan the entire unrelated history. Case
    history and feedback remain; no aggregate of all signals/evidence is needed
    merely to put a finance-only case outside the active product scope.
    """
    import json,time
    require(type(limit) is int and 1<=limit<=128,'SCOPE_MIGRATION_PAGE_LIMIT')
    with store.transaction():
        state=store.state(MIGRATION);scope=store.state('input_contract')
        if not state or state.get('complete'):return state
        require(state['scope_epoch']==scope.get('scope_epoch') and state['input_contract']==scope.get('input_contract'),
                'SCOPE_MIGRATION_CONTRACT_CHANGED')
        phases=('signals','findings','cases');phase=state['phase']
        tables={'signals':('adp_case_signals','signal_key'),'findings':('adp_findings','finding_key'),'cases':('adp_cases','case_key')}
        table,key=tables[phase]
        if 'through' not in state:
            row=store.raw.execute('SELECT '+key+' FROM anomaly_detection.'+table+' ORDER BY '+key+' DESC LIMIT 1').fetchone()
            state['through']=row[key] if row else None
        rows=[]
        if state['through'] is not None:
            after=' AND '+key+'>%s' if state.get('after') is not None else ''
            params=(state['through'],state['after'],limit) if after else (state['through'],limit)
            rows=store.raw.execute('SELECT * FROM anomaly_detection.'+table+' WHERE '+key+'<=%s'+after+
                ' ORDER BY '+key+' LIMIT %s',params).fetchall()
        now=time.time_ns();changed=0;behavior=behavioral(scope)
        for row in rows:
            if phase=='signals':
                if row['family'] not in DISABLED:continue
                desired='OUT_OF_SCOPE' if behavior else 'DEFERRED'
                if row['state']==desired or not behavior and row['state']!='OUT_OF_SCOPE':continue
                store.raw.execute('UPDATE anomaly_detection.adp_case_signals SET state=%s,qualified=FALSE,review_eligible=FALSE WHERE signal_key=%s',
                                  (desired,row[key]));changed+=1
            elif phase=='findings':
                if not behavior or row['family'] not in DISABLED or row['state']=='OUT_OF_SCOPE':continue
                body=decisions([json.loads(row['body'])],scope)[0]|dict(state='OUT_OF_SCOPE')
                revision=row['revision']+1
                store.raw.execute("UPDATE anomaly_detection.adp_findings SET state='OUT_OF_SCOPE',revision=%s,body=%s,content_digest=%s,updated_ns=%s WHERE finding_key=%s",
                    (revision,canonical(body),digest(body),now,row[key]))
                store.raw.execute('INSERT INTO anomaly_detection.adp_finding_versions VALUES(%s,%s,%s,%s)',
                                  (row[key],revision,canonical(body),now));changed+=1
            else:
                from .cases import KINDS
                if row['issue_kind'] not in {KINDS[f] for f in DISABLED}:continue
                desired='OUT_OF_SCOPE' if behavior else 'HOLD'
                if row['state']==desired or not behavior and row['state']!='OUT_OF_SCOPE':continue
                # The existing (case_key,state,...) index bounds this probe.
                active=store.raw.execute("SELECT 1 FROM anomaly_detection.adp_case_signals WHERE case_key=%s AND state='ACTIVE' LIMIT 1",(row[key],)).fetchone()
                if active:continue
                body=json.loads(row['body'])|dict(state=desired,input_contract=scope['input_contract'],scope_epoch=scope['scope_epoch'],
                    reason='FINANCIAL_RELATIONS_OUT_OF_SCOPE' if behavior else 'FINANCE_REQUALIFICATION_REQUIRED',active_signals=0)
                if behavior:
                    body['deferred_signals']=0
                    if body.get('strongest',{}).get('family') in DISABLED:
                        body['strongest']=decisions([body['strongest']],scope)[0]
                revision=row['revision']+1
                store.raw.execute('UPDATE anomaly_detection.adp_cases SET state=%s,revision=%s,body=%s,content_digest=%s,updated_ns=%s WHERE case_key=%s',
                    (desired,revision,canonical(body),digest(body),now,row[key]))
                store.raw.execute('INSERT INTO anomaly_detection.adp_case_versions VALUES(%s,%s,%s,%s)',
                                  (row[key],revision,canonical(body),now));changed+=1
        state.update(pages=state['pages']+1,scanned=state['scanned']+len(rows),changed=state['changed']+changed)
        if rows:state['after']=rows[-1][key]
        if not rows or rows[-1][key]>=state['through']:
            next_index=phases.index(phase)+1
            if next_index==len(phases):state.update(phase='complete',status='COMPLETE',complete=True)
            else:
                state['phase']=phases[next_index];state.pop('after',None);state.pop('through',None)
        store.save_state(MIGRATION,state)
    return state


def advance_requalification(store,limit=128):
    """Bound parent pages before JSON predicates; one page per worker turn.

    A crash repeats only a rolled-back page. All updates, including the cursor,
    are committed together by the caller. A subsequent behavior switch pauses
    this full-only repair without losing any receipts.
    """
    scope=store.state('input_contract');state=store.state('finance_requalification')
    if behavioral(scope) or not state or (state['jobs_done'] and state['facts_done']):return
    import json
    if not state['jobs_done']:
        after=state['jobs_after']
        rows=store.raw.execute('SELECT session_key,target_ns,version,evaluation FROM anomaly_detection.adp_jobs '+
            ('WHERE (session_key,target_ns)>(%s,%s) ' if after else '')+
            'ORDER BY session_key,target_ns LIMIT %s',(*after,limit) if after else (limit,)).fetchall()
        for row in rows:
            evaluation=json.loads(row['evaluation'] or '{}')
            pending=store.raw.execute("SELECT 1 FROM anomaly_detection.adp_findings WHERE session_key=%s AND target_ns=%s AND family=ANY(%s) AND state='OUT_OF_SCOPE' LIMIT 1",
                (row['session_key'],row['target_ns'],list(DISABLED))).fetchone()
            if evaluation.get('input_contract')==BEHAVIOR or pending and evaluation.get('scope_epoch',0)!=state['scope_epoch']:
                store.raw.execute('UPDATE anomaly_detection.adp_jobs SET version=version+1,dirty=TRUE,due_ns=0 WHERE session_key=%s AND target_ns=%s AND version=%s',
                    (row['session_key'],row['target_ns'],row['version']))
        state['jobs_after']=[rows[-1]['session_key'],rows[-1]['target_ns']] if rows else after
        state['jobs_done']=len(rows)<limit
    if not state['facts_done']:
        after=state['facts_after']
        rows=store.raw.execute('SELECT request_key,details FROM anomaly_detection.adp_facts '+
            ('WHERE request_key>%s ' if after else '')+'ORDER BY request_key LIMIT %s',
            (after,limit) if after else (limit,)).fetchall()
        for row in rows:
            # Full reconstruction may add a relationship to an unchanged
            # request through another request. Its old full cache is stale too.
            store.raw.execute('UPDATE anomaly_detection.adp_facts SET next_audit_ns=0 WHERE request_key=%s',(row['request_key'],))
            store.raw.execute('UPDATE anomaly_detection.adp_journeys SET next_read_ns=0 WHERE request_key=%s',(row['request_key'],))
        state['facts_after']=rows[-1]['request_key'] if rows else after
        state['facts_done']=len(rows)<limit
    store.save_state('finance_requalification',state)
