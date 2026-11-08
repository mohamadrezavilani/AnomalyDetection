"""Current peer finding survives secondary retries; candidate evidence completes.

Disposable PostgreSQL/WASM only. Injected SQLSTATE is a failure-path test,
not a measurement of native Windows latency or production detection quality.
"""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import json
from transport import Engine
from anomaly_detection import BUILD_ID,FIVE_NS
from anomaly_detection.product_store import ProductStore
from anomaly_detection.product_pipeline import apply_window,owned_context
from anomaly_detection.product_engine import evaluate_job
from anomaly_detection.primary_pipeline import context
from anomaly_detection.cases import identity
from anomaly_detection.case_summary import case_status,filters,render
from anomaly_detection.presentation_proof import collect
from anomaly_detection.audit_scope import keys
from anomaly_detection.snapshot import canonical
from check_revision10 import packet,metadata,SERVICES
from check_revision16 import T

ROOT=Path(__file__).resolve().parents[2]
ACTOR='a'*64;SERVICE=SERVICES[0]


def job(store,actor=ACTOR,at=T):
    return dict(store.raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(actor,at)).fetchone())


def primary(store,actor=ACTOR,at=T):
    j=job(store,actor,at);c=context(store,j);assert c
    c=store.save_context(j,c);j['version']=c['job_version']
    return evaluate_job(store,j,c,T+20*FIVE_NS,mode='primary')


def audit(store,key,now):
    row=store.raw.execute('SELECT body,service_path,session_key FROM anomaly_detection.adp_facts WHERE request_key=%s',(key,)).fetchone()
    e=json.loads(row['body']);fact={'request_key':key,'semantic':e,'source_present':True,
        'quality':{'evidence_available':True,'conflicted':False,'identity_state':'assigned'},
        'transport':{'root_call':row['service_path']},'evidence':[],'observations':[],'relations':[],'identifiers':[]}
    return store.apply_audit(SimpleNamespace(keys=[key],source=dict(metadata(T),captured_at_ns=now),
        requests={key:{'session_key':row['session_key']}},facts=lambda:[fact]))


def main():
    engine=Engine();checks={}
    try:
        raw=engine.connect();raw.execute('CREATE SCHEMA anomaly_detection');store=ProductStore(raw);store.initialize()
        points=[(SERVICE,'service_execution',f'{1000+i:064x}',T-(i+2)*FIVE_NS,1+i%3,True) for i in range(411)]
        with raw.cursor() as cur:cur.executemany('INSERT INTO anomaly_detection.adp_service_reference_points VALUES(%s,%s,%s,%s,%s,%s)',points)
        apply_window(store,packet(T-FIVE_NS,{},offset=49900))
        apply_window(store,packet(T,{SERVICE:20},offset=50000))
        sql=[];original=raw.execute
        def observed(query,args=()):sql.append((query,args));return original(query,args)
        with patch.object(raw,'execute',side_effect=observed):r=primary(store)
        d=next(x for x in r['decisions'] if x['family']=='peer_service_rate_5m')
        assert r['status']=='APPLIED' and d['status']=='CANDIDATE' and d['observed']==20 and d['upper']==3 and d['peer_session_epochs']==411,d
        history_reads=[q for q,args in sql if 'FROM anomaly_detection.adp_windows' in q and any(type(x) is int and x<T for x in args)]
        assert not history_reads,history_reads
        key=identity('actor',ACTOR,'activity',SERVICE)
        assert case_status(store,key)['bucket']=='EVIDENCE_PENDING',dict(case_status(store,key))
        assert not job(store)['dirty'] and store.next_model_job(T+20*FIVE_NS)
        p=collect(store,ACTOR,T);assert p['services'][0]['qualified_evidence_executions']==0 and p['status']=='NOT_READY_OR_LIMITED',p
        checks['20_vs_411_reference_sessions_without_audit_is_visible_evidence_pending_not_ready']='PASS_20_VS_MAX3_RANK_1_OVER_412'
        checks['primary_path_reads_target_only_and_queues_13_secondary_methods_independently']='PASS_QUERY_SCOPE_ASSERTION_NOT_CAPACITY_MEASUREMENT'
        selected=keys(store,T+20*FIVE_NS)
        assert len(selected)==1
        for i in range(20):
            if i==4:
                # A newer candidate must not continually displace a scope
                # already being finished, including after store recreation.
                apply_window(store,packet(T+FIVE_NS,{SERVICE:30},session='b'*64,offset=60000))
                primary(store,'b'*64,T+FIVE_NS)
                store=ProductStore(raw)
            selected=keys(store,T+20*FIVE_NS+i)
            assert len(selected)==1
            assert raw.execute('SELECT session_key FROM anomaly_detection.adp_facts WHERE request_key=%s',(selected[0],)).fetchone()['session_key']==ACTOR
            audit(store,selected[0],T+20*FIVE_NS+i)
        primary(store)
        p=collect(store,ACTOR,T);assert p['status']=='PASS_REVIEWABLE_RATE_FINDING' and p['services'][0]['qualified_evidence_executions']==20,p
        assert case_status(store,key)['bucket']=='READY'
        checks['all_20_evidence_audits_finish_despite_newer_arrivals_and_store_restart']='PASS_NO_TEST_IDS_IN_PRODUCTION_SELECTOR'
        before=raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_cases WHERE case_key=%s',(key,)).fetchone()['n']
        assert before==1
        # The real full pipeline reaches continuous rate, then a simulated
        # statement-cancellation occurs inside that method's transaction.
        timeout=RuntimeError('test statement cancellation');timeout.sqlstate='57014'
        with patch('anomaly_detection.continuous.reference',side_effect=timeout):
            j=job(store);c=store.save_context(j,owned_context(store,j));j['version']=c['job_version']
            full=evaluate_job(store,j,c,T+21*FIVE_NS)
        assert any(d.get('reason')=='CONTINUOUS_MODEL_READ_RETRY' for d in full['decisions']),full
        assert not job(store)['dirty'] and case_status(store,key)['bucket']=='READY'
        assert json.loads(job(store)['evaluation'])['pending_families']==['continuous_rate']
        checks['injected_continuous_sqlstate_57014_retries_its_method_without_hiding_completed_peer_finding']='PASS_FULL_PIPELINE'
        token=job(store)['primary_version']
        from anomaly_detection.product_dependencies import context_changed
        context_changed(store,SERVICE,T-5*FIVE_NS)
        assert job(store)['dirty'] and job(store)['primary_version']==token
        assert case_status(store,key)['bucket']=='READY'
        assert collect(store,ACTOR,T)['status']=='PASS_REVIEWABLE_RATE_FINDING'
        checks['other_session_context_audit_does_not_invalidate_canonical_count_reference']='PASS_PRIMARY_TOKEN_UNCHANGED'
        # Existing case + old stale signal + new valid signal retain one case.
        primary(store)
        apply_window(store,packet(T+2*FIVE_NS,{SERVICE:50},offset=70000))
        primary(store,at=T+2*FIVE_NS)
        for row in raw.execute('SELECT request_key FROM anomaly_detection.adp_facts WHERE session_key=%s AND at_ns>=%s',(ACTOR,T+2*FIVE_NS)).fetchall():audit(store,row['request_key'],T+22*FIVE_NS)
        primary(store,at=T+2*FIVE_NS)
        raw.execute('UPDATE anomaly_detection.adp_jobs SET primary_version=primary_version+1,version=version+1,dirty=TRUE WHERE session_key=%s AND target_ns=%s',(ACTOR,T))
        status=case_status(store,key)
        assert status['bucket']=='READY' and status['stale_signals']>=1 and json.loads(status['body'])['strongest']['observed']==50,dict(status)
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_cases WHERE entity_key=%s AND service_path=%s',(ACTOR,SERVICE)).fetchone()['n']==1
        checks['stale_historical_signal_does_not_hide_current_signal_or_duplicate_case']='PASS_ONE_STABLE_CASE_LATEST_CURRENT50'
        normal='c'*64;at=T+3*FIVE_NS
        apply_window(store,packet(at,{SERVICE:1},session=normal,offset=80000));primary(store,normal,at)
        assert collect(store,normal,at)['status']=='PASS_RATE_COMPARISON_ONLY'
        cold='d'*64;atcold=T+4*FIVE_NS
        apply_window(store,packet(atcold,{SERVICES[1]:20},session=cold,offset=81000));primary(store,cold,atcold)
        assert collect(store,cold,atcold)['services'][0]['status']=='INSUFFICIENT_REFERENCE_OR_COMPARABILITY'
        checks['normal_control_and_unknown_service_are_not_forced_into_anomalies']='PASS_SYNTHETIC_CONTROLS'
        from anomaly_detection.product_web import render as page
        html=page(store,{},'/evaluation/'+ACTOR+'/'+str(T+2*FIVE_NS)+'/proof',{},'token')
        assert 'dir="rtl"' in html and '50 / 50 / 50' in html and '412' in html
        _,_,_,condition,params=filters({'bucket':['PENDING']});assert 'EVIDENCE_PENDING' in condition
        assert 'شاهد' in render(store,{'bucket':['PENDING']})
        checks['presentation_receipt_recomputes_saved_rank_and_matches_summary_facts_audit_and_display']='PASS_READ_ONLY_HTML_AND_JSON'
        with raw.transaction():
            raw.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            assert collect(store,ACTOR,T+2*FIVE_NS)['status']=='PASS_REVIEWABLE_RATE_FINDING'
        checks['presentation_receipt_succeeds_in_enforced_read_only_snapshot']='PASS'
        bulk='e'*64;atbulk=T+5*FIVE_NS
        apply_window(store,packet(atbulk,{SERVICE:2050},session=bulk,offset=90000))
        raw.execute("UPDATE anomaly_detection.adp_facts SET details=jsonb_build_object('source_present',true,'semantic',body::jsonb,'quality',jsonb_build_object('evidence_available',true,'conflicted',false))::text WHERE session_key=%s",(bulk,))
        bulk_result=primary(store,bulk,atbulk)
        bulk_proof=collect(store,bulk,atbulk)
        assert bulk_proof['status']=='PASS_REVIEWABLE_RATE_FINDING' and bulk_proof['services'][0]['qualified_evidence_executions']==2050,bulk_proof
        checks['oversized_canonical_target_uses_exact_sql_counts_and_qualification_not_clipped_sample']='PASS_2050_EXACT_NOT_2048'
        # A real semantic reference correction invalidates the primary token
        # and rejects an old in-flight publish; secondary exemption is narrow.
        j=job(store,at=T+2*FIVE_NS);c=context(store,j)
        from anomaly_detection.model_queue import reference_changed
        reference_changed(store,[(SERVICE,T-FIVE_NS)])
        assert job(store,at=T+2*FIVE_NS)['primary_version']>j['primary_version']
        assert store.complete(j,c,[],T+30*FIVE_NS)['status']=='INPUT_CHANGED_RETRY'
        assert collect(store,ACTOR,T+2*FIVE_NS)['status']=='NOT_READY_OR_LIMITED'
        checks['real_reference_correction_stales_primary_and_old_commit_is_rejected']='PASS_VERSION_AND_DEPENDENCY_FENCE'
        report={'build_id':BUILD_ID,'status':'PASS_PRIMARY_EVIDENCE_AND_SECONDARY_RETRY_SQL','checks':checks,
            'owner_connections':0,'native_windows_postgresql':'NOT_RUN','production_precision_recall_and_capacity':'NOT_MEASURED','source_modified':False}
        (ROOT/'validation/PRODUCT_revision18.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
    finally:engine.close()


if __name__=='__main__':main()
