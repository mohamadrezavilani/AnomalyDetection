"""End-to-end continuous/multi-entity cases on disposable PostgreSQL/WASM.

No owner connection. In particular the split-burst fixture is NOT an owner
holdout, and none of these checks establish production precision or capacity.
"""
from datetime import datetime
from pathlib import Path
import json
from unittest.mock import patch
from types import SimpleNamespace
from transport import Engine
from anomaly_detection import BUILD_ID,FIVE_NS
from anomaly_detection.product_store import ProductStore
from anomaly_detection.product_pipeline import apply_window,owned_context
from anomaly_detection.product_engine import evaluate_job
from anomaly_detection.snapshot import canonical,digest
from anomaly_detection.cases import identity,replace_scope,normal_observations,current,feedback
from anomaly_detection.population import assess,save_relations,enqueue,process_one
from anomaly_detection.product_web import render
from check_revision10 import packet,metadata,SERVICES

ROOT=Path(__file__).resolve().parents[2]
T=int(datetime.fromisoformat('2026-11-04T00:00:00+03:30').timestamp())*10**9
ACTOR='a'*64;SERVICE=SERVICES[0]


def merged_packet(at,groups,offset):
    p=packet(at,{});p['rows']=[]
    for session,n,anchor in groups:
        q=packet(at,{SERVICE:n},session=session,offset=offset+len(p['rows']))
        for i,row in enumerate(q['rows']):row['anchor_ns']=anchor+i
        p['rows']+=q['rows']
    return p


def qualify(raw,session):
    for row in raw.execute('SELECT request_key,body FROM anomaly_detection.adp_facts WHERE session_key=%s',(session,)).fetchall():
        e=json.loads(row['body'])
        fact={'request_key':row['request_key'],'semantic':e,'source_present':True,
            'quality':{'evidence_available':True,'conflicted':False},
            'transport':{'root_call':SERVICE,'root_code':'G00000','started_ns':e['anchor_ns'],'ended_ns':e['anchor_ns']+1},
            'observations':[],'identifiers':[],'relations':[],'evidence':[]}
        raw.execute('UPDATE anomaly_detection.adp_facts SET details=%s,details_digest=%s WHERE request_key=%s',
            (canonical(fact),digest(fact),row['request_key']))


def evaluated(store,session,target,now=None):
    job=dict(store.raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(session,target)).fetchone())
    context=owned_context(store,job);assert context is not None
    context=store.save_context(job,context);job['version']=context['job_version']
    return evaluate_job(store,job,context,T+20*FIVE_NS if now is None else now)


def main():
    engine=Engine();checks={}
    try:
        raw=engine.connect();raw.execute('CREATE SCHEMA anomaly_detection');store=ProductStore(raw);store.initialize()
        # Complete census coverage, not a fabricated absence in retained logs.
        proof=metadata(T)|{'peer_population_valid':True,'scope_contract':'atomic-lane-window-v3'}
        raw.execute("INSERT INTO anomaly_detection.adp_source_windows SELECT at,'coverage',%s,TRUE FROM generate_series(%s::bigint,%s::bigint,%s::bigint) at",
            (canonical(proof),T-4*288*FIVE_NS,T+10*FIVE_NS,FIVE_NS))
        # Other actors have 30 executions per burst, separated by 43 hours.
        # Every reference uses exactly the same event-aligned duration.
        sessions=[f'{i+1000:064x}' for i in range(320)]
        for k,at in enumerate((T-2*288*FIVE_NS+24*FIVE_NS,T-36*FIVE_NS)):
            p=merged_packet(at,[(s,30,at+1_000_000_000) for s in sessions],100000+k*10000)
            apply_window(store,p,cursor_name='reference')
        # 20 + 20 executions straddle Tehran midnight and a five-minute fence.
        # Neither aligned window exceeds the reference of 30.
        apply_window(store,merged_packet(T-FIVE_NS,[(ACTOR,20,T-30_000_000_000)],400000),cursor_name='before_midnight')
        apply_window(store,merged_packet(T,[(ACTOR,20,T+60_000_000_000)],500000),cursor_name='after_midnight')
        qualify(raw,ACTOR)
        result=evaluated(store,ACTOR,T);assert result['status']=='APPLIED'
        grid=[d for d in result['decisions'] if d['family']=='peer_service_rate_5m']
        assert grid and grid[0]['status']=='NO_DEVIATION_OBSERVED' and grid[0]['observed']==20,grid
        rolling=[d for d in result['decisions'] if d['family']=='continuous_rate' and d['duration_ns']<=288*FIVE_NS]
        assert len(rolling)==3 and all(d['status']=='CANDIDATE' and d['observed']==40 for d in rolling),rolling
        key=identity('actor',ACTOR,'activity',SERVICE)
        case=raw.execute('SELECT * FROM anomaly_detection.adp_cases WHERE case_key=%s',(key,)).fetchone()
        body=json.loads(case['body'])
        assert body['distinct_executions']==40 and body['distinct_sessions']==1 and case['state']=='NEEDS_REVIEW',body
        assert T-30_000_000_000<=body['first_ns']<T and body['last_ns']>T
        assert current(store,key)
        checks['split_burst_crosses_midnight_and_source_fence_grid20_is_not_high_exact_rolling40_is_high']='PASS_320_OTHER_SESSIONS_19200_REFERENCE_EXECUTIONS'
        checks['three_rolling_horizons_create_one_case_and_40_unique_executions_not_120']='PASS'
        checks['first_and_last_case_times_are_actual_behavior_times_not_empty_lookback_bounds']='PASS'
        # A new actor's ordinary single execution is measured by the same model.
        normal='9'*64
        apply_window(store,merged_packet(T+2*FIVE_NS,[(normal,1,T+2*FIVE_NS+1)],600000),cursor_name='normal')
        normal_result=evaluated(store,normal,T+2*FIVE_NS)
        assert not any(d['status']=='CANDIDATE' for d in normal_result['decisions']),normal_result
        assert all(d['status']=='NO_DEVIATION_OBSERVED' for d in normal_result['decisions'] if d['family']=='continuous_rate' and d['duration_ns']<=288*FIVE_NS)
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_cases WHERE entity_key=%s',(normal,)).fetchone()['n']==0
        checks['ordinary_control_is_current_and_has_no_candidate_without_tuning_a_threshold']='PASS_SYNTHETIC_NOT_OWNER_CONTROL'
        # Reprocessing the same target changes neither execution count, episode
        # count nor case revision. Extra evidence revises the signal, not history.
        before=dict(raw.execute('SELECT * FROM anomaly_detection.adp_cases WHERE case_key=%s',(key,)).fetchone())
        evaluated(store,ACTOR,T)
        assert dict(raw.execute('SELECT * FROM anomaly_detection.adp_cases WHERE case_key=%s',(key,)).fetchone())==before
        checks['replay_does_not_create_case_occurrence_or_revision']='PASS'
        # Another kind of issue is separate, while same-kind reappearance keeps
        # the case key and its old evidence/reviews.
        job={'session_key':ACTOR,'target_ns':T,'version':raw.execute('SELECT version FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(ACTOR,T)).fetchone()['version']}
        otp={'signal_key':'synthetic-otp','family':'otp_result_change','service_path':SERVICE,'status':'CANDIDATE',
            'evidence_verified':True,'begin_ns':T,'end_ns':T+FIVE_NS,'score':10,'observed':10,'reason':'SYNTHETIC_REVIEW_ONLY',
            'explanation_fa':'شرح آزمایشی <script>باید escape شود</script>'}
        with store.transaction():replace_scope(store,'different_kind',[otp],T+10*FIVE_NS,job=job)
        otp_key=identity('actor',ACTOR,'otp',SERVICE)
        assert otp_key!=key and raw.execute('SELECT 1 FROM anomaly_detection.adp_cases WHERE case_key=%s',(otp_key,)).fetchone()
        checks['different_issue_kind_is_a_separate_case_for_the_same_actor_and_service']='PASS'
        # Normal evidence ends the observed period without erasing past anomaly
        # evidence or asserting the entire user is benign.
        old_requests=body['distinct_executions']
        normals=[{'family':'continuous_rate','service_path':SERVICE,'duration_ns':s,'status':'NO_DEVIATION_OBSERVED',
            'target_ns':T+4*FIVE_NS} for s in (FIVE_NS,12*FIVE_NS,288*FIVE_NS)]
        with store.transaction():normal_observations(store,normals,T+5*FIVE_NS,entity_key=ACTOR)
        closed=json.loads(raw.execute('SELECT body FROM anomaly_detection.adp_cases WHERE case_key=%s',(key,)).fetchone()['body'])
        assert closed['phase']=='NO_CURRENT_SIGNAL' and closed['distinct_executions']==old_requests
        apply_window(store,merged_packet(T+8*FIVE_NS,[(ACTOR,50,T+8*FIVE_NS+1)],700000),cursor_name='returned')
        qualify(raw,ACTOR);evaluated(store,ACTOR,T+8*FIVE_NS)
        reopened=json.loads(raw.execute('SELECT body FROM anomaly_detection.adp_cases WHERE case_key=%s',(key,)).fetchone()['body'])
        assert reopened['phase']=='RETURNED'
        checks['quiet_then_returned_issue_keeps_identity_and_historical_evidence']='PASS'
        late=raw.execute('SELECT request_key,details FROM anomaly_detection.adp_facts WHERE session_key=%s ORDER BY at_ns LIMIT 1',(ACTOR,)).fetchone()
        late_fact=json.loads(late['details']);late_fact['quality']['identity_state']='assigned'
        completed=T+288*FIVE_NS
        late_fact['observations'].append({'axis':'service_dispatch.inquiry_result','qualified':True,'value':'GD9999','at_ns':completed})
        snapshot=SimpleNamespace(keys=[late['request_key']],source=metadata(T)|{'captured_at_ns':completed},
            requests={late['request_key']:{'session_key':ACTOR}},facts=lambda:[late_fact])
        before_late=json.loads(raw.execute('SELECT body FROM anomaly_detection.adp_cases WHERE case_key=%s',(key,)).fetchone()['body'])
        store.apply_audit(snapshot)
        evaluated(store,ACTOR,T,completed+1);evaluated(store,ACTOR,T+8*FIVE_NS,completed+2)
        after_late=json.loads(raw.execute('SELECT body FROM anomaly_detection.adp_cases WHERE case_key=%s',(key,)).fetchone()['body'])
        assert after_late['distinct_executions']==before_late['distinct_executions'] and after_late['episodes']==before_late['episodes']
        assert after_late['evidence_last_change_ns']==completed and after_late['last_ns']==before_late['last_ns']
        checks['yesterday_request_completed_a_day_later_updates_same_case_evidence_without_new_execution_or_episode']='PASS'
        # Delegated Viewer relations are positive evidence only. A complete
        # correction removes an old relation; a truncated read cannot invent one.
        requests=[r['request_key'] for r in raw.execute('SELECT request_key FROM anomaly_detection.adp_facts WHERE session_key=%s ORDER BY at_ns LIMIT 2',(ACTOR,)).fetchall()]
        edge={'from_request_key':requests[0],'to_request_key':requests[1],'basis':'shared_typed_invoice',
            'identity_key':'typed-invoice','certainty':'same_reference_not_same_execution'}
        with store.transaction():save_relations(store,requests[0],{'journey':{'edges':[edge],'truncated':False}},T)
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_viewer_relations').fetchone()['n']==1
        with store.transaction():save_relations(store,requests[0],{'journey':{'edges':[],'truncated':True}},T+1)
        assert not raw.execute('SELECT current_verified FROM anomaly_detection.adp_viewer_relations').fetchone()['current_verified']
        with store.transaction():save_relations(store,requests[0],{'journey':{'edges':[],'truncated':False}},T+2)
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_viewer_relations').fetchone()['n']==0
        checks['viewer_typed_relations_are_reused_and_corrected_without_session_time_heuristics']='PASS'
        # A late semantic change makes the old census unknown until atomic
        # repair publishes the new membership; it does not erase the old body.
        revised=dict(packet(T,{SERVICE:1},session=ACTOR,offset=500000)['rows'][0],revision=2,anchor_ns=T+60_000_000_000)
        old_body=raw.execute('SELECT body FROM anomaly_detection.adp_windows WHERE session_key=%s AND start_ns=%s',(ACTOR,T)).fetchone()['body']
        store.apply_rows([revised],metadata(T))
        proof_now=raw.execute('SELECT source,complete FROM anomaly_detection.adp_source_windows WHERE start_ns=%s',(T,)).fetchone()
        assert not proof_now['complete'] and json.loads(proof_now['source'])['needs_scope_repair']
        assert raw.execute('SELECT body FROM anomaly_detection.adp_windows WHERE session_key=%s AND start_ns=%s',(ACTOR,T)).fetchone()['body']==old_body
        assert not current(store,key)
        checks['late_semantic_revision_invalidates_population_proof_preserves_history_and_marks_case_stale']='PASS'
        # Summary and detail views are read-only, full identifiers and feedback
        # are retained, and untrusted explanation/note strings are escaped.
        page=render(store,{},'/incidents',{'state':['ALL'],'view':['cases']},'test-token')
        detail=render(store,{},'/case/'+otp_key,{},'test-token')
        assert 'dir="rtl"' in page and 'شواهد و تاریخچه' in page and '40' in page
        assert '<script>باید' not in detail and '&lt;script&gt;' in detail and ACTOR in detail
        feedback(store,otp_key,'needs_evidence','<img src=x> یادداشت',T+20*FIVE_NS)
        detail=render(store,{},'/case/'+otp_key,{},'test-token')
        assert '&lt;img src=x&gt;' in detail
        checks['issue_summary_inline_history_full_identity_legacy_links_feedback_and_rtl_are_read_only_and_escaped']='PASS_RENDERED_HTML'
        report={'build_id':BUILD_ID,'status':'PASS_CONTINUOUS_AND_STABLE_CASE_SQL_ISOLATED','checks':checks,
            'owner_connections':0,'native_windows_postgresql':'NOT_RUN','native_owner_negative_control':'PENDING_POST_INSTALL',
            'production_precision_recall_and_capacity':'NOT_MEASURED','sqlite':'NOT_IMPORTED','source_modified':False}
        (ROOT/'validation/PRODUCT_revision16.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
    finally:engine.close()


if __name__=='__main__':main()
