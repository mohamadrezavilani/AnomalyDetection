"""Cumulative content -> owned SQL -> stable case -> NOC -> versioned feedback.

Disposable PGlite SQL engine only. No owner connection or native server claim.
"""
from pathlib import Path
from unittest.mock import patch
import json
from transport import Engine
from anomaly_detection import BUILD_ID,FIVE_NS
from anomaly_detection.snapshot import canonical,digest,ContractError
from anomaly_detection.product_store import ProductStore
from anomaly_detection.scenario_store import enqueue,scope_key,process_one,save_profile,volume_history
from anomaly_detection.longitudinal import DAY,context,reference,seed,coverage_changed
from anomaly_detection.request_profiles import VERSION,input_features
from anomaly_detection.cases import identity,replace_scope,feedback,review_token
from anomaly_detection.case_summary import case_status
from anomaly_detection.noc_evidence import read,aggregate
from anomaly_detection.product_web import render
from check_revision10 import metadata

ROOT=Path(__file__).resolve().parents[2]
T=1800000000000000000//FIVE_NS*FIVE_NS
SERVICE='Fixture.v1/LongBills'
ACTOR='a'*64


def insert(raw,table,columns,rows):
    if rows:raw.execute('INSERT INTO anomaly_detection.'+table+'('+','.join(k for k,t in columns)+') SELECT * FROM jsonb_to_recordset(%s::jsonb) AS x('+','.join(k+' '+t for k,t in columns)+')',(canonical(rows),))


def add_requests(raw,items):
    facts=[];profiles=[];members=[]
    for actor,service,at,bill,ip in items:
        key=digest([actor,service,at,bill]);anchor='ba1:'+digest(['anchor',key])
        subjects=[dict(x,channel=service) for x in input_features({'BillID':bill},service)['subjects']]
        p={'version':VERSION,'request_key':key,'session_key':actor,'service_path':service,'at_ns':at,'ended_ns':at+1,
            'semantic_active':True,'semantic_revision':1,'anchor_key':anchor,'actor_qualified':True,'qualified':True,'input_complete':True,
            'content_complete':True,'subjects':subjects,'targets':{service:digest(bill)},'ip_keys':[digest(ip)],'ip_display':{digest(ip):ip},
            'witnesses':[{'at_ns':at,'origin_key':digest(key),'version_key':digest(['v',key])}],
            'result':{'scope':'fixture','code':'G00000'}}
        f={'request_key':key,'anchor_key':anchor,'session_key':actor,'at_ns':at,'service_path':service,'kind':'service_execution',
            'state':'active','revision':1,'eligible':True,'body':canonical({'request_key':key}),'content_digest':digest(key),'last_seen_ns':T}
        facts.append(f);profiles.append({'request_key':key,'session_key':actor,'service_path':service,'at_ns':at,'body':canonical(p),'content_digest':digest(p),'observed_ns':T})
        members.append({'start_ns':at//FIVE_NS*FIVE_NS,'request_key':key,'body':'{}'})
    insert(raw,'adp_facts',[(k,'BIGINT' if k in ('at_ns','revision','last_seen_ns') else 'BOOLEAN' if k=='eligible' else 'TEXT') for k in facts[0]],facts)
    insert(raw,'adp_profiles',[(k,'BIGINT' if k in ('at_ns','observed_ns') else 'TEXT') for k in profiles[0]],profiles)
    insert(raw,'adp_window_members',[('start_ns','BIGINT'),('request_key','TEXT'),('body','TEXT')],members)
    return profiles


def main():
    e=Engine();checks={}
    try:
        raw=e.connect();raw.execute('CREATE SCHEMA anomaly_detection');s=ProductStore(raw);s.initialize()
        windows=[{'start_ns':at,'stamp':str(at),'source':canonical({'peer_population_valid':True}),'complete':True} for at in range(T-3*DAY,T+FIVE_NS,FIVE_NS)]
        insert(raw,'adp_source_windows',[('start_ns','BIGINT'),('stamp','TEXT'),('source','TEXT'),('complete','BOOLEAN')],windows)
        peers=[f'{i:064x}' for i in range(1,1001)]
        items=[(who,SERVICE,T-(2-d)*DAY-FIVE_NS+1,'00123000','192.0.2.1') for who in peers for d in range(3)]
        items+=[(ACTOR,SERVICE,T-(2-d)*DAY+1,'0012300'+str(d),'192.0.2.'+str(d+2)) for d in range(3)]
        ps=add_requests(raw,items)
        enqueue(s,'longitudinal',ACTOR,SERVICE,T)
        result=process_one(s,T+FIVE_NS)
        assert result['status']=='APPLIED',result
        long=next(d for d in result['decisions'] if d['family']=='long_subject_enumeration' and d['duration_ns']==3*DAY)
        assert long['status']=='CANDIDATE' and long['observed']==3 and long['reference_max']==1 and long['reference_actors']==1000,long
        assert long['single_signal_review_eligible'] and long['evidence_verified']
        daily=next(d for d in result['decisions'] if d['family']=='long_subject_enumeration' and d['duration_ns']==DAY)
        assert daily['status']=='NO_DEVIATION_OBSERVED',daily
        key=identity('actor',ACTOR,'subject_enumeration',SERVICE)
        assert case_status(s,key)['bucket']=='READY'
        body=json.loads(raw.execute('SELECT body FROM anomaly_detection.adp_cases WHERE case_key=%s',(key,)).fetchone()['body'])
        assert body['distinct_executions']==3 and body['distinct_sessions']==1,body
        checks['ordinary_daily_one_bill_but_three_day_distinct_bill_pattern']='PASS_1000_COMPLETE_OTHER_ACTOR_SQL_COHORTS'
        checks['sql_reference_aggregation_transfers_actor_metrics_not_3000_profile_bodies']='PASS_EXACT_SQL_DISTINCT_AND_COMPLETENESS'
        job=raw.execute('SELECT * FROM anomaly_detection.adp_scenario_jobs WHERE scope_key=%s',(result['scope_key'],)).fetchone()
        rows,covered,bounded,receipt,refs=context(s,job)
        assert len(rows)==3 and len(refs[3*DAY])==1000 and bounded and receipt['queued_profile_repairs']==0,receipt
        before=raw.execute('SELECT revision,body FROM anomaly_detection.adp_cases WHERE case_key=%s',(key,)).fetchone()
        enqueue(s,'longitudinal',ACTOR,SERVICE,T);process_one(s,T+2*FIVE_NS)
        after=raw.execute('SELECT revision,body FROM anomaly_detection.adp_cases WHERE case_key=%s',(key,)).fetchone()
        assert before==after,(before,after)
        checks['same_case_and_same_revision_on_identical_longitudinal_replay']='PASS'
        coverage_changed(s,T-2*DAY)
        assert case_status(s,key)['bucket']=='RECHECK'
        raw.execute('UPDATE anomaly_detection.adp_source_windows SET complete=FALSE WHERE start_ns=%s',(T-2*DAY,))
        process_one(s,T+3*FIVE_NS)
        assert case_status(s,key)['bucket']!='READY'
        assert raw.execute("SELECT 1 FROM anomaly_detection.adp_case_signals WHERE case_key=%s AND state='DEFERRED'",(key,)).fetchone()
        assert raw.execute('SELECT COUNT(DISTINCT request_key) AS n FROM anomaly_detection.adp_case_requests WHERE case_key=%s',(key,)).fetchone()['n']==3
        raw.execute('UPDATE anomaly_detection.adp_source_windows SET complete=TRUE WHERE start_ns=%s',(T-2*DAY,));coverage_changed(s,T-2*DAY)
        process_one(s,T+4*FIVE_NS);assert case_status(s,key)['bucket']=='READY'
        checks['historical_partition_gap_invalidates_long_case_and_completion_rechecks_it']='PASS_NO_FALSE_NORMAL'
        enqueue(s,'longitudinal',ACTOR,SERVICE,T);chosen=result['scope_key'];execute=raw.execute;fired=False
        def interleave(sql,args=()):
            nonlocal fired
            if 'SELECT version FROM anomaly_detection.adp_scenario_jobs' in sql and 'FOR UPDATE' in sql and not fired:
                fired=True;execute('UPDATE anomaly_detection.adp_scenario_jobs SET version=version+1 WHERE scope_key=%s',(chosen,))
            return execute(sql,args)
        with patch.object(raw,'execute',side_effect=interleave):retry=process_one(s,T+5*FIVE_NS)
        assert fired and retry['status']=='INPUT_CHANGED_RETRY';process_one(s,T+6*FIVE_NS)
        checks['longitudinal_input_cas_rejects_outdated_result']='PASS_INJECTED_INTERLEAVING_NOT_NATIVE_CONCURRENCY'
        # A reference actor with a missing profile is excluded in its entirety.
        missing=ps[0];raw.execute('DELETE FROM anomaly_detection.adp_profiles WHERE request_key=%s',(missing['request_key'],))
        rows,covered,bounded,receipt,refs=context(s,job)
        assert sum(x['qualified'] for x in refs[3*DAY])==999 and receipt['queued_profile_repairs']==1,receipt
        assert raw.execute('SELECT 1 FROM anomaly_detection.adp_profile_tasks WHERE request_key=%s',(missing['request_key'],)).fetchone()
        insert(raw,'adp_profiles',[(k,'BIGINT' if k in ('at_ns','observed_ns') else 'TEXT') for k in missing],[missing])
        raw.execute('DELETE FROM anomaly_detection.adp_profile_tasks WHERE request_key=%s',(missing['request_key'],))
        checks['partial_reference_is_not_a_small_normal_actor_and_missing_profile_is_queued']='PASS'
        # Real case membership, not a synthetic HTML-only 100 number.
        water='Fixture.v1/Water';water_actor='b'*64
        water_ps=add_requests(raw,[(water_actor,water,T+i+1,'00987654321','198.51.100.'+str(i%3+1)) for i in range(100)])
        scope=scope_key('actor',water_actor,water,T);enqueue(s,'actor',water_actor,water,T)
        signal={'signal_key':'sf1:'+digest(scope),'family':'repeated_target','entity_type':'actor','entity_key':water_actor,'service_path':water,
            'begin_ns':T,'end_ns':T+FIVE_NS,'duration_ns':FIVE_NS,'status':'CANDIDATE','observed':100,'expected':1,
            'evidence_verified':True,'single_signal_review_eligible':True,'request_keys':[p['request_key'] for p in water_ps],
            'explanation_fa':'۱۰۰ درخواست یکتا برای یک BillID؛ شاهد محتوایی آزمون کنترل‌شده.'}
        with s.transaction():replace_scope(s,scope,[signal],T+7*FIVE_NS,source_kind='feature',job={'session_key':water_actor,'target_ns':T,'version':1})
        raw.execute("UPDATE anomaly_detection.adp_scenario_jobs SET dirty=FALSE,processed_version=version,evaluation='{}' WHERE scope_key=%s",(scope,))
        wk=identity('actor',water_actor,'repeat_target',water)
        rows,total,complete=read(s,wk);a=aggregate(rows)
        assert total==100 and complete and a['qualified']==100 and len(a['fields'][(water,'$.BillID')])==1
        assert len(a['tokens'][0]['requests'])==100 and len(a['ips'])==3,a
        with raw.transaction():
            raw.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            raw.execute("SET LOCAL statement_timeout='3s'")
            for path in ('/','/incidents','/coverage','/case/'+wk,'/case/'+key,'/scenario-evaluation/'+chosen):
                html=render(s,{},path,{},'token');assert 'dir="rtl"' in html
                if path=='/case/'+wk:
                    assert 'یک قبض یا چند قبض' in html and '100' in html and '198.51.100.1' in html
                    assert 'بازخورد' in html and 'case_revision' in html and 'لاگ و مراحل' in html
                    (ROOT/'validation/NOC_case25_fixture.html').write_text(html)
                assert raw.execute("SELECT current_setting('statement_timeout') AS v").fetchone()['v']=='3s'
        checks['one_bill_100_requests_three_client_ips_with_readonly_noc_drilldown']='PASS_EXACT_REQUEST_MEMBERSHIP'
        checks['dashboard_unified_list_coverage_case_and_method_pages_readonly_and_budget_restored']='PASS_SQL_HTML_NOT_BROWSER'
        # Feedback is tied to a reviewed revision. A stale browser cannot review
        # data that appeared after the page was displayed.
        rev=raw.execute('SELECT revision FROM anomaly_detection.adp_cases WHERE case_key=%s',(wk,)).fetchone()['revision']
        try:feedback(s,wk,'reviewed_benign','old page',T+8*FIVE_NS,expected_revision=rev+1)
        except ContractError as ex:assert str(ex)=='CASE_CHANGED_SINCE_DISPLAY'
        else:raise AssertionError('stale review was accepted')
        assert not raw.execute('SELECT 1 FROM anomaly_detection.adp_case_feedback WHERE case_key=%s',(wk,)).fetchone()
        feedback(s,wk,'reviewed_benign','normal repeat verified by operator',T+8*FIVE_NS,expected_revision=rev)
        # Same service reference exposes this reviewed actor to another target.
        rm,_=reference(s,water,T+FIVE_NS,T-12*FIVE_NS,[water_actor],[12*FIVE_NS])
        assert rm[12*FIVE_NS][0]['qualified']
        stale_token=review_token(s,wk)
        p=json.loads(water_ps[0]['body']);p['subjects'][0]['display']='…changed-label'
        save_profile(s,{'source':metadata(T),'request_key':p['request_key'],'profile':p},T+9*FIVE_NS)
        assert raw.execute('SELECT revision FROM anomaly_detection.adp_cases WHERE case_key=%s',(wk,)).fetchone()['revision']==rev
        try:feedback(s,wk,'reviewed_benign','unseen new input',T+10*FIVE_NS,expected_revision=rev,expected_input_token=stale_token)
        except ContractError as ex:assert str(ex)=='CASE_INPUT_CHANGED_SINCE_DISPLAY'
        else:raise AssertionError('new evidence before case rebuild accepted an old review token')
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_case_feedback WHERE case_key=%s',(wk,)).fetchone()['n']==1
        checks['stale_input_receipt_is_rejected_before_case_revision_has_been_rebuilt']='PASS_SQL_NO_FEEDBACK_INSERTED'
        rm,repair=reference(s,water,T+FIVE_NS,T-12*FIVE_NS,[water_actor],[12*FIVE_NS])
        assert not rm[12*FIVE_NS][0]['qualified'] and not repair
        checks['feedback_is_revision_checked_and_benign_training_permission_does_not_cover_later_evidence']='PASS_SQL'
        volume='Fixture.v1/VolumeFeedback';vscope=scope_key('canonical_traffic',volume,volume,T)
        enqueue(s,'canonical_traffic',volume,volume,T)
        point={'start_ns':T,'executions':0,'sessions':0,'covered':True}
        raw.execute('INSERT INTO anomaly_detection.adp_population VALUES(%s,%s,%s,%s)',(volume,T,canonical(point),digest(point)))
        raw.execute('INSERT INTO anomaly_detection.adp_traffic_counts VALUES(%s,%s,%s)',(volume,T,canonical({'start_ns':T,'requests':100,'sessions':5,'complete':True})))
        vd={'signal_key':'sf1:'+digest(vscope),'family':'service_volume','entity_type':'service','entity_key':volume,'service_path':volume,
            'begin_ns':T,'end_ns':T+FIVE_NS,'status':'CANDIDATE','observed':0,'expected':100,'direction':'decrease',
            'evidence_verified':True,'single_signal_review_eligible':True,'request_keys':[],'count_scope':'canonical_meaningful_executions'}
        with s.transaction():replace_scope(s,vscope,[vd],T+10*FIVE_NS,source_kind='feature',job={'target_ns':T,'version':1})
        vk=identity('service',volume,'service_volume',volume)
        assert not volume_history(s,volume,T+FIVE_NS,canonical_scope=True)
        assert len(volume_history(s,volume,T+FIVE_NS,canonical_scope=False))==1
        vrev=raw.execute('SELECT revision FROM anomaly_detection.adp_cases WHERE case_key=%s',(vk,)).fetchone()['revision']
        feedback(s,vk,'reviewed_benign','volume change approved',T+11*FIVE_NS,expected_revision=vrev)
        assert len(volume_history(s,volume,T+FIVE_NS,canonical_scope=True))==1
        with s.transaction():replace_scope(s,vscope,[vd],T+12*FIVE_NS,source_kind='feature',job={'target_ns':T,'version':2})
        assert raw.execute('SELECT revision FROM anomaly_detection.adp_cases WHERE case_key=%s',(vk,)).fetchone()['revision']==vrev
        assert len(volume_history(s,volume,T+FIVE_NS,canonical_scope=True))==1
        with s.transaction():replace_scope(s,vscope,[dict(vd,observed=20)],T+13*FIVE_NS,source_kind='feature',job={'target_ns':T,'version':3})
        assert not volume_history(s,volume,T+FIVE_NS,canonical_scope=True)
        checks['volume_feedback_quarantine_respects_count_scope_and_survives_token_only_replay_but_not_changed_evidence']='PASS_SQL'
        # Singleton requests get long-content jobs as well as busy scopes.
        seed(s,limit=8)
        assert raw.execute("SELECT 1 FROM anomaly_detection.adp_scenario_jobs WHERE kind='longitudinal' AND entity_key=ANY(%s) LIMIT 1",(peers,)).fetchone()
        checks['automatic_seeding_includes_low_rate_singleton_actor_windows']='PASS_KEYSET_SEED'
        from datetime import datetime
        from zoneinfo import ZoneInfo
        ns=int(datetime(2026,11,6,tzinfo=ZoneInfo('Asia/Tehran')).timestamp())*1_000_000_000
        date_service='Fixture.v1/DateBoundary';date_actor='d'*64
        add_requests(raw,[(date_actor,date_service,ns-1,'date-bill','192.0.2.1'),(date_actor,date_service,ns,'date-bill','192.0.2.1')])
        rm,_=reference(s,date_service,ns+FIVE_NS,ns-1_000_000_000,[date_actor],[FIVE_NS+1_000_000_000])
        assert rm[FIVE_NS+1_000_000_000][0]['active_days']==2
        checks['sql_tehran_day_boundary_preserves_nanosecond_before_midnight']='PASS_INTEGER_SECOND_PROJECTION'
        report={'build_id':BUILD_ID,'status':'PASS_LONGITUDINAL_NOC_AND_FEEDBACK_SQL','checks':checks,
            'owner_connections':0,'engine':'PGlite PostgreSQL WASM single-session fixture',
            'native_windows_postgresql':'NOT_RUN','browser_layout':'NOT_RUN','production_precision_recall_and_capacity':'NOT_MEASURED',
            'cross_session_person_resolution':'BLOCKED_NO_VERIFIED_STABLE_PRINCIPAL_IN_PINNED_SOURCE',
            'financial_acceptance':'BLOCKED_EXTERNAL_DEPENDENCY','source_modified':False}
        (ROOT/'validation/PRODUCT_revision25.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');print(json.dumps(report))
    finally:e.close()


if __name__=='__main__':main()
