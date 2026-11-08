"""Grouped review, effect qualification and preserved evidence on isolated PG."""
import argparse,json,zipfile
from pathlib import Path
from transport import Engine
from anomaly_detection import BUILD_ID,FIVE_NS
from anomaly_detection.product_store import ProductStore
from anomaly_detection.product_pipeline import apply_window
from anomaly_detection.cases import replace_scope,requalify,identity
from anomaly_detection.case_summary import statistics,groups,render,filters,case_status
from anomaly_detection.product_web import render as page_render
from anomaly_detection.review_policy import eligible
from anomaly_detection.population import process_one,enqueue
from anomaly_detection.snapshot import canonical
from check_revision16 import T,merged_packet,SERVICE

ROOT=Path(__file__).resolve().parents[2]


def load(raw,table,rows):
    if table=='adp_jobs':
        for row in rows:row.setdefault('primary_version',1)
    if rows:raw.execute('INSERT INTO anomaly_detection.'+table+' SELECT * FROM jsonb_populate_recordset(NULL::anomaly_detection.'+table+',%s::jsonb)',(canonical(rows),))


def snapshot_check(raw,path):
    with zipfile.ZipFile(path) as z:
        read=lambda n:[json.loads(x) for x in z.read(n+'.jsonl').decode().splitlines()]
        for table,name in [('adp_cases','cases'),('adp_case_signals','case_signals'),('adp_case_requests','case_members'),('adp_jobs','case_jobs')]:load(raw,table,read(name))
        store=ProductStore(raw);stats=statistics(store)
        assert stats['READY']['cases']==2 and stats['READY']['actors']==2 and stats['READY']['services']==2,stats
        _,_,_,condition,params=filters({});rows,metrics,leads=groups(store,'services',condition,params,0)
        assert len(rows)==2 and {r['group_key'] for r in rows}=={'Public.v1/ExchangeCrypto','Services.v1/IdentificationDocumentsStatusCar'}
        for view in ('services','actors','cases'):
            html=page_render(store,{},'/incidents',{'view':[view]},'token')
            assert 'dir="rtl"' in html and 'مرجع' in html
        report={'build_id':BUILD_ID,'status':'PASS_OWNER_SNAPSHOT_REVIEW_VIEW_REPLAY_NOT_OWNER_SERVER',
            'source_cases':987,'current_actor_cases_with_reference_contrast':2,'population_job_rows':'NOT_EXPORTED_CANNOT_VERIFY_CURRENTNESS',
            'production_precision_recall':'NOT_MEASURED','source_modified':False}
        print(json.dumps(report));return


def main(path=None):
    engine=Engine();checks={}
    try:
        raw=engine.connect();raw.execute('CREATE SCHEMA anomaly_detection');store=ProductStore(raw);store.initialize()
        if path:return snapshot_check(raw,path)
        actors=['a'*64,'b'*64,'c'*64]
        apply_window(store,merged_packet(T,[(a,n,T+1) for a,n in zip(actors,[20,9,25])],100000),cursor_name='fixture')
        jobs={r['session_key']:dict(r) for r in raw.execute('SELECT * FROM anomaly_detection.adp_jobs').fetchall()}
        for actor,observed,bound in zip(actors,[20,9,25],[3,20,3]):
            item={'signal_key':'test:'+actor,'family':'peer_service_rate_5m','service_path':SERVICE,'status':'CANDIDATE',
              'observed':observed,'expected':1,'upper':bound,'evidence_verified':True,'single_signal_review_eligible':True,'begin_ns':T,'end_ns':T+FIVE_NS,'score':observed/max(1,bound)}
            with store.transaction():replace_scope(store,'actor:'+actor,[item],T+FIVE_NS,job=jobs[actor])
        # Reproduce a legacy promotion from rarity while staying within the
        # observed reference range. The view must reject it before migration.
        weak=identity('actor',actors[1],'activity',SERVICE)
        raw.execute('UPDATE anomaly_detection.adp_case_signals SET review_eligible=TRUE WHERE case_key=%s',(weak,))
        raw.execute("UPDATE anomaly_detection.adp_cases SET state='NEEDS_REVIEW' WHERE case_key=%s",(weak,))
        raw.execute('UPDATE anomaly_detection.adp_jobs SET dirty=FALSE,processed_version=version')
        raw.execute('UPDATE anomaly_detection.adp_jobs SET dirty=TRUE,version=version+1,primary_version=primary_version+1 WHERE session_key=%s',(actors[2],))
        seq={'signal_key':'sequence:'+actors[0],'family':'service_sequence','service_path':SERVICE,'status':'CANDIDATE',
          'evidence_verified':True,'single_signal_review_eligible':True,'review_basis':'QUALIFIED_INDEPENDENT_DIMENSIONS','begin_ns':T,'end_ns':T+FIVE_NS}
        with store.transaction():replace_scope(store,'sequence',[seq],T+FIVE_NS,job=jobs[actors[0]])
        stats=statistics(store);assert stats['READY']['cases']==2 and stats['READY']['actors']==1 and stats['WATCH']['cases']==1 and stats['RECHECK']['cases']==1,stats
        _,_,_,condition,params=filters({});rows,metrics,_=groups(store,'services',condition,params,0)
        assert len(rows)==1 and rows[0]['cases']==2 and metrics[SERVICE]['executions']==20 and metrics[SERVICE]['sessions']==1
        checks['same_service_is_one_group_and_overlapping_issue_evidence_is_counted_once']='PASS_20_NOT_40_EXECUTIONS'
        checks['rare_within_reference_is_observation_and_dirty_case_is_recheck_before_migration']='PASS'
        page=page_render(store,{},'/incidents',{},'token');users=page_render(store,{},'/incidents',{'view':['actors']},'token')
        assert 'کاربران و پرونده‌های این خدمت' in page and actors[0] in users
        assert actors[1] not in users and actors[2] not in users
        html=page_render(store,{},'/incidents',{'view':['cases'],'bucket':['ALL']},'token');assert actors[1] in html and actors[2] in html
        checks['service_and_user_views_and_all_case_drilldown_show_explicit_readiness']='PASS_HTML'
        before=raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_cases').fetchone()['n']
        while not requalify(store,T+2*FIVE_NS,limit=1).get('done'):pass
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_cases').fetchone()['n']==before
        assert not raw.execute('SELECT review_eligible FROM anomaly_detection.adp_case_signals WHERE case_key=%s',(weak,)).fetchone()['review_eligible']
        checks['bounded_policy_migration_preserves_case_identity_membership_and_versions']='PASS'
        raw.execute('DELETE FROM anomaly_detection.adp_jobs WHERE session_key=%s',(actors[0],))
        assert case_status(store,identity('actor',actors[0],'activity',SERVICE))['bucket']=='RECHECK'
        checks['missing_job_is_unknown_not_current_reviewable']='PASS'
        from anomaly_detection.review_policy import warm
        raw.execute('UPDATE anomaly_detection.adp_jobs SET dirty=FALSE,last_evaluated_ns=%s,evaluation=%s WHERE session_key=%s',(T,canonical({'rate_history_policy_version':2}),actors[1]))
        raw.execute('UPDATE anomaly_detection.adp_jobs SET dirty=FALSE,last_evaluated_ns=%s,evaluation=%s WHERE session_key=%s',(T,canonical({'decisions':[]}),actors[2]))
        while not warm(store,limit=1).get('done'):pass
        assert not raw.execute('SELECT dirty FROM anomaly_detection.adp_jobs WHERE session_key=%s',(actors[1],)).fetchone()['dirty']
        assert raw.execute('SELECT dirty FROM anomaly_detection.adp_jobs WHERE session_key=%s',(actors[2],)).fetchone()['dirty']
        checks['old_method_results_requeue_in_finite_pages_and_current_policy_results_stay_current']='PASS'
        enqueue(store,[T+2*FIVE_NS,T+3*FIVE_NS,T+4*FIVE_NS])
        oldest=process_one(store,T+10*FIVE_NS);recent=process_one(store,T+10*FIVE_NS,recent=True)
        assert oldest['target_ns']==T and recent['target_ns']==T+4*FIVE_NS
        checks['latest_population_work_has_reserved_progress_while_oldest_lane_is_preserved']='PASS'
        report={'build_id':BUILD_ID,'status':'PASS_GROUPED_REVIEW_AND_QUALIFICATION_SQL','checks':checks,
            'owner_connections':0,'native_windows_postgresql':'NOT_RUN','production_precision_recall':'NOT_MEASURED'}
        (ROOT/'validation/PRODUCT_revision17.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
    finally:engine.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--snapshot');main(parser.parse_args().snapshot)
