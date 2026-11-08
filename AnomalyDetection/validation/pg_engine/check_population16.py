"""Service recurrence, correction, and all-age reassessment contract."""
import json
from pathlib import Path
from transport import Engine
from anomaly_detection import BUILD_ID,FIVE_NS
from anomaly_detection.product_store import ProductStore
from anomaly_detection.product_pipeline import apply_window
from anomaly_detection.population import process_one
from anomaly_detection.cases import identity,feedback,current
from anomaly_detection.snapshot import canonical,digest
from check_revision10 import packet,metadata,TARGET,SERVICES

ROOT=Path(__file__).resolve().parents[2];SERVICE=SERVICES[2]


def window(store,target,bad,offset):
    p=packet(target,{});p['rows']=[]
    for i in range(4):p['rows']+=packet(target,{SERVICE:5},session=f'{i+1:064x}',offset=offset+5*i)['rows']
    apply_window(store,p,cursor_name='population')
    for i,row in enumerate(store.raw.execute('SELECT request_key,body FROM anomaly_detection.adp_facts WHERE at_ns>=%s AND at_ns<%s ORDER BY request_key',
        (target,target+FIVE_NS)).fetchall()):
        semantic=json.loads(row['body']);code='GD9999' if i<bad else 'G00000'
        detail={'source_present':True,'semantic':semantic,'quality':{'evidence_available':True,'conflicted':False},
            'transport':{'root_call':SERVICE,'root_code':code,'ended_ns':semantic['anchor_ns']+1},'observations':[]}
        store.raw.execute('UPDATE anomaly_detection.adp_facts SET details=%s WHERE request_key=%s',(canonical(detail),row['request_key']))
    result=process_one(store,target+10*FIVE_NS);assert result['target_ns']==target


def main():
    e=Engine();checks={}
    try:
        raw=e.connect();raw.execute('CREATE SCHEMA anomaly_detection');store=ProductStore(raw);store.initialize()
        # Qualified retained historical summaries: there is no inference about
        # missing raw/source periods. Only explicitly covered summaries train.
        for i in range(100):
            at=TARGET-(100-i)*FIVE_NS
            body={'start_ns':at,'executions':20,'sessions':4,'service_count':1,'top_session_share':.25,'covered':True,
                'outcomes':{'direct_api_reported_result':{'G00000':20}},'outcome_cutoffs':{'direct_api_reported_result':at+FIVE_NS-1},'known_outcomes':20}
            raw.execute('INSERT INTO anomaly_detection.adp_population VALUES(%s,%s,%s,%s)',(SERVICE,at,canonical(body),digest(body)))
        key=identity('service',SERVICE,'service_health',SERVICE)
        for i,bad in enumerate((18,0,18,0,18)):
            window(store,TARGET+i*FIVE_NS,bad,1000000+i*100)
            row=raw.execute('SELECT body FROM anomaly_detection.adp_cases WHERE case_key=%s',(key,)).fetchone()
            assert row,row
            body=json.loads(row['body'])
            if bad:assert body['state']=='NEEDS_REVIEW'
            else:assert body['phase']=='NO_CURRENT_SIGNAL'
        assert body['episodes']==3 and body['distinct_executions']==60 and body['distinct_sessions']==4,body
        assert body['phase']=='RETURNED' and current(store,key)
        assert raw.execute("SELECT COUNT(*) AS n FROM anomaly_detection.adp_cases WHERE issue_kind='service_health'").fetchone()['n']==1
        checks['three_outages_with_normal_periods_are_one_service_case_three_episodes_60_distinct_executions_four_sessions']='PASS'
        checks['detected_service_failure_periods_do_not_train_themselves_into_the_normal_reference']='PASS'
        before=raw.execute('SELECT revision,body FROM anomaly_detection.adp_cases WHERE case_key=%s',(key,)).fetchone()
        # Requeue a census with unchanged data: no extra episode or case revision.
        from anomaly_detection.population import enqueue
        with store.transaction():enqueue(store,[TARGET+4*FIVE_NS])
        process_one(store,TARGET+10*FIVE_NS)
        after=raw.execute('SELECT revision,body FROM anomaly_detection.adp_cases WHERE case_key=%s',(key,)).fetchone()
        assert before==after
        checks['service_census_replay_is_idempotent']='PASS'
        # A human review remains in history and applies to its observed range;
        # it does not silently declare future episodes benign.
        feedback(store,key,'reviewed_benign','real operator scope',TARGET+10*FIVE_NS)
        review=raw.execute('SELECT reviewed_end_ns,note FROM anomaly_detection.adp_case_feedback WHERE case_key=%s',(key,)).fetchone()
        assert review['reviewed_end_ns']==TARGET+5*FIVE_NS and review['note']=='real operator scope'
        assert not current(store,key)
        checks['case_feedback_is_preserved_scoped_to_reviewed_evidence_and_invalidates_service_reassessment']='PASS'
        # Finite all-age recheck passes: an actor in the middle of the backlog
        # cannot be bypassed forever by new/repeatedly dirtied recent arrivals.
        raw.execute('UPDATE anomaly_detection.adp_jobs SET dirty=FALSE')
        targets=[(TARGET,'c'*64),(TARGET-24*FIVE_NS,'b'*64),(TARGET-500*288*FIVE_NS,'a'*64)]
        for at,s in targets:
            raw.execute('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns,last_evaluated_ns,observed_count) VALUES(%s,%s,%s,1)',(s,at,TARGET))
            raw.execute('INSERT INTO anomaly_detection.adp_source_windows VALUES(%s,%s,%s,TRUE) ON CONFLICT(start_ns) DO NOTHING',(at,'queue-proof',canonical(metadata(at)|{'peer_population_valid':True})))
        seen=[]
        for i in range(3):
            if i==1:store=ProductStore(raw) # Restart must retain the keyset.
            job=store.next_recheck_job(TARGET+50*FIVE_NS);seen.append((job['target_ns'],job['session_key']))
            newer=TARGET+(i+1)*FIVE_NS
            raw.execute('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns,last_evaluated_ns) VALUES(%s,%s,%s)',('f'*64,newer,TARGET))
        assert seen==targets,(seen,targets)
        checks['recheck_cursor_survives_restart_and_reaches_middle_and_500_day_old_targets_despite_new_arrivals']='PASS'
        report={'build_id':BUILD_ID,'status':'PASS_SERVICE_AND_SYSTEM_CASE_CONTRACT_ISOLATED','checks':checks,
            'owner_connections':0,'native_service_outage_acceptance':'NOT_RUN','source_modified':False,
            'financial_finality':'NOT_INFERRED','session_epochs_not_asserted_distinct_people':True}
        (ROOT/'validation/PRODUCT_population16.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
    finally:e.close()


if __name__=='__main__':main()
