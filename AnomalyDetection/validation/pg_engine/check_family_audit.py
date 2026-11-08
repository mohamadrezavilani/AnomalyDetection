"""Regression checks for input versions, old profile work, and secondary isolation."""
import json
from unittest.mock import patch

from anomaly_detection import FIVE_NS
from anomaly_detection.case_export import datasets
from anomaly_detection.case_summary import case_status
from anomaly_detection.cases import identity,replace_scope
from anomaly_detection.context_models import FAMILIES
from anomaly_detection.longitudinal import context as long_context,upgrade_profiles
from anomaly_detection.presentation_proof import collect
from anomaly_detection.product_engine import evaluate_job
from anomaly_detection.product_pipeline import apply_window,owned_context
from anomaly_detection.product_store import ProductStore
from anomaly_detection.request_profiles import VERSION
from anomaly_detection.scenario_store import enqueue,next_profile,publish_scope,scope_key,scope_profiles
from anomaly_detection.snapshot import canonical,digest
from check_revision10 import packet,SERVICES
from check_revision16 import T
from check_revision18 import audit,job,primary
from tests.test_scenarios import point
from transport import Engine

ACTOR='a'*64
PEER='b'*64
SERVICE=SERVICES[0]
OLD_VERSION='qualified-request-profile-2'


def setup(engine):
    raw=engine.connect()
    raw.execute('CREATE SCHEMA anomaly_detection')
    store=ProductStore(raw);store.initialize()
    return raw,store


def versioned_profiles(raw,store):
    for step in range(12,1,-1):
        at=T-step*FIVE_NS
        assert apply_window(store,packet(at,{},offset=21000+step))['status']=='COMPLETE'
    past=packet(T-FIVE_NS,{SERVICE:1},session=PEER,offset=22000)
    current=packet(T,{SERVICE:1},session=ACTOR,offset=23000)
    for incoming in (past,current):assert apply_window(store,incoming)['status']=='COMPLETE'
    raw.execute("UPDATE anomaly_detection.adp_source_windows SET source=jsonb_set(source::jsonb,'{peer_population_valid}','true'::jsonb)::text")
    for incoming in (past,current):
        row=incoming['rows'][0];key=row['request_key'];at=row['anchor_ns']
        p=point(int(key,16),row['session_key'],at)|{'version':OLD_VERSION,'actor_qualified':True,
            'input_complete':True,'semantic_active':True,'service_path':SERVICE,
            'semantic_revision':row['revision'],'anchor_key':row['anchor_key']}
        raw.execute('INSERT INTO anomaly_detection.adp_profiles VALUES(%s,%s,%s,%s,%s,%s,%s)',
                    (key,row['session_key'],SERVICE,at,canonical(p),digest(p),at+2))
        publish_scope(store,row['session_key'],SERVICE,incoming['target_ns'],[key],independent=True)
    key=current['rows'][0]['request_key']
    data,complete,_=scope_profiles(store,ACTOR,SERVICE,T)
    assert len(data)==1 and not data[0]['qualified'] and not complete
    assert raw.execute('SELECT request_key FROM anomaly_detection.adp_profile_tasks WHERE request_key=%s',(key,)).fetchone()
    rows,_,bounded,receipt,reference=long_context(store,{'entity_key':ACTOR,'service_path':SERVICE,'target_ns':T})
    assert bounded and len(rows)==1 and not rows[0]['qualified'] and receipt['missing_or_stale_profiles_at_least']==2,receipt
    assert reference and not any(row['qualified'] for values in reference.values() for row in values),reference

    feature=scope_key('actor',ACTOR,SERVICE,T)
    item={'signal_key':'sf1:'+digest([feature,'repeated_target']),'family':'repeated_target','status':'CANDIDATE',
          'entity_type':'actor','entity_key':ACTOR,'service_path':SERVICE,'target_ns':T,'evidence_verified':True,
          'single_signal_review_eligible':True,'request_keys':[key],'observed':1,'explanation_fa':'آزمون'}
    with store.transaction():
        replace_scope(store,feature,[item],T+FIVE_NS,source_kind='feature',
                      job={'session_key':ACTOR,'target_ns':T,'version':1})
        raw.execute('UPDATE anomaly_detection.adp_scenario_jobs SET dirty=FALSE,processed_version=version,evaluation=%s WHERE scope_key=%s',
                    (canonical({'input_receipt':{'profile_version':OLD_VERSION}}),feature))
    case=identity('actor',ACTOR,'repeat_target',SERVICE)
    assert case_status(store,case)['bucket']=='RECHECK',case_status(store,case)
    sql=next(sql for name,sql,_ in datasets() if name=='case_signals')
    assert next(r for r in raw.execute(sql).fetchall() if r['case_key']==case)['current_method_input'] is False
    upgrade_profiles(store)
    assert raw.execute('SELECT dirty FROM anomaly_detection.adp_scenario_jobs WHERE scope_key=%s',(feature,)).fetchone()['dirty']
    assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_case_requests WHERE case_key=%s',(case,)).fetchone()['n']==1

    raw.execute("UPDATE anomaly_detection.adp_profiles SET body=jsonb_set(body::jsonb,'{version}',to_jsonb(%s::text))::text",(VERSION,))
    assert scope_profiles(store,ACTOR,SERVICE,T)[1]
    rows,_,_,_,reference=long_context(store,{'entity_key':ACTOR,'service_path':SERVICE,'target_ns':T})
    assert all(r['qualified'] for r in rows)
    assert reference and any(r['qualified'] for values in reference.values() for r in values)


def fair_profiles(raw,store):
    earlier,newer=f'{10:064x}',f'{20:064x}'
    raw.execute('INSERT INTO anomaly_detection.adp_profile_tasks(request_key,priority) VALUES(%s,0),(%s,5)',(earlier,newer))
    store.save_state('profile_active_scope_v1',{'keys':[newer]})
    assert next_profile(store,T)==newer
    assert next_profile(store,T,historical=True)==earlier
    arrived=f'{5:064x}'
    raw.execute('INSERT INTO anomaly_detection.adp_profile_tasks(request_key,priority) VALUES(%s,10)',(arrived,))
    assert next_profile(store,T,historical=True)==newer
    assert next_profile(store,T,historical=True)==arrived


def independent_methods(raw,store):
    raw.execute("INSERT INTO anomaly_detection.adp_service_reference_points "
                "SELECT %s,'service_execution',lpad(to_hex(i),64,'0'),%s::bigint-(i%%300+2)*%s::bigint,"
                "CASE WHEN i=411 THEN 3 ELSE 1 END,TRUE FROM generate_series(1,411) i",(SERVICE,T,FIVE_NS))
    apply_window(store,packet(T-FIVE_NS,{},offset=24000))
    apply_window(store,packet(T,{SERVICE:20},offset=25000))
    for row in raw.execute('SELECT request_key FROM anomaly_detection.adp_facts').fetchall():audit(store,row['request_key'],T+20*FIVE_NS)
    primary(store)
    assert collect(store,ACTOR,T)['status']=='PASS_REVIEWABLE_RATE_FINDING'
    j=job(store);ctx=store.save_context(j,owned_context(store,j));j['version']=ctx['job_version']
    signal='pf1:'+digest([ACTOR,T,'request_latency',SERVICE])
    prior={'finding_key':signal,'family':'request_latency','dimension':'context','service_path':SERVICE,
        'session_key':ACTOR,'target_ns':T,'status':'CANDIDATE','reason':'SYNTHETIC_PRIOR_RESULT',
        'observed':12,'expected':1,'explanation_fa':'آزمون'}
    with patch('anomaly_detection.context_models.evaluate',return_value=[prior]):
        assert evaluate_job(store,j,ctx,T+20*FIVE_NS+1)['status']=='APPLIED'
    def members():
        return raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_case_requests WHERE signal_key=%s',
                           (signal,)).fetchone()['n']
    assert members()==20
    def timeout(*args):
        with store.transaction():
            raw.execute("DO $$ BEGIN RAISE EXCEPTION 'context reference fixture' USING ERRCODE='57014'; END $$")
    now=T+21*FIVE_NS
    with patch.object(store,'service_details',side_effect=timeout),patch('anomaly_detection.continuous.reference',side_effect=timeout):
        applied=evaluate_job(store,j,ctx,now)
    assert applied['status']=='APPLIED'
    decisions=applied['decisions']
    assert {d['family'] for d in decisions if d['reason']=='CONTEXT_REFERENCE_READ_RETRY'}==set(FAMILIES)
    assert any(d['family']=='service_sequence' for d in decisions)
    retry=raw.execute('SELECT families,due_ns FROM anomaly_detection.adp_model_queue WHERE session_key=%s AND target_ns=%s',(ACTOR,T)).fetchone()
    assert set(json.loads(retry['families']))==set(FAMILIES)|{'continuous_rate'} and retry['due_ns']==now+30_000_000_000,retry
    assert collect(store,ACTOR,T)['status']=='PASS_REVIEWABLE_RATE_FINDING'
    assert raw.execute('SELECT state FROM anomaly_detection.adp_case_signals WHERE signal_key=%s',(signal,)).fetchone()['state']=='DEFERRED'
    assert members()==20
    with patch('anomaly_detection.context_models.evaluate',return_value=[prior]):
        assert evaluate_job(store,j,ctx,retry['due_ns'])['status']=='APPLIED'
    assert raw.execute('SELECT state FROM anomaly_detection.adp_case_signals WHERE signal_key=%s',(signal,)).fetchone()['state']=='ACTIVE'
    assert members()==20
    assert not raw.execute('SELECT 1 FROM anomaly_detection.adp_model_queue WHERE session_key=%s AND target_ns=%s',(ACTOR,T)).fetchone()


def main():
    checks={}
    for name,check in [('profile_contract_excludes_stale_targets_and_peer_cohorts',versioned_profiles),
                       ('historical_profile_pass_advances_despite_new_arrivals',fair_profiles),
                       ('context_read_timeout_retries_only_its_methods_and_preserves_rate_proof',independent_methods)]:
        engine=Engine()
        try:
            check(*setup(engine))
            checks[name]='PASS'
        finally:engine.close()
    print(json.dumps({'status':'PASS_ISOLATED_POSTGRESQL_WASM','checks':checks,'native_windows':'NOT_RUN'}))


if __name__=='__main__':main()
