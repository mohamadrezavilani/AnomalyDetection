"""Independent, synthetic oracle checks against the actual evaluator functions.

Run: python AnomalyDetection/audit/run_independent_audit.py --output result.json
This does NOT qualify PostgreSQL, real Worker scheduling, HTTP, or accuracy in
production. Scripted SQL responses below are explicitly marked as test doubles.
The oracle for categorical changes uses exact integer combinations, independently
of the product's logarithmic Fisher implementation. All identities are synthetic.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import nullcontext
from copy import deepcopy
from fractions import Fraction
from math import comb
from pathlib import Path
import json
import hashlib
import random
import subprocess
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from anomaly_detection import FIVE_NS as W
from anomaly_detection import scenario_models as sm
from anomaly_detection import product_models as pm
from anomaly_detection import context_models as cm
from anomaly_detection import longitudinal as lm
from anomaly_detection import continuous as cr
from anomaly_detection import population as pop
from anomaly_detection import input_subjects as ins
from anomaly_detection.request_profiles import VERSION as PROFILE_VERSION, output_features

T = 1_800_000_000_000_000_000 // W * W
S = 'Services.v1/WaterBills'
OTHER = 'Services.v1/ElectricBills'
ACTOR = 'a' * 64
RESULTS = []


def exact_greater(a, b, c, d):
    """Exact rational hypergeometric tail under equal category proportions."""
    n, successes, total = a+b, a+c, a+b+c+d
    return float(Fraction(sum(comb(successes, k)*comb(total-successes, n-k)
                              for k in range(a, min(successes, n)+1)
                              if 0 <= n-k <= total-successes), comb(total, n)))


def check(family, name, expected, actual, *, level='real_evaluator_synthetic_input', **evidence):
    ok = actual in expected if isinstance(expected, list) else actual == expected
    RESULTS.append(dict(family=family, test=name, status='PASS' if ok else 'FAIL',
                        expected=expected, actual=actual, level=level, evidence=evidence))


def one(items, family):
    return next(d for d in items if d['family'] == family)


def profile(i, who=ACTOR, at=None, *, subject=None, topic=None, ip='ip0',
            service=S, stage=True, code='G00000', output=True):
    at = T+i if at is None else at
    return dict(version=PROFILE_VERSION, request_key=f'{i:064x}', session_key=who,
                service_path=service, at_ns=at, ended_ns=at+1, qualified=True,
                actor_qualified=True, content_complete=True, input_complete=True,
                output_complete=True, complete_event_scope=True,
                targets={'provider': str(i) if topic is None else topic},
                subjects=[dict(channel='provider', field='$.BillID', key=str(i) if subject is None else subject)],
                ip_keys=[ip], stages=[service]+(['DB.Access'] if stage else []),
                outputs={'provider': output_features({'Result': {'Exists': output}})},
                result={'scope': 'direct_api_reported_result', 'code': code},
                witnesses=[{'at_ns': at}])


def actor_refs(*, repeat=False, count=400):
    return [[profile(100000+k*100+i, who=f'peer-{k}', at=T-2*288*W+i,
                     subject=f'peer-{k}' if repeat else None,
                     topic=f'peer-{k}' if repeat else None)
             for i in range(20)] for k in range(count)]


def detail(i, *, at=None, current=False, latency=1., otp=None, payment=None,
           roles=('service_operation',), service=S, kind='service_execution',
           inquiry=None, available=True):
    at = T+i if current else T-(i+1)*W+1 if at is None else at
    key=f'{i:064x}'; origin=f'origin-{i}'
    observations=[]
    for axis, value in [('otp_validation', otp), ('inquiry_result', inquiry)]:
        if value is not None:
            observations.append(dict(qualified=True, axis='service_dispatch.'+axis,
                                     value=value, at_ns=at+2))
    invoice={'sources':[{'request_key': key}], 'inquiry_payments':[], 'bill_payments':[]}
    if payment:
        invoice[payment[0]]=[{'statuses':[{'value':payment[1], 'evidence':{'at_ns':at+2}}]}]
    fact=dict(source_present=True, quality={'evidence_available':available, 'conflicted':False},
              semantic={'kind':kind, 'state':'active', 'session_key':ACTOR, 'revision':1, 'anchor_key':'anchor-'+key},
              transport={'started_ns':at, 'ended_ns':at+int(latency*1e9)},
              observations=observations,
              identifiers=[dict(issuer='p24', kind='invoice', scope='service', identity_key=key,
                                origin_key=origin, evidence_quality={'qualified':True})],
              evidence=[{'origin_key':origin, 'at_ns':at}],
              viewer_journey={'journey': {'identity_status':'resolved', 'truncated':False,
                                          'coverage_caveats':[], 'steps':[{'role':r,'ended_ns':at+10} for r in roles]},
                              'payment': {'truncated':False, 'invoices':[invoice]}})
    return {'request_key':key, 'at_ns':at, 'service_path':service, 'details':fact}


def behavior_context(current=100, n=144, counts=None):
    history=[dict(start_ns=T-(n-i)*W, coverage_complete=True, population_complete=True,
                  counts={S:2}, first_observed_ns=T-n*W) for i in range(n)]
    context=dict(session_key=ACTOR, target_ns=T, target_complete=True,
                 target_events_complete=True, evidence_verified=True, events=[],
                 windows=[dict(start_ns=T, coverage_complete=True, population_complete=True,
                               counts=counts or {S:current}, witnesses={S:'witness'},
                               first_observed_ns=T-n*W)])
    return context, history


def actor_checks():
    sparse=actor_refs(repeat=True); varied=actor_refs()
    normal=[profile(i) for i in range(20)]
    groups={
        'repeated_target': ([profile(i, topic='same', subject='same') for i in range(20)], varied, S),
        'subject_enumeration': (normal, sparse, S),
        'client_ip_rotation': ([profile(i,ip=f'ip{i}') for i in range(20)], sparse, S),
        'service_traversal': ([profile(i,service=S if i%2 else OTHER) for i in range(20)], sparse, '*'),
        'workflow_change': ([profile(i,stage=False) for i in range(10)], varied, S),
    }
    for family,(now,refs,service) in groups.items():
        positive=one(sm.actor(ACTOR,service,T,now,[],refs,complete=True),family)
        check(family,'positive','CANDIDATE',positive['status'], observed=positive.get('observed'),
              review_eligible=positive.get('single_signal_review_eligible'))
        ordinary=[profile(i,topic='same',subject='same') for i in range(20)] if family=='subject_enumeration' else normal
        if family=='repeated_target': ordinary=normal
        negative=one(sm.actor(ACTOR,service,T,ordinary,[],refs,complete=True),family)
        check(family,'ordinary_has_no_independent_alert',False,negative.get('single_signal_review_eligible',False))
        unknown=one(sm.actor(ACTOR,service,T,now,[],refs,complete=False),family)
        check(family,'incomplete_has_no_qualified_alert',False,
              bool(unknown.get('evidence_verified') and unknown.get('single_signal_review_eligible')))
    before=[profile(i,at=T-W+i,topic='same',subject='same') for i in range(10)]
    after=[profile(30+i,topic='same',subject='same') for i in range(10)]
    d=one(sm.actor(ACTOR,S,T,after,before,varied,complete=True),'repeated_target')
    check('repeated_target','cross_window_logical_request_count',20,d['observed'])
    late=deepcopy(after); late[-1]['qualified']=False
    d=one(sm.actor(ACTOR,S,T,late,before,varied,complete=False),'repeated_target')
    check('repeated_target','late_incomplete_is_not_qualified',False,d['evidence_verified'])
    low=one(sm.actor(ACTOR,S,T,normal,[],sparse[:298],complete=True),'subject_enumeration')
    high=one(sm.actor(ACTOR,S,T,normal,[],sparse[:299],complete=True),'subject_enumeration')
    check('subject_enumeration','298_reference_tail_boundary','INSUFFICIENT_DATA',low['status'])
    check('subject_enumeration','299_reference_tail_boundary','CANDIDATE',high['status'])
    d=one(sm.actor(ACTOR,S,T,[profile(i,ip=f'ip{i}') for i in range(20)],[],varied,complete=True),'client_ip_rotation')
    check('client_ip_rotation','ip_change_alone_does_not_alert',False,d['single_signal_review_eligible'])


def service_data():
    past=[profile(10000+w*20+i,who=f'peer-{i%20}',at=T-(120-w)*W+i,
                  topic=f'unique-{w}-{i}') for w in range(120) for i in range(20)]
    now=[profile(50000+i,who=f'current-{i%3}') for i in range(12)]
    return now,past


def service_checks():
    now,past=service_data()
    for family in ['response_schema_change','response_content_change','service_health','multi_session_target']:
        positive=deepcopy(now)
        if family=='response_schema_change':
            for r in positive:r['outputs']['provider']=output_features({'Result':{'Exists':'changed-type'}})
        elif family=='response_content_change':
            for r in positive:r['outputs']['provider']=output_features({'Result':{'Exists':False}})
        elif family=='service_health':
            for r in positive:r['result']['code']='GD2076'
        else:
            for r in positive:r['targets']={'provider':'shared-across-sessions'}
        d=one(sm.service(S,T,positive,past,independent=True),family)
        check(family,'positive','CANDIDATE',d['status'], scope=d.get('count_scope'))
        d=one(sm.service(S,T,now,past,independent=True),family)
        check(family,'ordinary','NO_DEVIATION_OBSERVED',d['status'])
        d=one(sm.service(S,T,positive,past,independent=False),family)
        check(family,'nonindependent_sample','INSUFFICIENT_DATA',d['status'])
    numeric_past=deepcopy(past);numeric_now=deepcopy(now)
    for i,r in enumerate(numeric_past):r['outputs']['provider']=output_features({'Result':{'Amount':100+i}})
    for i,r in enumerate(numeric_now):r['outputs']['provider']=output_features({'Result':{'Amount':1_000_000+i}})
    d=one(sm.service(S,T,numeric_now,numeric_past,independent=True),'response_content_change')
    check('response_content_change','disjoint_continuous_amount_shift','CANDIDATE',d['status'],
          oracle='all_current_numeric_values_exceed_all_past_values',
          one_sided_complete_rank_separation_p=float(Fraction(1,comb(len(past)+len(now),len(now)))))
    # Actual service-workflow dispatcher; persistence is intercepted, not SQL-tested.
    from anomaly_detection.scenario_store import process_one
    from anomaly_detection.snapshot import canonical
    class Result:
        def __init__(self,rows):self.rows=rows
        def fetchall(self):return self.rows
        def fetchone(self):return self.rows[0] if self.rows else None
    class Raw:
        def __init__(self,missing=True,extra_frames=0,family='service_workflow_change',current_available=True,profile_bytes=1):
            self.missing=missing;self.extra_frames=extra_frames;self.family=family
            self.current_available=current_available;self.profile_bytes=profile_bytes
        def execute(self,sql,params=()):
            if sql.startswith('WITH expired AS MATERIALIZED (SELECT scope_key '):return Result([])
            if sql.startswith('SELECT * FROM anomaly_detection.adp_scenario_jobs'):
                return Result([dict(scope_key='synthetic-scope',kind='request_workflow' if self.family=='service_workflow_change' else 'request_response',entity_key=S,service_path=S,target_ns=T,version=1)])
            if sql.startswith('SELECT * FROM anomaly_detection.adp_service_profile_samples'):
                return Result([dict(start_ns=T,available=self.current_available,request_keys=canonical([r['request_key'] for r in now]))]+[
                    dict(start_ns=T-(k+1)*W,available=True,request_keys=canonical([r['request_key'] for r in past if r['at_ns']//W*W==T-(k+1)*W]))
                    for k in range(120)]+[dict(start_ns=T-(k+121)*W,available=False,request_keys='[]') for k in range(self.extra_frames)])
            if sql.startswith('SELECT COALESCE(SUM(octet_length(body))'):return Result([{'n':self.profile_bytes}])
            if sql.startswith(('SELECT request_key,body FROM anomaly_detection.adp_profiles','SELECT p.request_key,p.body')):
                rows=deepcopy(now)+past
                if self.missing:
                    for r in rows[:len(now)]:
                        if self.family=='service_workflow_change':r['stages']=[S]
                        elif self.family=='response_schema_change':r['outputs']['provider']=output_features({'Result':{'Exists':'new-type'}})
                        elif self.family=='response_content_change':r['outputs']['provider']=output_features({'Result':{'Exists':False}})
                        elif self.family=='service_health':r['result']['code']='GD2076'
                        elif self.family=='multi_session_target':r['targets']={'provider':'shared-across-sessions'}
                return Result([{'request_key':r['request_key'],'body':canonical(r)} for r in rows])
            if sql.startswith('SELECT DISTINCT m.request_key'):return Result([])
            if sql.startswith('SELECT version FROM anomaly_detection.adp_scenario_jobs'):return Result([{'version':1}])
            if sql.startswith(('INSERT ','UPDATE ')):return Result([])
            raise AssertionError('unexpected scripted SQL: '+sql[:90])
    class Store:
        def __init__(self,missing=True,extra_frames=0,family='service_workflow_change',**kwargs):
            self.raw=Raw(missing,extra_frames,family,**kwargs);self.states={}
        def state(self,name):return self.states.get(name,{})
        def save_state(self,name,value):self.states[name]=value
        def transaction(self):return nullcontext()
    for family in ['service_workflow_change','response_schema_change','response_content_change','service_health','multi_session_target']:
        for name,missing,extra,expected in [('dispatcher_positive',True,0,'CANDIDATE'),('dispatcher_ordinary',False,0,'NO_DEVIATION_OBSERVED'),
                                            ('1025_frames_positive_blocked',True,904,'CANDIDATE')]:
            with patch('anomaly_detection.cases.replace_scope'),patch('anomaly_detection.cases.normal_observations'):
                outcome=process_one(Store(missing,extra,family),T+W)
            d=one(outcome['decisions'],family)
            check(family,name,expected,d['status'],level='real_scenario_dispatch_scripted_sql',frame_count=121+extra)
        for name,missing,kwargs,expected in [
            ('1025_frames_ordinary',False,{},'NO_DEVIATION_OBSERVED'),
            ('1025_frames_missing_current',True,{'current_available':False},'INSUFFICIENT_DATA'),
            ('1025_frames_memory_guard',True,{'profile_bytes':64*1024*1024},'INSUFFICIENT_DATA')]:
            with patch('anomaly_detection.cases.replace_scope'),patch('anomaly_detection.cases.normal_observations'):
                outcome=process_one(Store(missing,904,family,**kwargs),T+W)
            check(family,name,expected,one(outcome['decisions'],family)['status'],
                  level='real_scenario_dispatch_scripted_sql',frame_count=1025)


def traffic_checks():
    history=[dict(start_ns=T-(120-i)*W,requests=10,sessions=3,complete=True) for i in range(120)]
    for family in ['service_volume','multi_session_service']:
        for name,now,expected in [('positive',dict(requests=1000,sessions=40,complete=True),'CANDIDATE'),
                                  ('ordinary',dict(requests=10,sessions=3,complete=True),'NO_DEVIATION_OBSERVED'),
                                  ('missing_coverage',dict(requests=1000,sessions=40,complete=False),'INSUFFICIENT_DATA')]:
            d=one(sm.traffic(S,T,now,history),family);check(family,name,expected,d['status'])
    d=one(sm.traffic(S,T,dict(requests=0,sessions=0,complete=True),history),'service_volume')
    check('service_volume','complete_census_drop_to_zero','CANDIDATE',d['status'])
    history=[dict(start_ns=T-(120-i)*W,covered=True,executions=20,sessions=5,top_session_share=.3,
                  outcomes={'inquiry':{'G00000':20}},outcome_cutoffs={'inquiry':T-(120-i)*W+10}) for i in range(120)]
    for family in ['service_population','service_health']:
        current=dict(start_ns=T,covered=True,executions=2000 if family=='service_population' else 20,
                     sessions=50 if family=='service_population' else 5,top_session_share=.9,
                     outcomes={'inquiry':{'GD2076':20}},outcome_cutoffs={'inquiry':T+10})
        check(family,'population_census_positive','CANDIDATE',one(pop.assess(S,T,current,history),family)['status'])
        normal=history[-1]|{'start_ns':T}
        check(family,'population_census_ordinary','NO_DEVIATION_OBSERVED',one(pop.assess(S,T,normal,history),family)['status'])


def behavior_checks():
    for family in ['rate_5m','rate_60m','service_mix','isolation_forest']:
        context,history=behavior_context(current=2000,n=180)
        if family=='service_mix':
            for r in history:r['counts']={S:20}
            context['windows'][0]['counts']={S:1,OTHER:19}
        if family=='isolation_forest':
            rng=random.Random(20261109)
            for r in history:r['counts']={f'Services.v1/P{k}':rng.randint(2,20) for k in range(rng.randint(1,4))}
            context['windows'][0]['counts']={f'Services.v1/P{k}':100000 for k in range(30)}
        d=one(pm.evaluate(context,history),family)
        check(family,'positive','CANDIDATE',d['status'],score=d.get('score'),upper=d.get('upper'))
        ordinary=deepcopy(context);ordinary['windows'][0]['counts']=history[-1]['counts']
        d=one(pm.evaluate(ordinary,history),family)
        check(family,'ordinary','NO_DEVIATION_OBSERVED',d['status'])
        context['target_complete']=False
        check(family,'missing_target','INSUFFICIENT_DATA',one(pm.evaluate(context,history),family)['status'])
    context,history=behavior_context(current=30)
    # 1,200 requests distributed over four windows; unique timestamps and identity.
    rng=random.Random(712);time=T-2400*1_000_000_000;events=[]
    for i in range(1200):
        time+=rng.randint(1,3)*1_000_000_000
        events.append(dict(request_key=f'{i:064x}',anchor_ns=time,root_call=S if i%2 else OTHER,
                           identity_state='assigned',conflicted=False,request_session_key=ACTOR))
    # Shift the whole sequence to end strictly before the cutoff.
    delta=events[-1]['anchor_ns']-(T-10_000_000_000)
    for e in events:e['anchor_ns']-=delta
    for family in ['service_sequence','timing_regularization']:
        current=[dict(request_key=f'{5000+i:064x}',anchor_ns=T+i*100_000_000,
                      root_call='Services.v1/Novel' if family=='service_sequence' else S,
                      identity_state='assigned',conflicted=False,request_session_key=ACTOR) for i in range(30)]
        context['events']=events+current
        d=one(pm.evaluate(context,history),family)
        check(family,'positive','CANDIDATE',d['status'])
        context['target_events_complete']=False
        check(family,'partial_events','INSUFFICIENT_DATA',one(pm.evaluate(context,history),family)['status'])
        context['target_events_complete']=True
        # The normal control repeats a sufficiently long historical segment.
        normal=[]
        for i in range(30):
            at=T+i*2_000_000_000+(i%3)*100_000_000
            normal.append(dict(request_key=f'{9000+i:064x}',anchor_ns=at,root_call=S if i%2 else OTHER,
                               identity_state='assigned',conflicted=False,request_session_key=ACTOR))
        context['events']=events+normal
        check(family,'ordinary','NO_DEVIATION_OBSERVED',one(pm.evaluate(context,history),family)['status'])


def context_checks():
    context,_=behavior_context(current=20)
    for family,field,old,new in [('otp_result_change','otp','G00000','GD2076'),
                                ('payment_result_change','payment',('bill_payments','Success'),('bill_payments','Failed')),
                                ('journey_profile_change','roles',('service_operation',),('other_role',)),
                                ('business_result_change','inquiry','G00000','GD2076')]:
        def run(rows):return pm.evaluate(context,[],rows) if family=='business_result_change' else cm.evaluate(context,rows)
        for name,history,expected in [('novel_category', [detail(i,**{field:old}) for i in range(120)],'CANDIDATE'),
                                      ('known_rare_category_becomes_dominant',[detail(i,**{field:old if i<119 else new}) for i in range(120)],'CANDIDATE')]:
            now=[detail(900+i,current=True,**{field:new}) for i in range(20)]
            d=one(run(history+now),family)
            check(family,name,expected,d['status'],oracle_exact_p=exact_greater(20,0,1 if name.startswith('known') else 0,119 if name.startswith('known') else 120),
                  oracle='same_service_category_enrichment_exact_hypergeometric',score=d.get('score'))
        ordinary=[detail(i,**{field:old}) for i in range(120)]+[detail(900+i,current=True,**{field:old}) for i in range(20)]
        check(family,'ordinary','NO_DEVIATION_OBSERVED',one(run(ordinary),family)['status'])
        unknown=[detail(i,available=False,**{field:old}) for i in range(120)]+[detail(900+i,current=True,available=False,**{field:new}) for i in range(20)]
        check(family,'unavailable_evidence','INSUFFICIENT_DATA',one(run(unknown),family)['status'])
    for family in ['request_latency','typed_target_diversity']:
        past=[detail(i) for i in range(120)]
        now=[detail(900+i,current=True,latency=100 if family=='request_latency' else 1) for i in range(20)]
        check(family,'positive','CANDIDATE',one(cm.evaluate(context,past+now),family)['status'])
        ordinary=[detail(900,current=True)]
        check(family,'ordinary','NO_DEVIATION_OBSERVED',one(cm.evaluate(context,past+ordinary),family)['status'])
        for r in now:r['details']['quality']['evidence_available']=False
        check(family,'unavailable_current','INSUFFICIENT_DATA',one(cm.evaluate(context,past+now),family)['status'])
    # A ready service must not hide the insufficient status of another service.
    rows=[detail(i,otp='OK') for i in range(120)]+[detail(900+i,current=True,otp='BAD') for i in range(20)]
    rows += [detail(2000+i,current=True,otp='BAD',service=OTHER) for i in range(20)]
    ds=cm.evaluate(context,rows)
    check('otp_result_change','insufficient_second_service_is_explicit',True,
          any(d['family']=='otp_result_change' and d['service_path']==OTHER and d['status']=='INSUFFICIENT_DATA' for d in ds))
    rows=[detail(i,otp='OK') for i in range(120)]+[detail(900+i,current=True,otp='BAD') for i in range(20)]
    rows += [detail(2000+i,otp='OK',kind='wallet_funding_execution') for i in range(120)]
    rows += [detail(3000+i,current=True,otp='OK',kind='wallet_funding_execution') for i in range(20)]
    ds=[d for d in cm.evaluate(context,rows) if d['family']=='otp_result_change' and d['service_path']==S]
    check('otp_result_change','different_semantic_kinds_have_distinct_finding_keys',len(ds),len({d['finding_key'] for d in ds}))


def peer_and_input_checks():
    from anomaly_detection.service_reference import reference,rank_screen
    points=[dict(session_key=f'peer-{i}',start_ns=T-(i+1)*W,value=2,qualified=True) for i in range(400)]
    ref=reference(points,ACTOR,T,S,unit='canonical_service_executions',reference_id='synthetic')
    check('peer_service_rate_5m','positive',True,rank_screen(ref,20,1)['high'])
    check('peer_service_rate_5m','ordinary',False,rank_screen(ref,2,1)['high'])
    cold=reference(points[:20],ACTOR,T,S,unit='canonical_service_executions',reference_id='synthetic')
    check('peer_service_rate_5m','warmup','INSUFFICIENT_DATA',cold['status'])
    job=dict(session_key=ACTOR,target_ns=T);events=[];details=[]
    for i in range(20):
        key=f'{i:064x}';at=T+i;origin=f'o{i}'
        event=dict(request_key=key,anchor_key=f'a{i}',revision=1,kind='service_execution',state='active',session_key=ACTOR,root_call=S,anchor_ns=at)
        locator=dict(origin_key=origin,version_key='v',at_ns=at,callpath='ClientAyanCoInquiry.WaterBillInquiry')
        proof=dict(version=ins.VERSION,status='VERIFIED',field='WaterBillID',subject_key=f's{i}',key_tag='synthetic-key',witnesses=[locator])
        fact=dict(source_present=True,semantic=event,quality={'evidence_available':True,'conflicted':False},
                  input_subject=proof,evidence=[locator|{'qualified':True,'raw_available':True}])
        events.append(event);details.append({'request_key':key,'details':fact})
    rate=dict(family='peer_service_rate_5m',status='CANDIDATE',observed=20,comparison_count=1,service_path=S,model=ref)
    context=dict(events=events,target_complete=True,target_events_complete=True)
    check('input_subject_burst','positive','CANDIDATE',next(ins.decisions(job,context,details,[rate]))['status'])
    same=deepcopy(details)
    for r in same:r['details']['input_subject']['subject_key']='same'
    check('input_subject_burst','one_subject_many_requests','NO_DEVIATION_OBSERVED',next(ins.decisions(job,context,same,[rate]))['status'])
    late=deepcopy(details);late[0]['details']['evidence'][0]['version_key']='v2'
    check('input_subject_burst','late_witness_invalidates_old_receipt','INSUFFICIENT_DATA',next(ins.decisions(job,context,late,[rate]))['status'])
    for family in ['continuous_rate']:
        events=[dict(request_key=f'{i:064x}',at_ns=T-10+i,qualified=True) for i in range(20)]
        peak=cr.peak(events,W,T,T+W,[[T-W,T+W]])
        check(family,'cross_window_peak_exact_membership',20,peak['observed'])
        hist=[dict(value=2,n=400,low_ns=T-3*288*W,high_ns=T-W)]
        check(family,'positive',True,cr.histogram_reference(hist,peak['observed'],4)['high'])
        check(family,'ordinary',False,cr.histogram_reference(hist,2,4)['high'])
        check(family,'gap_is_unknown',None,cr.peak(events,W,T,T+W,[[T,T+W]]))
        check(family,'reference_resolution_398',False,cr.histogram_reference([hist[0]|{'n':398}],20,4)['ready'])


def longitudinal_checks():
    duration=3*lm.DAY;covered=list(range(T-duration,T+W,W));now=[];peers=[]
    # Identical number of executions and active days in current and peer cohorts.
    for day in range(3):
        for i in range(2):
            now.append(profile(100+day*2+i,at=T-day*lm.DAY-100+i,subject=f'new-{day}-{i}',ip=f'ip-{day}-{i}'))
    for who in range(1000):
        for day in range(3):
            for i in range(2):
                peers.append(profile(100000+who*6+day*2+i,who=f'peer-{who}',at=T-1-day*lm.DAY-i,
                                     subject='same-for-actor',ip='ip0'))
    positive=lm.evaluate(ACTOR,S,T,now+peers,covered)
    ordinary=deepcopy(now)
    for r in ordinary:r['subjects'][0]['key']='same-for-actor';r['ip_keys']=['ip0']
    negative=lm.evaluate(ACTOR,S,T,ordinary+peers,covered)
    broken=lm.evaluate(ACTOR,S,T,now+peers,[v for v in covered if v!=T-lm.DAY],extra_durations=(duration,))
    for family in lm.FAMILIES:
        def get(ds):return next(d for d in ds if d['family']==family and d['duration_ns']==duration)
        check(family,'three_active_days_positive','CANDIDATE',get(positive)['status'],reference_actors=get(positive)['reference_actors'])
        check(family,'three_active_days_ordinary','NO_DEVIATION_OBSERVED',get(negative)['status'])
        check(family,'multi_day_gap','INSUFFICIENT_DATA',get(broken)['status'])
    d=one(sm.actor(ACTOR,S,T,[profile(1)],[],[],complete=False),'subject_enumeration')
    check('subject_enumeration','no_reference_is_unknown','INSUFFICIENT_DATA',d['status'])


def scheduler_checks():
    from anomaly_detection.product_scheduling import EvaluationScheduler
    class Store:
        def next_live_job(self,now):return {'lane':'live'}
        def next_model_job(self,now):return {'lane':'model'}
        def __getattr__(self,name):
            if name.startswith('next_'):return lambda *a,**k:{'lane':name}
            raise AttributeError(name)
    scheduler=EvaluationScheduler();seen=[]
    with patch('anomaly_detection.product_priority.next_evidence_job',return_value={'lane':'evidence'}):
        for _ in range(16):seen.append(scheduler.choose(Store(),T)[1])
    for family in ['rate_5m','rate_60m','service_mix','isolation_forest','service_sequence','timing_regularization',
                   'business_result_change','request_latency','otp_result_change','payment_result_change',
                   'typed_target_diversity','journey_profile_change','continuous_rate']:
        check(family,'advanced_lane_reserved_under_live_load',1,seen.count('advanced'),level='real_scheduler_fake_store',turns=16)
    from anomaly_detection.scenario_worker import step
    from types import SimpleNamespace
    clock=SimpleNamespace(time_ns=lambda:T,monotonic=lambda:0.)
    store=SimpleNamespace();source=SimpleNamespace(profile=lambda k:None);state={}
    with patch('anomaly_detection.scenario_store.seed',side_effect=RuntimeError('synthetic seed failure')), \
         patch('anomaly_detection.scenario_store.next_profile',return_value=None), \
         patch('anomaly_detection.scenario_store.process_one',return_value={'status':'APPLIED','scope_key':'synthetic'}) as model, \
         patch('anomaly_detection.scenario_traffic.read_page',return_value={}), \
         patch('anomaly_detection.scenario_traffic.apply',return_value='CAUGHT_UP'):
        store.state=lambda name:{}
        step(store,source,clock,1,state)
    for family in sm.ACTOR_FAMILIES+sm.SERVICE_FAMILIES+('service_traversal','service_workflow_change')+lm.FAMILIES:
        check(family,'reserved_scenario_lane_survives_seed_failure',1,model.call_count,
              level='real_scenario_worker_step_patched_io',native_throughput='NOT_RUN')


def engine_and_lifecycle_checks():
    from anomaly_detection.product_engine import evaluate_job
    from anomaly_detection.service_reference import reference
    from anomaly_detection import cases
    context,history=behavior_context(current=20)
    context['windows'][0]['count_kinds']={S:'service_execution'}
    past=[detail(i,otp='OK',inquiry='OK',payment=('bill_payments','Success')) for i in range(120)]
    now=[detail(900+i,current=True,latency=100,otp='BAD',inquiry='BAD',payment=('bill_payments','Failed'),roles=('other_role',)) for i in range(20)]
    for row in now:
        context['events'].append(dict(request_key=row['request_key'],anchor_ns=row['at_ns'],
            anchor_key=row['details']['semantic']['anchor_key'],revision=1,root_call=S,kind='service_execution',
            session_key=ACTOR,request_session_key=ACTOR,identity_state='assigned',conflicted=False))
    points=[dict(session_key=f'p{i}',start_ns=T-(i+1)*W,value=2,qualified=True) for i in range(400)]
    ref=reference(points,ACTOR,T,S,unit='canonical_service_executions',reference_id='synthetic')
    class Result:
        def __init__(self,rows):self.rows=rows
        def fetchall(self):return self.rows
        def fetchone(self):return self.rows[0] if self.rows else None
    class EngineRaw:
        def execute(self,sql,params=()):
            if sql.startswith('INSERT INTO anomaly_detection.adp_peer_epochs'):return Result([])
            if sql.startswith('SELECT version FROM anomaly_detection.adp_peer_epochs'):return Result([{'version':1}])
            raise AssertionError('unexpected engine SQL: '+sql[:80])
    class Store:
        def __init__(self):self.raw=EngineRaw();self.model_cache={}
        def history(self,job):return history
        def excluded_windows(self,job):return set()
        def details(self,job):return past+now,True
        def transaction(self):return nullcontext()
        def peer(self,service,target):return [dict(start_ns=r['start_ns'],value=2,eligible=True) for r in history]
        def complete(self,job,ctx,decisions,at):return {'status':'CAPTURED_NOT_SQL_COMMITTED','decisions':decisions,'context':ctx}
    job=dict(session_key=ACTOR,target_ns=T,version=1)
    stages=[]
    with patch('anomaly_detection.service_reference.model',return_value=(ref,{})):
        full=evaluate_job(Store(),job,context,T+W,progress=stages.append)
        primary=evaluate_job(Store(),job,context|{'primary_details':now},T+W,mode='primary')
    for family in ['rate_5m','rate_60m','service_mix','isolation_forest','service_sequence','timing_regularization',
                   'business_result_change',*cm.FAMILIES,'peer_service_rate_5m','input_subject_burst']:
        check(family,'full_engine_dispatch_contains_evaluation',True,any(d['family']==family for d in full['decisions']),
              level='real_product_engine_scripted_store_no_commit',native_commit='NOT_RUN')
    check('peer_service_rate_5m','full_engine_positive_status','CANDIDATE',one(full['decisions'],'peer_service_rate_5m')['status'],
          level='real_product_engine_scripted_reference_io_no_commit')
    check('rate_5m','primary_marker_is_not_model_execution','SECONDARY_MODELS_PENDING',one(primary['decisions'],'rate_5m')['reason'],
          level='real_primary_engine_scripted_store_no_commit')
    class CaseRaw:
        def __init__(self):self.rows={};self.writes=[]
        def execute(self,sql,params=()):
            if sql.startswith('SELECT * FROM anomaly_detection.adp_case_signals'):return Result(list(self.rows.values()))
            if sql.startswith('INSERT INTO anomaly_detection.adp_case_signals('):
                cols=['signal_key','case_key','scope_key','job_session','target_ns','job_version','source_kind','family','state',
                      'qualified','review_eligible','begin_ns','end_ns','score','body','content_digest','updated_ns','primary_version']
                r=dict(zip(cols,params));self.rows[r['signal_key']]=r;self.writes.append(r.copy());return Result([])
            if sql.startswith(('DELETE FROM anomaly_detection.adp_case_requests','INSERT INTO anomaly_detection.adp_case_requests')):return Result([])
            raise AssertionError('unexpected case SQL: '+sql[:80])
    raw=CaseRaw();store=type('CaseStore',(),{'raw':raw})()
    item=dict(signal_key='synthetic-signal',family='peer_service_rate_5m',entity_type='actor',entity_key=ACTOR,
              service_path=S,target_ns=T,observed=20,upper=2,evidence_verified=True,
              single_signal_review_eligible=True,review_basis='REFERENCE_CONTRAST')
    with patch('anomaly_detection.cases.refresh'):
        for version,(status,state) in enumerate([('CANDIDATE','ACTIVE'),('INSUFFICIENT_DATA','DEFERRED'),
                                                ('CANDIDATE','ACTIVE'),('NO_DEVIATION_OBSERVED','WITHDRAWN')],1):
            cases.replace_scope(store,'synthetic-scope',[item|{'status':status}],T+version,job=job|{'version':version})
            check('peer_service_rate_5m','signal_lifecycle_'+str(version)+'_'+status,state,raw.rows['synthetic-signal']['state'],
                  level='real_replace_scope_scripted_sql_refresh_not_run')


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True);parser.add_argument('--label',default='current');args=parser.parse_args()
    for section in [actor_checks,service_checks,traffic_checks,behavior_checks,context_checks,
                    peer_and_input_checks,longitudinal_checks,scheduler_checks,engine_and_lifecycle_checks]:
        try:section()
        except Exception as exc:
            import traceback
            RESULTS.append(dict(family='HARNESS',test=section.__name__,status='ERROR',error=str(exc),traceback=traceback.format_exc()))
    try:
        commit=subprocess.run(['git','rev-parse','HEAD'],cwd=ROOT,text=True,capture_output=True)
        sha=commit.stdout.strip() if commit.returncode==0 else None
    except OSError:sha=None
    runtime={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT/'anomaly_detection').glob('*.py'))}
    out=dict(reference_commit=sha,code_label=args.label,runtime_files_sha256=runtime,
             harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
             scope='OFFLINE_SYNTHETIC_REAL_PYTHON_FUNCTIONS_WITH_SCRIPTED_STORES_WHERE_LABELLED',
             native_postgresql='NOT_RUN',production='NOT_ACCESSED',http_browser='NOT_RUN',
             oracle='behavioral_invariants_and_exact_integer_hypergeometric_test',
             summary=dict(Counter(r['status'] for r in RESULTS)),families_exercised=sorted({r['family'] for r in RESULTS if r['family']!='HARNESS'}),results=RESULTS)
    Path(args.output).parent.mkdir(parents=True,exist_ok=True)
    Path(args.output).write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:out[k] for k in ['reference_commit','summary','families_exercised']},ensure_ascii=False))
    for r in RESULTS:
        if r['status']!='PASS':print(json.dumps(r,ensure_ascii=False))
    return int(any(r['status']!='PASS' for r in RESULTS))


if __name__=='__main__':raise SystemExit(main())
