"""Request-scoped durations and bounded session patterns; no financial graph."""
from collections import Counter, defaultdict
from functools import lru_cache
import math
import statistics
from compact_behavior import FIVE
from compact_behavior.extract import digest
from .forest import SmallIsolationForest


def patterns(actors, previous=None, start=None):
    sessions = defaultdict(list)
    incomplete = set()
    for (session, service), actor in actors.items():
        sessions[session].extend(actor.get('events', []))
        if actor.get('sequence_incomplete'):
            incomplete.add(session)
    transitions = Counter()
    vectors = []
    cvs = []
    median_gaps = []
    results = {}
    for session, events in sessions.items():
        # No truncated sequence is labelled complete.
        if len(events) > 512 or session in incomplete:
            results[session] = dict(limited=True, events=[], counts={})
            continue
        events.sort()
        counts = Counter(e[1] for e in events)
        total = len(events)
        probabilities = [n/total for n in counts.values()] if total else []
        vector = [math.log1p(total),math.log1p(len(counts)),max(probabilities,default=0),
                  -sum(p*math.log(p) for p in probabilities)]
        if total >= 10:
            vectors.append((digest(session), vector))
        prior = (previous or {}).get(session, [])
        continuity = previous is not None and session in previous and prior is not None
        prior = prior or []
        combined = sorted(prior[-32:]+events)
        pairs = Counter()
        intervals = []
        tied = False
        for left, right in zip(combined, combined[1:]):
            if start is not None and right[0] < start:
                continue
            gap = (right[0]-left[0])/1e9
            if gap <= 0:
                tied = True
                continue
            pairs[digest([left[1],right[1]])] += 1
            intervals.append(gap)
        cv = statistics.pstdev(intervals)/statistics.mean(intervals) if len(intervals)>=20 and sum(intervals)>=60 else None
        if tied:
            cv = None
        if continuity and not tied:
            transitions.update(pairs)
        if cv is not None:
                cvs.append(cv)
                median_gaps.append(statistics.median(intervals))
        results[session] = dict(limited=False, events=events,counts=counts,vector=vector,
            pairs=pairs,cv=cv,tied=tied,continuity=continuity,
            gap_median=statistics.median(intervals) if intervals else None,
            timing_evidence=[e[2] for e in combined[-12:]])
    # No session identifier persists in peer training vectors.
    vector_sample = [v for _,v in sorted(vectors)[:64]]
    complete = len(transitions)<=4096 and any(v.get('continuity') for v in results.values())
    return dict(transitions=dict(transitions) if complete else {}, complete=complete,
        tail_signature=digest([(s,sorted(e)[-32:]) for s,e in sorted(sessions.items())]),
        peer_vectors=vector_sample, timing_n=len(cvs),
        timing_gap_median=statistics.median(median_gaps) if median_gaps else None,
        timing_p05=sorted(cvs)[max(0,math.ceil(.05*len(cvs))-1)] if cvs else None), results


@lru_cache(maxsize=8)
def trained_forest(vectors):
    split = len(vectors)*3//4
    model = SmallIsolationForest().fit(vectors[:split])
    calibration = [model.score(v) for v in vectors[split:]]
    return model, calibration, max(.65,max(calibration)+.02)


def evaluate_patterns(start, summary, services, actors, refs, add, previous=None):
    current_summary, sessions = patterns(actors, previous, start)
    training_cutoff = start//(12*FIVE)*(12*FIVE)
    training_refs = [r for r in refs if training_cutoff-276*FIVE<=r['start_ns']<training_cutoff]
    vectors = []
    for ref in training_refs:
        # Balanced bounded window contribution, not all users' stored logs.
        vectors.extend(ref['summary'].get('patterns',{}).get('peer_vectors',[])[:4])
    vectors = tuple(tuple(v) for v in vectors[-512:])
    forest = trained_forest(vectors) if len(vectors)>=160 else None
    old_pairs = Counter()
    sequence_refs = []
    timing_refs = []
    for ref in refs:
        value = ref['summary'].get('patterns',{})
        if value.get('complete'):
            old_pairs.update(value.get('transitions',{}));sequence_refs.append(ref)
            if len(old_pairs)>20000:
                old_pairs.clear();sequence_refs=[];break
        if value.get('timing_n',0)>0 and value.get('timing_p05') is not None:
            timing_refs.append(ref)
    old_total = sum(old_pairs.values())
    # Chronological calibration of transition surprise, using compact counts.
    split=len(sequence_refs)*2//3
    train_pairs=Counter()
    for ref in sequence_refs[:split]:train_pairs.update(ref['summary']['patterns']['transitions'])
    vocabulary=len(train_pairs)+1
    denominator=sum(train_pairs.values())+vocabulary
    def surprise(pairs):
        return sum(-math.log((train_pairs.get(pair,0)+1)/denominator)*n for pair,n in pairs.items())/max(1,sum(pairs.values()))
    calibration=[surprise(r['summary']['patterns']['transitions']) for r in sequence_refs[split:]
        if sum(r['summary']['patterns']['transitions'].values())>=10]
    sequence_limit=max(calibration)+.5 if calibration else None
    timing_baseline = statistics.median(r['summary']['patterns']['timing_p05'] for r in timing_refs) if timing_refs else None
    past_gaps=[r['summary']['patterns']['timing_gap_median'] for r in timing_refs if r['summary']['patterns'].get('timing_gap_median') is not None]
    past_gap=statistics.median(past_gaps) if past_gaps else None
    for session, actor in sessions.items():
        evidence = [e[2] for e in actor['events'][-12:]]
        if actor['limited']:
            for method in ('isolation_forest','service_sequence','timing_regularization'):
                add(method,'*',session,'INVALID_INPUT',reason='SESSION_PATTERN_LIMIT',used=[])
            continue
        n = sum(actor['counts'].values())
        if n>=10 and forest:
            model,calibration,limit=forest
            score=model.score(actor['vector'])
            rank=(1+sum(v>=score for v in calibration))/(len(calibration)+1)
            result=add('isolation_forest','*',session,'ANOMALY' if score>limit and rank<=.025 else 'NORMAL',
                score,None,limit,evidence,used=training_refs)
            result.update(model_id=digest(['peer-isolation-1',vectors]),training_rows=len(vectors)*3//4,
                calibration_rows=len(calibration),comparison='PAST_SESSION_PEERS_NOT_PERSONAL_PROFILE',score_is_probability=False)
        elif n>=10:
            add('isolation_forest','*',session,'INSUFFICIENT_DATA',reason='PEER_MODEL_WARMUP',used=training_refs)
        if n>=10:
            rare=sum(count for pair,count in actor['pairs'].items() if old_pairs.get(pair,0)<3)
            pair_total=sum(actor['pairs'].values())
            ready=actor['continuity'] and not actor['tied'] and len(calibration)>=12 and old_total>=500
            # Require repeated evidence of a rare transition, not a single new click.
            repeated=max((v for pair,v in actor['pairs'].items() if old_pairs.get(pair,0)<3),default=0)
            score=surprise(actor['pairs'])
            sequence_result=add('service_sequence','*',session,'INSUFFICIENT_DATA' if not ready else
                'ANOMALY' if repeated>=3 and rare>=5 and rare/max(1,pair_total)>.8 and score>sequence_limit else 'NORMAL',
                score,None,sequence_limit,evidence,
                reason=None if ready else 'CONTIGUOUS_SEQUENCE_REFERENCE_REQUIRED',used=sequence_refs)
            sequence_result.update(calibration_windows=len(calibration),rare_transition_fraction=rare/max(1,pair_total),
                comparison='PAST_PEER_TRANSITIONS_WITH_TEMPORAL_HOLDOUT')
        if n>=21 and actor['cv'] is not None:
            limit=min(.05,timing_baseline/3) if timing_baseline is not None else None
            ready=actor['continuity'] and past_gap is not None and len(timing_refs)>=12 and sum(r['summary']['patterns']['timing_n'] for r in timing_refs)>=30
            add('timing_regularization','*',session,'INSUFFICIENT_DATA' if not ready else
                'ANOMALY' if actor['cv']<limit and actor['gap_median']<past_gap/3 else 'NORMAL',actor['cv'],timing_baseline,limit,actor['timing_evidence'],
                reason='LOWER_VARIATION_THAN_REFERENCE' if ready else 'TIMING_REFERENCE_WARMUP',used=timing_refs)
    for key, service in services.items():
        rejection_refs=[r for r in refs if key in r['summary']['services']
            and 'rejected_count' in r['summary']['services'][key] and not r['summary']['services'][key]['invalid_rate']]
        rejection_past=[r['summary']['services'][key]['rejected_actor_p95'] for r in rejection_refs]
        from .engine import upper
        rejection_limit=upper(rejection_past)
        for session,count in service.get('rejected_actors',{}).items():
            result=add('rate_limit_rejections',key,session,'INSUFFICIENT_DATA' if len(rejection_refs)<12 else
                'ANOMALY' if count>rejection_limit else 'NORMAL',count,
                statistics.median(rejection_past) if rejection_past else None,rejection_limit,
                service['rejected_witnesses'].get(session,[]),reason='RATE_LIMITED_ATTEMPTS_NOT_COMPLETED_EXECUTIONS',used=rejection_refs)
            result['behavior_stage']='REJECTED_ATTEMPT'
        values=service.get('durations',[])
        selected=[r for r in refs if r['summary']['services'].get(key,{}).get('duration_n',0)>=10
                  and r['summary']['services'][key].get('duration_invalid',0)<=r['summary']['services'][key]['duration_n']/4]
        past=[r['summary']['services'][key]['duration_p95'] for r in selected]
        baseline=statistics.median(past) if past else None
        spread=statistics.median(abs(v-baseline) for v in past) if past else None
        limit=max(250.,baseline*2,baseline+6*1.4826*spread) if past else None
        value=sorted(values)[max(0,math.ceil(.95*len(values))-1)] if values else None
        ready=len(selected)>=12 and len(values)>=10
        invalid=service.get('duration_invalid',0)>len(values)/4
        result=add('service_latency',key,None,'INVALID_INPUT' if invalid else 'INSUFFICIENT_DATA' if not ready else
            'ANOMALY' if value>limit else 'NORMAL',value,baseline,limit,service['witnesses'],
            reason='REPORTED_EXECUTION_TIME_P95_RELATIVE_COMPARISON',used=selected)
        result.update(measurement_unit='milliseconds',signal_domain='SERVICE_HEALTH_NOT_USER_MISUSE',
            duration_valid=len(values),duration_missing=service.get('duration_invalid',0))
