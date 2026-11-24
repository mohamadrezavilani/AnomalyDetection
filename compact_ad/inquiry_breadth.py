"""Outcome-independent rolling breadth over reviewed same-request subjects.

Only two adjacent published windows are read. Events stay transient; summaries
carry a signature rather than another copy of request inputs or identifiers.
"""
from collections import Counter, defaultdict, deque
from itertools import islice
from bisect import bisect_left
from compact_behavior import FIVE, FEATURES, inquiry
from compact_behavior.extract import digest

POLICY = 'requested-inquiry-breadth-2'
WATER = 'Services.v1/WaterBills'


def current(actors):
    return {(session,service):actor['inquiry_events'] for (session,service),actor in actors.items()
            if service in inquiry.ROUTES and actor.get('inquiry_events')}


def signature(actors):
    return digest([[s,k,events] for (s,k),events in sorted(current(actors).items())])


def previous(row, cutoff):
    f=row['features'];service=f.get('service_key')
    if (f.get('version')!=FEATURES or not f.get('session_eligible') or service not in inquiry.ROUTES
            or not row.get('session_id') or f.get('security_attempt')):
        return None
    subjects=(f.get(inquiry.POLICY) or {}) if (f.get('input_feature_eligibility',{}).get('targets')
        and type(f.get('input_asof_ns')) is int and f['input_asof_ns']<cutoff) else {}
    return (row['session_id'],service,(row['observed_at_ns'],row['behavior_id'],subjects,row.get('result_code')))


def apply(start,summary,actors,results,previous_events=()):
    if summary['content_resource_invalid']:
        return
    groups=current(actors)
    combined={key:list(events) for key,events in groups.items()}
    for session,service,event in previous_events or ():
        if (session,service) in combined:combined[(session,service)].append(event)
    rows={(r['session_id'],r['service'],r.get('numeric_path')):r for r in results if r['method']=='target_diversity'}
    peers=defaultdict(list)
    for (session,service),actor in actors.items():
        for axis,field in actor.get('target_fields',{}).items():
            if field['covered']==actor['count']:peers[(service,axis)].append(len(field['tokens']))
    for values in peers.values():values.sort()
    for (session,service),events in combined.items():
        # A logical RequestID is represented once, independently of log count.
        events=sorted({e[1]:e for e in events if type(e[0]) is int and start-FIVE<=e[0]<start+FIVE}.values())
        for axis,_ in inquiry.ROUTES[service]:
            result=rows.get((session,service,axis))
            if result is None:continue
            floor=10 if service==WATER else 12
            limit=max(floor,result['threshold'] or floor) if result.get('target_reference_ready') else floor
            queue=deque();known=deque();targets=Counter();frequencies=Counter()
            outcomes=Counter({'G00000':0,'UNKNOWN':0});covered=0;peak=0;best=None
            for event in events:
                at,bid,subjects,code=event
                token=subjects.get(axis)
                bucket=code or 'UNKNOWN'
                if bucket not in outcomes and len(outcomes)>=32:bucket='OTHER_RESULT_CODES'
                queue.append((at,bid,token,bucket))
                if token:
                    before=targets[token]
                    if before:frequencies[before]-=1
                    targets[token]+=1;frequencies[before+1]+=1;covered+=1
                    peak=max(peak,before+1);known.append((at,bid))
                outcomes[bucket]+=1
                while queue and queue[0][0]<=at-FIVE:
                    _,_,old,old_code=queue.popleft();outcomes[old_code]-=1
                    if old:
                        before=targets[old];frequencies[before]-=1
                        targets[old]-=1;covered-=1
                        if before>1:frequencies[before-1]+=1
                        if targets[old]==0:del targets[old]
                while known and known[0][0]<=at-FIVE:known.popleft()
                while peak and not frequencies[peak]:peak-=1
                width=len(targets)
                if at<start or width<limit or width*5<covered*4:continue
                if result.get('target_reference_ready') and width<=result['threshold']:continue
                # Compare breadth with breadth. Retry volume of a peer is not
                # evidence that querying many different subjects is routine.
                values=peers.get((service,axis),())
                own=actors[(session,service)]['target_fields'].get(axis)
                included=bool(own and own['covered']==actors[(session,service)]['count'])
                n=len(values)-int(included);p95=None
                if n:
                    import math
                    position=math.ceil(.95*n)-1
                    own_width=len(own['tokens']) if included else None
                    p95=values[position+int(included and bisect_left(values,own_width)<=position)]
                if n>=20 and width<=2*p95:continue
                score=(width,at,len(queue))
                if best is None or score>best[0]:
                    best=(score,dict(requests=len(queue),covered_requests=covered,distinct_targets=width,
                        most_frequent_count=peak,repeated_requests=covered-width,
                        successful_requests=outcomes.get('G00000',0),unknown_requests=outcomes.get('UNKNOWN',0),
                        result_counts={k:v for k,v in outcomes.items() if v},
                        evidence=[r[1] for r in islice(known,12)],period_start_ns=queue[0][0],period_end_ns=at+1,
                        observed_is_lower_bound=covered<len(queue),peer_count=n,peer_p95_distinct_targets=p95))
            if best is None:continue
            values=best[1]
            if len(set(values['evidence']))<3:continue
            result.update(values,status='ANOMALY',observed=values['distinct_targets'],threshold=limit,
                single_signal_review_eligible=True,inquiry_breadth_policy=POLICY,
                reason='ENUMERATED_REQUESTED_INQUIRY_TARGETS',
                requested_window_requests=actors[(session,service)]['count'],
                span_seconds=(values['period_end_ns']-values['period_start_ns']-1)/1e9,
                failed_requests=values['requests']-values['successful_requests']-values['unknown_requests'],
                threshold_basis='PAST_TYPED_TARGET_DIVERSITY' if result.get('target_reference_ready') else 'INITIAL_ENGINEERING_FLOOR',
                next_action='هدف‌های ورودی شاهد و توزیع نتیجه را بررسی کنید؛ موفقیت پاسخ شرط شمارش هدف درخواستی نیست.')
