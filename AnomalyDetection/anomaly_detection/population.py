"""Service and whole-system views of the same canonical Viewer executions.

Service errors require explicit, comparable, fully covered reported outcomes.
Traffic growth alone is never labelled an outage or customer misconduct.
"""
from collections import Counter,defaultdict
from statistics import median
import json,math
from . import FIVE_NS,KINDS
from .snapshot import api_path,canonical,digest
from .temporal import quantile,phase

DDL=[
 '''CREATE TABLE IF NOT EXISTS anomaly_detection.adp_population(service_path TEXT NOT NULL,start_ns BIGINT NOT NULL,
 body TEXT NOT NULL,content_digest TEXT NOT NULL,PRIMARY KEY(service_path,start_ns))''',
 '''CREATE TABLE IF NOT EXISTS anomaly_detection.adp_population_jobs(start_ns BIGINT PRIMARY KEY,
 version BIGINT NOT NULL DEFAULT 1,processed_version BIGINT NOT NULL DEFAULT 0,dirty BOOLEAN NOT NULL DEFAULT TRUE,
 due_ns BIGINT NOT NULL DEFAULT 0)''',
 'CREATE INDEX IF NOT EXISTS adp_population_pending ON anomaly_detection.adp_population_jobs(dirty,due_ns,start_ns)',
 '''CREATE TABLE IF NOT EXISTS anomaly_detection.adp_viewer_relations(origin_request TEXT NOT NULL,from_request TEXT NOT NULL,to_request TEXT NOT NULL,
 basis TEXT NOT NULL,identity_key TEXT NOT NULL,body TEXT NOT NULL,observed_ns BIGINT NOT NULL,
 current_verified BOOLEAN NOT NULL,PRIMARY KEY(origin_request,from_request,to_request,basis,identity_key))''',
 'CREATE INDEX IF NOT EXISTS adp_viewer_relation_to ON anomaly_detection.adp_viewer_relations(to_request,from_request)',
]


def enqueue(store,targets):
    values=sorted({at//FIVE_NS*FIVE_NS for at in targets if at>0})
    if values:store.raw.execute('INSERT INTO anomaly_detection.adp_population_jobs(start_ns) SELECT * FROM unnest(%s::bigint[]) '
        'ON CONFLICT(start_ns) DO UPDATE SET version=adp_population_jobs.version+1,dirty=TRUE,due_ns=0',(values,))


def outcome(fact,service):
    if not fact.get('source_present') or not fact.get('quality',{}).get('evidence_available') or fact.get('quality',{}).get('conflicted'):return None
    values={str(o['value']) for o in fact.get('observations',[]) if o.get('qualified') and o.get('axis')=='service_dispatch.inquiry_result'}
    if len(values)==1:return 'dispatcher_inquiry_result',next(iter(values))
    if values:return None
    transport=fact.get('transport') or {}
    code=transport.get('root_code')
    if api_path(transport.get('root_call'))==service and isinstance(code,str) and code:
        return 'direct_api_reported_result',code
    return None


def outcome_time(fact,scope):
    if scope=='dispatcher_inquiry_result':
        times=[o.get('at_ns') for o in fact.get('observations',[]) if o.get('qualified') and o.get('axis')=='service_dispatch.inquiry_result']
        return max(times) if times and all(type(t) is int for t in times) else None
    end=(fact.get('transport') or {}).get('ended_ns')
    if type(end) is int:return end
    root=api_path((fact.get('transport') or {}).get('root_call'))
    times=[e.get('at_ns') for e in fact.get('evidence',[]) if e.get('qualified') and api_path(e.get('callpath'))==root]
    return max(times) if times and all(type(t) is int for t in times) else None


def summarize(rows):
    groups=defaultdict(list)
    for row in rows:
        e=json.loads(row['body']) if isinstance(row['body'],str) else row['body']
        if e.get('kind') not in KINDS or e.get('identity_state')!='assigned' or e.get('conflicted') or e.get('request_session_key')!=e.get('session_key'):continue
        service=api_path(e.get('root_call'))
        if service:groups[service].append((row,e))
    if groups:groups['*']=[item for service,items in groups.items() if service!='*' for item in items]
    result={}
    for service,items in groups.items():
        users=Counter(e['session_key'] for _,e in items);codes=defaultdict(Counter);times=defaultdict(list)
        for row,e in items:
            f=json.loads(row['details']) if isinstance(row.get('details'),str) else row.get('details') or {}
            valid=f.get('semantic',{}).get('revision')==row.get('revision') and f.get('semantic',{}).get('anchor_key')==row.get('anchor_key')
            value=outcome(f,api_path(e.get('root_call'))) if valid else None
            if value:
                codes[value[0]][value[1]]+=1;times[value[0]].append(outcome_time(f,value[0]))
        n=len(items)
        result[service]={'executions':n,'sessions':len(users),'top_session_share':max(users.values())/n,
            'service_count':len({api_path(e.get('root_call')) for _,e in items}),
            'outcomes':{scope:dict(values) for scope,values in codes.items()},'known_outcomes':sum(sum(c.values()) for c in codes.values()),
            'outcome_cutoffs':{scope:max(values) if all(type(t) is int for t in values) else None for scope,values in times.items()},
            'covered':True,'scope':'canonical_meaningful_executions','population_is_distinct_session_epochs':True}
    return result


def assess(service,target,current,history):
    """Temporal holdout on continuous service features and explicit outcomes."""
    history=sorted((r for r in history if r.get('covered') and r['start_ns']<target),key=lambda r:r['start_ns'])
    result=[]
    def emit(family,status,reason,**values):
        result.append({'signal_key':'ps1:'+digest([service,target,family]),'family':family,'entity_type':'system' if service=='*' else 'service',
            'entity_key':service,'service_path':service,'target_ns':target,'begin_ns':target,'end_ns':target+FIVE_NS,
            'status':status,'reason':reason,'operator_alert':False,'precision_recall':'NOT_EVALUATED',**values})
    if service=='*' and current.get('service_count',0)<2:
        for family in ('service_population','service_health'):emit(family,'INSUFFICIENT_DATA','SINGLE_SERVICE_NOT_INDEPENDENT_SYSTEM_SIGNAL',
            explanation_fa='این شاهد فقط یک خدمت را پوشش می‌دهد؛ مسئله در پروندهٔ همان خدمت پیگیری می‌شود.')
        return result
    if len(history)<80:
        for family in ('service_population','service_health'):emit(family,'INSUFFICIENT_DATA','INSUFFICIENT_COMPLETE_SERVICE_HISTORY',
            explanation_fa='تاریخچهٔ کامل و قابل مقایسهٔ خدمت هنوز کافی نیست؛ دادهٔ ناکافی عادی بودن نیست.')
        return result
    # Select day/hour/week only when its independent past validation improves.
    cut=len(history)*3//4;training=history[:cut];validation=history[cut:];selected=history;chosen='rolling'
    baseline=median(r['executions'] for r in training)
    best=sum(abs(r['executions']-baseline) for r in validation)/max(1,len(validation))
    for period in ('hourly','daily','weekly'):
        buckets=defaultdict(list)
        for row in training:buckets[phase(row['start_ns'],period)].append(row)
        if any(len(buckets[phase(r['start_ns'],period)])<3 for r in validation):continue
        error=sum(abs(r['executions']-median(x['executions'] for x in buckets[phase(r['start_ns'],period)])) for r in validation)/len(validation)
        candidates=[r for r in history if phase(r['start_ns'],period)==phase(target,period)]
        if len(candidates)>=30 and error<best*.75:selected=candidates;chosen=period;best=error
    def vector(r):return [math.log1p(r['executions']),math.log1p(r['sessions']),r.get('top_session_share',0)]
    vectors=[vector(r) for r in selected];split=max(20,len(vectors)*3//4)
    center=[median(row[i] for row in vectors[:split]) for i in range(3)]
    scale=[max(.1,median(abs(row[i]-center[i]) for row in vectors[:split])) for i in range(3)]
    def score(v):return max(abs(v[i]-center[i])/scale[i] for i in range(3))
    calibration=[score(v) for v in vectors[split:]];observed=score(vector(current));upper=max(6,quantile(calibration,.99)*1.5)
    tail=(1+sum(v>=observed for v in calibration))/(len(calibration)+1)
    high=observed>upper and tail<=.05
    emit('service_population','CANDIDATE' if high else 'NO_DEVIATION_OBSERVED',
        'SERVICE_MULTIVARIATE_PROFILE_SHIFT' if high else 'SERVICE_PROFILE_WITHIN_REFERENCE',
        observed=current['executions'],expected=median(r['executions'] for r in selected),score=observed,upper=upper,
        distinct_sessions=current['sessions'],evidence_verified=True,single_signal_review_eligible=False,
        baseline_origin=chosen,explanation_fa='حجم اجرا، تعداد نشست‌های درگیر و تمرکز مصرف خدمت با تاریخچهٔ همان خدمت مقایسه شد؛ '
            'تغییر جمعی به‌تنهایی قطعی خدمت یا سوءاستفادهٔ کاربر را ثابت نمی‌کند.')
    # Never compare an audited sample selected for suspicious users against a
    # complete census. All executions in each compared window need outcomes.
    current_scope=next((k for k,v in current.get('outcomes',{}).items() if sum(v.values())==current['executions']),None)
    qualified=[]
    if current_scope:
        for row in selected:
            codes=row.get('outcomes',{}).get(current_scope,{})
            observed_end=row.get('outcome_cutoffs',{}).get(current_scope)
            if sum(codes.values())==row['executions'] and row['executions']>0 and type(observed_end) is int and observed_end<target:
                qualified.append((sum(n for c,n in codes.items() if c!='G00000')/row['executions'],row))
    if not current_scope or type(current.get('outcome_cutoffs',{}).get(current_scope)) is not int or len(qualified)<60 or current['executions']<10 or current['sessions']<3:
        emit('service_health','INSUFFICIENT_DATA','SERVICE_OUTCOME_CENSUS_INCOMPLETE',
            explanation_fa='تمام نتیجه‌های هم‌دامنهٔ خدمت و سابقهٔ کافی فراهم نیست؛ افزایش درخواست، قطعی فرض نشده است.')
    else:
        values=[v for v,_ in qualified];codes=current['outcomes'][current_scope]
        bad=sum(n for c,n in codes.items() if c!='G00000');rate=bad/current['executions'];limit=max(.10,quantile(values,.99)*2)
        high=bad>=5 and rate>limit and (1+sum(v>=rate for v in values))/(len(values)+1)<=.05
        emit('service_health','CANDIDATE' if high else 'NO_DEVIATION_OBSERVED',
            'REPORTED_SERVICE_FAILURE_RATE_SHIFT' if high else 'REPORTED_SERVICE_FAILURES_WITHIN_REFERENCE',
            activation_rule_fa='census کاملِ نتیجه‌های هم‌دامنه، حداقل ۶۰ بازهٔ مرجع، حداقل ۱۰ اجرای جاری از ۳ نشست و حداقل ۵ نتیجهٔ ناموفق؛ نرخ خطا باید از بزرگ‌ترِ ۱۰ درصد یا دو برابر صدک ۹۹ مرجع عبور کند و رتبهٔ دُم حداکثر ۰٫۰۵ باشد.',
            reference_windows=len(values),reference_cutoff_ns=target,current_result_requests=current['executions'],
            observed=bad,expected=median(values)*current['executions'],error_rate=rate,upper=limit,
            outcome_scope=current_scope,distinct_sessions=current['sessions'],score=rate/max(.01,limit),
            evidence_verified=True,single_signal_review_eligible=high,
            explanation_fa=f'{bad} نتیجهٔ ناموفق گزارش‌شده از {current["executions"]} اجرا در {current["sessions"]} نشست؛ '
                'افزایش خطا در سطح خدمت دیده شده است. علت ریشه‌ای یا قطعیت مالی از آن استنتاج نمی‌شود.')
    return result


def process_one(store,now,*,recent=False):
    store.active_population_target=None
    job=store.raw.execute('SELECT * FROM anomaly_detection.adp_population_jobs WHERE dirty=TRUE AND due_ns<=%s '
        'ORDER BY start_ns '+('DESC' if recent else 'ASC')+' LIMIT 1',(now,)).fetchone()
    if not job:return None
    target=job['start_ns']
    store.active_population_target=target
    with store.transaction():
        proof=store.raw.execute('SELECT source,complete FROM anomaly_detection.adp_source_windows WHERE start_ns=%s',(target,)).fetchone()
        available=bool(proof and proof['complete'] and json.loads(proof['source']).get('peer_population_valid'))
        rows=store.raw.execute('SELECT m.body,f.details,f.revision,f.anchor_key,f.source_present,f.state '
            'FROM anomaly_detection.adp_window_members m LEFT JOIN anomaly_detection.adp_facts f ON f.request_key=m.request_key '
            'WHERE m.start_ns=%s',(target,)).fetchall() if available else []
        if any(not r['source_present'] or r['state']!='active' or json.loads(r['body']).get('revision')!=r['revision'] for r in rows):available=False
        summaries=summarize(rows)
        old=store.raw.execute('SELECT DISTINCT service_path FROM anomaly_detection.adp_population WHERE start_ns>=%s AND start_ns<=%s',(target-56*288*FIVE_NS,target)).fetchall()
        services=sorted(set(summaries)|{r['service_path'] for r in old})
        from .cases import replace_scope,normal_observations
        for service in services:
            body=summaries.get(service,{'executions':0,'sessions':0,'top_session_share':0,'outcomes':{},'known_outcomes':0,'covered':available})
            body=dict(body,start_ns=target)
            if not available:body['covered']=False
            previous=store.raw.execute('SELECT content_digest FROM anomaly_detection.adp_population WHERE service_path=%s AND start_ns=%s',(service,target)).fetchone()
            if previous is None or previous['content_digest']!=digest(body):
                store.raw.execute('UPDATE anomaly_detection.adp_population_jobs SET dirty=TRUE,version=version+1,due_ns=0 '
                    'WHERE start_ns>%s AND start_ns<=%s AND dirty=FALSE AND processed_version>0',(target,target+56*288*FIVE_NS))
            store.raw.execute('INSERT INTO anomaly_detection.adp_population VALUES(%s,%s,%s,%s) ON CONFLICT(service_path,start_ns) '
                'DO UPDATE SET body=excluded.body,content_digest=excluded.content_digest',(service,target,canonical(body),digest(body)))
            if service!='*':
                from .scenario_store import enqueue as scenario_enqueue,changed as scenario_changed
                if previous is None or previous['content_digest']!=digest(body):scenario_changed(store,[service],target)
                scenario_enqueue(store,'canonical_traffic',service,service,target)
            from .cases import identity
            health_key=identity('system' if service=='*' else 'service',service,'service_health',service)
            prior=[json.loads(r['body']) for r in store.raw.execute('SELECT p.body FROM anomaly_detection.adp_population p '
                'WHERE p.service_path=%s AND p.start_ns<%s AND p.start_ns>=%s '
                'AND NOT EXISTS(SELECT 1 FROM anomaly_detection.adp_case_signals s WHERE s.case_key=%s '
                "AND s.target_ns=p.start_ns AND s.state='ACTIVE' AND s.qualified=TRUE AND s.review_eligible=TRUE "
                "AND COALESCE((SELECT b.label FROM anomaly_detection.adp_case_feedback b WHERE b.case_key=s.case_key "
                "AND b.case_revision=(SELECT c.revision FROM anomaly_detection.adp_cases c WHERE c.case_key=s.case_key) AND b.reviewed_end_ns>=s.end_ns ORDER BY b.id DESC LIMIT 1),'unreviewed')<>'reviewed_benign') "
                'ORDER BY p.start_ns DESC LIMIT 16128',
                (service,target,target-56*288*FIVE_NS,health_key)).fetchall()]
            decisions=assess(service,target,body,prior) if available else [
                {'signal_key':'ps1:'+digest([service,target,f]),'family':f,'entity_type':'system' if service=='*' else 'service',
                 'entity_key':service,'service_path':service,'target_ns':target,'status':'INSUFFICIENT_DATA','reason':'POPULATION_COVERAGE_UNKNOWN'}
                for f in ('service_population','service_health')]
            for decision in decisions:decision['job_version']=job['version']
            replace_scope(store,'population:'+service+':'+str(target),decisions,now,source_kind='population')
            normal_observations(store,decisions,now)
        store.raw.execute('UPDATE anomaly_detection.adp_population_jobs SET dirty=FALSE,processed_version=version WHERE start_ns=%s AND version=%s',
            (target,job['version']))
    return {'target_ns':target,'services':len(services),'status':'APPLIED' if available else 'WAITING_FOR_COVERAGE'}


def warm(store,limit=8):
    state=store.state('population_backfill_v1')
    if state.get('done'):return state
    if 'through_ns' not in state:
        state['through_ns']=store.raw.execute('SELECT MAX(start_ns) AS at FROM anomaly_detection.adp_source_windows').fetchone()['at']
    if state['through_ns'] is None:return state
    rows=store.raw.execute('SELECT start_ns FROM anomaly_detection.adp_source_windows WHERE start_ns>%s AND start_ns<=%s '
        'ORDER BY start_ns LIMIT %s',(state.get('after_ns',0),state['through_ns'],limit)).fetchall()
    with store.transaction():
        enqueue(store,[r['start_ns'] for r in rows])
        if rows:state['after_ns']=rows[-1]['start_ns']
        state['done']=len(rows)<limit;store.save_state('population_backfill_v1',state)
    return state


def save_relations(store,key,packet,now):
    journey=packet.get('journey') or {}
    if not journey.get('truncated') and not journey.get('coverage_caveats'):
        store.raw.execute('DELETE FROM anomaly_detection.adp_viewer_relations WHERE origin_request=%s',(key,))
    else:
        store.raw.execute('UPDATE anomaly_detection.adp_viewer_relations SET current_verified=FALSE WHERE origin_request=%s',(key,))
    # Relations are delegated Viewer output. No Session/IP/time heuristic.
    for edge in journey.get('edges',[]):
        a=edge.get('from_request_key');b=edge.get('to_request_key');basis=edge.get('basis','');identity=edge.get('identity_key')
        if not all(isinstance(v,str) and v for v in (a,b,basis,identity)):continue
        if not basis.startswith(('shared_typed_','explicit_')):continue
        store.raw.execute('INSERT INTO anomaly_detection.adp_viewer_relations VALUES(%s,%s,%s,%s,%s,%s,%s,TRUE) '
            'ON CONFLICT(origin_request,from_request,to_request,basis,identity_key) DO UPDATE SET body=excluded.body,observed_ns=excluded.observed_ns,current_verified=TRUE',
            (key,a,b,basis,identity,canonical(edge),now))
