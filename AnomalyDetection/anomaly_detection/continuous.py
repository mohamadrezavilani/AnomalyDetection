"""Event-aligned rolling counts; a source page boundary is not an event boundary.

References use the SAME event-aligned duration, past-only other-session maxima,
and complete canonical population coverage. Missing/pruned coverage is unknown.
"""
from collections import Counter
from statistics import median
import json
from . import FIVE_NS
from .snapshot import canonical,digest

SPANS=(FIVE_NS,12*FIVE_NS,288*FIVE_NS,7*288*FIVE_NS)
HISTORY_NS=56*288*FIVE_NS


def coverage_runs(rows):
    runs=[]
    for row in sorted(rows,key=lambda x:x['start_ns']):
        proof=json.loads(row['source']) if isinstance(row.get('source'),str) else row.get('source',{})
        if not row.get('complete') or proof.get('peer_population_valid') is not True:continue
        at=row['start_ns']
        if runs and runs[-1][1]==at:runs[-1][1]=at+FIVE_NS
        else:runs.append([at,at+FIVE_NS])
    return runs


def covered(begin,end,runs):return any(left<=begin and end<=right for left,right in runs)


def peak(events,span,begin,end,runs):
    """Exact [event_time+1-span,event_time+1), including simultaneous requests."""
    rows=sorted(events,key=lambda r:(r['at_ns'],r['request_key']));left=0;best=None;i=0
    while i<len(rows):
        at=rows[i]['at_ns'];right=i+1
        while right<len(rows) and rows[right]['at_ns']==at:right+=1
        while left<right and rows[left]['at_ns']<at+1-span:left+=1
        if begin<=at<end and covered(at+1-span,at+1,runs):
            n=right-left
            if best is None or n>best['observed']:
                selected=rows[left:right]
                best={'observed':n,'begin_ns':at+1-span,'end_ns':at+1,
                    'request_keys':[r['request_key'] for r in selected],
                    'evidence_verified':all(r.get('qualified') is True for r in selected)}
        i=right
    return best


def database_peak(store,service,subject,target,span,runs):
    """Exact large-actor fallback; never clip an 8,193rd execution to normal."""
    row=store.raw.execute('WITH history AS (SELECT f.at_ns,COUNT(*) OVER w AS volume,'
        "COUNT(*) FILTER(WHERE f.details::jsonb->'quality'->>'evidence_available'='true' "
        "AND COALESCE(f.details::jsonb->'quality'->>'conflicted','false')='false' "
        "AND f.details::jsonb->'semantic'->>'state'='active' "
        "AND f.details::jsonb->'semantic'->>'revision'=f.revision::text "
        "AND f.details::jsonb->'semantic'->>'anchor_key'=f.anchor_key "
        "AND f.details::jsonb->>'source_present'='true') OVER w AS verified "
        'FROM anomaly_detection.adp_facts f JOIN anomaly_detection.adp_source_windows sw ON sw.start_ns=(f.at_ns/%s)*%s '
        'JOIN anomaly_detection.adp_window_members m ON m.start_ns=sw.start_ns AND m.request_key=f.request_key '
        "WHERE f.session_key=%s AND f.service_path=%s AND f.eligible=TRUE AND f.source_present=TRUE "
        "AND f.state='active' AND sw.complete=TRUE AND f.at_ns>=%s AND f.at_ns<%s "
        'WINDOW w AS (ORDER BY f.at_ns RANGE BETWEEN %s PRECEDING AND CURRENT ROW)) '
        'SELECT volume AS observed,at_ns+1-%s AS begin_ns,at_ns+1 AS end_ns,volume=verified AS evidence_verified '
        'FROM history h WHERE h.at_ns>=%s AND h.at_ns<%s AND EXISTS('
        'SELECT 1 FROM jsonb_to_recordset(%s::jsonb) AS r(begin_ns BIGINT,end_ns BIGINT) '
        'WHERE h.at_ns+1-%s>=r.begin_ns AND h.at_ns+1<=r.end_ns) ORDER BY volume DESC,h.at_ns LIMIT 1',
        (FIVE_NS,FIVE_NS,subject,service,target-span,target+FIVE_NS,span-1,span,target,target+FIVE_NS,
         canonical([{'begin_ns':a,'end_ns':b} for a,b in runs]),span)).fetchone()
    return dict(row) if row else None


def histogram_reference(histogram,observed,comparisons):
    n=sum(row['n'] for row in histogram)
    values=sorted((int(row['value']),int(row['n'])) for row in histogram)
    def ordinal(k):
        seen=0
        for value,count in values:
            seen+=count
            if seen>k:return value
    expected=((ordinal((n-1)//2)+ordinal(n//2))/2) if n else None
    tail=(1+sum(row['n'] for row in histogram if row['value']>=observed))/(n+1)
    first=min((row['low_ns'] for row in histogram),default=None);last=max((row['high_ns'] for row in histogram),default=None)
    minimum=max(100,100*max(1,comparisons)-1)
    ready=bool(n>=minimum and first is not None and last-first>=288*FIVE_NS)
    adjusted=min(1.,max(1,comparisons)*tail)
    return {'ready':ready,'other_session_epochs':n,'minimum_other_session_epochs':minimum,'expected':expected,
        'reference_max':max((v for v,_ in values),default=None),'empirical_tail_rank':tail,
        'adjusted_empirical_tail_rank':adjusted,'comparison_count':comparisons,'screening_level':.01,
        'high':bool(ready and observed>expected and adjusted<=.01),
        'calibration_status':'DESCRIPTIVE_RANK_PRODUCTION_ERROR_RATE_NOT_VALIDATED'}


def reference(store,service,subject,target,span,runs,epoch):
    global_key=('continuous-ref-v1',service,target,span,epoch,digest(runs))
    cache=getattr(store,'rolling_cache',None)
    if cache is None:cache=store.rolling_cache={}
    common=('WITH events AS (SELECT f.session_key,f.at_ns,COUNT(*) OVER('
        'PARTITION BY f.session_key ORDER BY f.at_ns RANGE BETWEEN %s PRECEDING AND CURRENT ROW) AS volume '
        'FROM anomaly_detection.adp_facts f JOIN anomaly_detection.adp_source_windows sw '
        'ON sw.start_ns=(f.at_ns/%s)*%s JOIN anomaly_detection.adp_window_members m '
        'ON m.start_ns=sw.start_ns AND m.request_key=f.request_key '
        "WHERE f.service_path=%s AND f.eligible=TRUE AND f.source_present=TRUE "
        "AND f.state='active' AND f.at_ns>=%s AND f.at_ns<%s AND sw.complete=TRUE "
        "AND sw.source::jsonb->>'peer_population_valid'='true' "
        'AND NOT EXISTS(SELECT 1 FROM anomaly_detection.adp_incidents i JOIN anomaly_detection.adp_feedback b '
        'ON b.incident_key=i.incident_key WHERE i.session_key=f.session_key AND i.target_ns=sw.start_ns '
        "AND b.label='confirmed_suspicious' AND b.id=(SELECT MAX(v.id) FROM anomaly_detection.adp_feedback v WHERE v.incident_key=i.incident_key))), "
        'maxima AS (SELECT e.session_key,MAX(e.volume) AS value,MIN(e.at_ns) AS low_ns,MAX(e.at_ns) AS high_ns '
        'FROM events e WHERE e.at_ns>=%s AND EXISTS(SELECT 1 FROM jsonb_to_recordset(%s::jsonb) AS r(begin_ns BIGINT,end_ns BIGINT) '
        'WHERE e.at_ns+1-%s>=r.begin_ns AND e.at_ns+1<=r.end_ns) GROUP BY e.session_key) ')
    args=(span-1,FIVE_NS,FIVE_NS,service,target-HISTORY_NS-span,target,target-HISTORY_NS,
        canonical([{'begin_ns':a,'end_ns':b} for a,b in runs]),span)
    if global_key not in cache:
        rows=store.raw.execute(common+'SELECT session_key,value,low_ns,high_ns FROM maxima ORDER BY session_key LIMIT 10001',args).fetchall()
        if len(cache)>=24:cache.clear()
        # A larger population uses a server-side histogram below, never a
        # truncated reference. Cached actor maxima are bounded to 10,000.
        cache[global_key]=tuple((r['session_key'],r['value'],r['low_ns'],r['high_ns']) for r in rows) if len(rows)<=10000 else None
    population=cache[global_key]
    if population is None:
        return [dict(r) for r in store.raw.execute(common+'SELECT value,COUNT(*) AS n,MIN(low_ns) AS low_ns,MAX(high_ns) AS high_ns '
            'FROM maxima WHERE session_key<>%s GROUP BY value ORDER BY value',(*args,subject)).fetchall()]
    buckets={}
    for actor,value,low,high in population:
        if actor==subject:continue
        row=buckets.setdefault(value,{'value':value,'n':0,'low_ns':low,'high_ns':high})
        row['n']+=1;row['low_ns']=min(row['low_ns'],low);row['high_ns']=max(row['high_ns'],high)
    return [buckets[v] for v in sorted(buckets)]


def evaluate(store,job,context):
    target=job['target_ns'];session=job['session_key']
    services=sorted(next((w.get('counts') or {} for w in context['windows'] if w['start_ns']==target),{}))
    if not services:return [],{}
    source_rows=store.raw.execute('SELECT start_ns,source,complete FROM anomaly_detection.adp_source_windows '
        'WHERE start_ns>=%s AND start_ns<%s ORDER BY start_ns',(target-HISTORY_NS-max(SPANS),target+FIVE_NS)).fetchall()
    runs=coverage_runs(source_rows);decisions=[];inputs={}
    tested=sum(any(right>target and max(target+1,left+span)<=min(target+FIVE_NS,right) for left,right in runs) for span in SPANS)
    comparisons=max(1,len(services)*tested)
    for service in services:
        name='context:'+service
        try:
            with store.transaction():
                store.raw.execute('INSERT INTO anomaly_detection.adp_peer_epochs VALUES(%s,0) ON CONFLICT DO NOTHING',(name,))
                epoch=store.raw.execute('SELECT version FROM anomaly_detection.adp_peer_epochs WHERE service_path=%s FOR SHARE',(name,)).fetchone()['version']
                inputs[name]=epoch
                rows=store.raw.execute('SELECT f.request_key,f.at_ns,f.details,f.revision,f.anchor_key FROM anomaly_detection.adp_facts f '
                    'JOIN anomaly_detection.adp_source_windows sw ON sw.start_ns=(f.at_ns/%s)*%s '
                    'JOIN anomaly_detection.adp_window_members m ON m.start_ns=sw.start_ns AND m.request_key=f.request_key '
                    "WHERE f.session_key=%s AND f.service_path=%s AND f.eligible=TRUE "
                    "AND f.source_present=TRUE AND f.state='active' AND sw.complete=TRUE AND f.at_ns>=%s AND f.at_ns<%s "
                    'ORDER BY f.at_ns,f.request_key LIMIT 8193',
                    (FIVE_NS,FIVE_NS,session,service,target-max(SPANS),target+FIVE_NS)).fetchall()
                events=[]
                for row in rows:
                    fact=json.loads(row['details']) if row['details'] else {}
                    valid=bool(fact.get('source_present') and fact.get('quality',{}).get('evidence_available') and
                        not fact.get('quality',{}).get('conflicted') and fact.get('semantic',{}).get('state')=='active' and
                        fact.get('semantic',{}).get('revision')==row['revision'] and fact.get('semantic',{}).get('anchor_key')==row['anchor_key'])
                    events.append({'request_key':row['request_key'],'at_ns':row['at_ns'],'qualified':valid})
                for span in SPANS:
                    value=database_peak(store,service,session,target,span,runs) if len(rows)>8192 else peak(events,span,target,target+FIVE_NS,runs)
                    base={'finding_key':'pf1:'+digest([session,target,'continuous_rate',service,span]),
                        'session_key':session,'target_ns':target,'family':'continuous_rate','dimension':'activity',
                        'service_path':service,'duration_ns':span,'comparison_count':comparisons,
                        'baseline_unit':'canonical_executions_in_event_aligned_duration','operator_alert':False,
                        'precision_recall':'NOT_EVALUATED'}
                    if value is None:
                        decisions.append(base|{'status':'INSUFFICIENT_DATA','reason':'EVENT_SPAN_COVERAGE_OR_PAGE_INCOMPLETE',
                            'explanation_fa':'پوشش کامل بازهٔ پیوسته یا تمام رخدادهای آن در این نوبت فراهم نیست؛ شکاف صفر فرض نشده است.'});continue
                    histogram=reference(store,service,session,target,span,runs,epoch)
                    ref=histogram_reference(histogram,value['observed'],comparisons)
                    status='CANDIDATE' if ref['high'] else 'NO_DEVIATION_OBSERVED' if ref['ready'] else 'INSUFFICIENT_DATA'
                    model={'model_id':'cr1:'+digest([service,target,span,histogram]),'version':'exact-event-rate-1',
                        'cutoff_ns':target,'duration_ns':span,'histogram':histogram,'input_epoch':epoch,'coverage_digest':digest(runs)}
                    minutes=span/60e9
                    decisions.append(base|value|ref|{'model':model,'status':status,'reason':'EVENT_ALIGNED_RATE_EXCEEDED' if ref['high'] else
                        'EVENT_ALIGNED_RATE_WITHIN_REFERENCE' if ref['ready'] else 'INSUFFICIENT_EVENT_ALIGNED_REFERENCE',
                        'span_evidence_verified':value['evidence_verified'],
                        'single_signal_review_eligible':bool(ref['high'] and value['observed']>ref['reference_max']),
                        'review_policy_version':2,'review_basis':'REFERENCE_CONTRAST' if ref['high'] and value['observed']>ref['reference_max'] else 'DESCRIPTIVE_RARITY_ONLY',
                        'score':value['observed']/max(1,ref['expected'] or 1),'witness_request_key':(value.get('request_keys') or [None])[-1],
                        'explanation_fa':f'{value["observed"]} اجرای همان خدمت در بازهٔ پیوستهٔ {minutes:g} دقیقه‌ای؛ '
                            'مرز پنجره یا روز زنجیره را قطع نمی‌کند. مرجع، همان مدت و فقط نشست‌های دیگر در گذشته است.'})
        except Exception as exc:
            if getattr(exc,'sqlstate',None)!='57014':raise
            decisions.append({'finding_key':'pf1:'+digest([session,target,'continuous_rate',service,'retry']),
                'session_key':session,'target_ns':target,'family':'continuous_rate','dimension':'activity','service_path':service,
                'status':'INSUFFICIENT_DATA','reason':'CONTINUOUS_MODEL_READ_RETRY','operator_alert':False,
                'explanation_fa':'خواندن مدل پیوسته در این نوبت کامل نشد؛ ارزیابی دوباره در صف باقی می‌ماند.'})
    return decisions,inputs
