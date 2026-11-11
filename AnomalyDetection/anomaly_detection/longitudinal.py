"""Exact, bounded content cohorts over hours/days; never join people by IP.

The five-minute partition is a publication receipt, not an actor lifetime.
Reference actors have the same service, duration, volume band, active-day
band and typed field. Missing profiles exclude an entire reference actor.
Ranks are descriptive screens with a fixed family/horizon multiplicity;
they are not calibrated fraud probabilities.
"""
from collections import Counter,defaultdict
from datetime import datetime,timezone
from statistics import median
from zoneinfo import ZoneInfo
import json
from . import FIVE_NS
from .snapshot import digest,canonical

DAY=288*FIVE_NS
SPANS=(12*FIVE_NS,DAY,7*DAY,30*DAY)
MAX_ACTORS=2048
MAX_ROWS=50000
FAMILIES=('long_subject_enumeration','long_client_ip_rotation')


def day(at):
    return datetime.fromtimestamp(at//1_000_000_000,timezone.utc).astimezone(ZoneInfo('Asia/Tehran')).date().isoformat()


def spans(target,complete_windows):
    """Require every source partition, including reference's extra first one."""
    covered=set(complete_windows);first=target
    while first-FIVE_NS in covered and target-first<30*DAY:first-=FIVE_NS
    available=target-first if target in covered else 0
    result=[v for v in SPANS if v<=available]
    # A new installation need not wait a full week to examine three full days.
    if 2*DAY<=available<30*DAY and available not in result:result.append(available)
    return sorted(result)


def aggregate(rows):
    """One RequestID once. Typed fields stay in their endpoint namespace."""
    unique={r['request_key']:r for r in rows};rows=list(unique.values())
    groups=defaultdict(Counter);covered=Counter();ips=set();ip_covered=0;days=Counter()
    for r in rows:
        days[day(r['at_ns'])]+=1
        items=defaultdict(set)
        for token in r.get('subjects') or []:
            if token.get('key') and token.get('field') and token.get('channel'):
                items[(token['channel'],token['field'])].add(token['key'])
        for field,keys in items.items():covered[field]+=1;groups[field].update(keys)
        keys=set(r.get('ip_keys') or [])
        if keys:ip_covered+=1;ips.update(keys)
    return {'requests':len(rows),'active_days':len(days),'daily_counts':dict(sorted(days.items())),
        'groups':{k:{'distinct':len(v),'max_repeat':max(v.values(),default=0),'covered':covered[k]} for k,v in groups.items()},
        'ips':len(ips),'ip_covered':ip_covered,'qualified':bool(rows and all(r.get('qualified') for r in rows)),
        'request_keys':sorted(unique)}


def evaluate(actor,service,target,rows,covered_windows,*,bounded=True,reference_metrics=None,extra_durations=()):
    durations=spans(target,covered_windows)
    # Fixed upper bound, not reduced after looking at which tests passed.
    comparisons=2*(len(SPANS)+1)
    out=[]
    for duration in sorted(set(SPANS)|set(durations)|set(extra_durations)):
        begin=target+FIVE_NS-duration;end=target+FIVE_NS
        now=[r for r in rows if r['session_key']==actor and begin<=r['at_ns']<end]
        value=aggregate(now);references=defaultdict(list)
        for r in rows:
            if r['session_key']!=actor and target-duration<=r['at_ns']<target:
                references[r['session_key']].append(r)
        ref=(reference_metrics or {}).get(duration,[]) if reference_metrics is not None else [aggregate(v) for v in references.values() if all(r.get('reference_qualified',r.get('qualified')) and not r.get('training_quarantined') for r in v)]
        ref=[v for v in ref if v['qualified'] and max(1,value['requests']*.5)<=v['requests']<=max(1,value['requests']*2)
             and abs(v['active_days']-value['active_days'])<=1]
        base={'entity_type':'actor','entity_key':actor,'service_path':service,'begin_ns':begin,'end_ns':end,
            'duration_ns':duration,'request_keys':value['request_keys'],'observed_requests':value['requests'],
            'active_days':value['active_days'],'daily_counts':value['daily_counts'],'comparison_count':comparisons,
            'reference_cutoff_ns':target,'reference_selection':'OTHER_ACTORS_SAME_SERVICE_DURATION_VOLUME_ACTIVE_DAYS_TYPED_FIELD',
            'activation_rule_fa':'تمام پنجره‌ها و درخواست‌های بازه باید معتبر باشند؛ دست‌کم ۱۰۰ نشست مرجعِ همین خدمت با حجم بین نصف تا دو برابر و اختلاف حداکثر یک روز فعال لازم است. مقدار باید حداقل ۳، بیش از یک واحد بالاتر از بیشینهٔ مرجع و رتبهٔ دُم پس از تعدیل ۱۰ مقایسه حداکثر ۰٫۰۱ باشد. توان واقعی تفکیک این رتبه به تعداد مرجع وابسته است.',
            'identity_basis':'AUTHORITATIVE_SESSION_ONLY_NO_IP_OR_BILL_IDENTITY_JOIN',
            'evidence_verified':bool(bounded and duration<=max(durations,default=0) and value['qualified']),
            'single_signal_review_eligible':False,'calibration_status':'DESCRIPTIVE_SCREEN_NOT_PRODUCTION_ERROR_RATE_GUARANTEE',
            'count_scope':'canonical_meaningful_executions_exact_request_membership'}
        # Choose the field with the largest observed diversity. The fixed
        # correction additionally includes every typed field considered.
        typed=[(k,v) for k,v in value['groups'].items() if v['covered']==value['requests']]
        field,subject=max(typed,key=lambda kv:(kv[1]['distinct'],kv[0]),default=(None,None))
        # Compare the SAME maximum-over-fields statistic for each actor; do
        # not select a favorable current field and compare a different peer one.
        fieldset={k for k,_ in typed};correction=comparisons
        subject_refs=[v for v in ref if all(k in v['groups'] and v['groups'][k]['covered']==v['requests'] for k in fieldset)] if fieldset else []
        sv=[max(v['groups'][k]['distinct'] for k in fieldset) for v in subject_refs]
        ip_refs=[v for v in ref if v['ip_covered']==v['requests']];iv=[v['ips'] for v in ip_refs]
        subjects_ready=base['evidence_verified'] and field is not None and len(sv)>=100
        ips_ready=base['evidence_verified'] and value['ip_covered']==value['requests'] and len(iv)>=100
        so=subject['distinct'] if subject else None
        sr=min(1,(1+sum(x>=so for x in sv))/(len(sv)+1)*correction) if sv else None
        ir=min(1,(1+sum(x>=value['ips'] for x in iv))/(len(iv)+1)*comparisons) if iv else None
        unusual_subjects=bool(subjects_ready and so>=3 and so>max(sv)+1 and sr<=.01)
        unusual_ips=bool(ips_ready and value['ips']>=3 and value['ips']>max(iv)+1 and ir<=.01)
        for family,ready,observed,values,rank in (
            (FAMILIES[0],subjects_ready,so,sv,sr),(FAMILIES[1],ips_ready,value['ips'] if now else None,iv,ir)):
            d=dict(base,family=family,observed=observed,expected=median(values) if values else None,
                reference_max=max(values) if values else None,reference_actors=len(values),adjusted_tail_rank=rank,
                comparison_count=correction if family==FAMILIES[0] else comparisons,
                subject_field=list(field) if field else None,distinct_subjects=so,distinct_client_ips=value['ips'])
            candidate=unusual_subjects if family==FAMILIES[0] else unusual_ips
            d['status']='CANDIDATE' if candidate else 'NO_DEVIATION_OBSERVED' if ready else 'INSUFFICIENT_DATA'
            d['single_signal_review_eligible']=bool(candidate and (family==FAMILIES[0] or unusual_subjects))
            d['review_basis']='QUALIFIED_CONTENT_COHORT' if family==FAMILIES[0] else 'IP_CHANGE_WITH_CONTENT_CORROBORATION' if unusual_subjects else 'IP_CHANGE_ALONE_NOT_ABUSE'
            if not base['evidence_verified']:
                d['reason']='LONG_SPAN_COVERAGE_OR_CONTENT_INCOMPLETE'
                d['explanation_fa']='پوشش پیوستهٔ بازه یا محتوای تمام درخواست‌های نشست کامل نیست؛ نتیجهٔ عادی یا مشکوک صادر نمی‌شود.'
            elif not ready:
                d['reason']='COMPARABLE_CONTENT_REFERENCE_INSUFFICIENT'
                d['explanation_fa']='مرجع کافی با همین خدمت، مدت، حجم، روزهای فعال و نوع شناسه فراهم نشده است؛ این وضعیت عادی بودن نیست.'
            else:
                d['reason']='CUMULATIVE_CONTENT_DEVIATION' if candidate else 'CUMULATIVE_CRITERION_NOT_EXCEEDED'
                unit='شناسهٔ موضوع متمایز' if family==FAMILIES[0] else 'IP متمایزِ سمت مشتری'
                d['explanation_fa']=f"{observed} {unit} در {value['requests']} اجرای یکتا، {value['active_days']} روز فعال و {duration/60e9:g} دقیقه؛ مرجع {len(values)} نشست هم‌خدمت و هم‌مدت با حجم و روزهای فعال مشابه، بیشینهٔ {max(values)} دارد. رتبهٔ تعدیل‌شده {rank:.5g} است."
                if family==FAMILIES[1]:d['explanation_fa']+=' تغییر IP به‌تنهایی نشانهٔ سوءاستفاده نیست؛ اولویت مستقل نیازمند شاهد محتوایی نیز هست.'
                if observed is not None and observed>max(values)+1 and (d['comparison_count']/(len(values)+1))>.01:
                    d['status']='INSUFFICIENT_DATA';d['reason']='REFERENCE_TAIL_RESOLUTION_INSUFFICIENT'
                    d['explanation_fa']+=' با تعداد فعلیِ مرجع، رتبهٔ تعدیل‌شده هنوز توان تفکیک لازم را ندارد؛ نتیجهٔ عادی صادر نمی‌شود.'
            out.append(d)
    return out


def context(store,job):
    """Project small features in SQL; never load unbounded raw profile bodies."""
    from .request_profiles import VERSION
    target=job['target_ns'];service=job['service_path'];actor=job['entity_key']
    covered=[r['start_ns'] for r in store.raw.execute("SELECT start_ns FROM anomaly_detection.adp_source_windows WHERE complete=TRUE AND source::jsonb->>'peer_population_valid'='true' AND start_ns>=%s AND start_ns<=%s",(target-30*DAY,target)).fetchall()]
    durations=spans(target,covered)
    previous=json.loads(job.get('evaluation') or '{}')
    extra=[d['duration_ns'] for d in previous.get('decisions',[]) if d.get('duration_ns') and d['duration_ns']<=max(durations,default=0)]
    durations=sorted(set(durations)|set(extra))
    if not durations:return [],covered,True,{'coverage':'NO_COMPLETE_HORIZON','expected_current_requests':None},{}
    begin=target-max(durations);end=target+FIVE_NS
    # Identity/outcome-independent selection by HMAC Session key. Selection is
    # made from facts BEFORE checking whether a profile or label is available.
    peers=[r['session_key'] for r in store.raw.execute("SELECT DISTINCT f.session_key FROM anomaly_detection.adp_facts f WHERE f.service_path=%s AND f.at_ns>=%s AND f.at_ns<%s AND f.session_key<>%s AND f.eligible=TRUE AND f.source_present=TRUE AND f.state='active' ORDER BY f.session_key LIMIT %s",(service,begin,target,actor,MAX_ACTORS)).fetchall()]
    identities=[actor]
    records=store.raw.execute("""SELECT f.request_key,f.session_key,f.at_ns,
        p.body::jsonb->'subjects' AS subjects,p.body::jsonb->'ip_keys' AS ip_keys,
        (p.request_key IS NULL OR COALESCE(p.body::jsonb->>'qualified','false')<>'true'
          OR EXISTS(SELECT 1 FROM anomaly_detection.adp_profile_tasks t WHERE t.request_key=f.request_key)
          OR p.body::jsonb->>'version' IS DISTINCT FROM %s
          OR p.body::jsonb->>'semantic_revision' IS DISTINCT FROM f.revision::text
          OR p.body::jsonb->>'anchor_key' IS DISTINCT FROM f.anchor_key
          OR p.session_key IS DISTINCT FROM f.session_key OR p.service_path IS DISTINCT FROM f.service_path OR p.at_ns IS DISTINCT FROM f.at_ns) AS needs_refresh,
        COALESCE(p.body::jsonb->>'qualified'='true' AND p.body::jsonb->>'actor_qualified'='true'
          AND NOT EXISTS(SELECT 1 FROM anomaly_detection.adp_profile_tasks t WHERE t.request_key=f.request_key)
          AND p.body::jsonb->>'version'=%s
          AND p.body::jsonb->>'input_complete'='true' AND p.body::jsonb->>'semantic_active'='true'
          AND p.body::jsonb->>'semantic_revision'=f.revision::text AND p.body::jsonb->>'anchor_key'=f.anchor_key
          AND p.session_key=f.session_key AND p.service_path=f.service_path AND p.at_ns=f.at_ns
          AND EXISTS(SELECT 1 FROM anomaly_detection.adp_window_members m WHERE m.request_key=f.request_key AND m.start_ns=(f.at_ns/%s)*%s),FALSE) AS qualified,
        p.body::jsonb->>'ended_ns' AS ended_ns,
        (SELECT MAX((w->>'at_ns')::bigint) FROM jsonb_array_elements(COALESCE(p.body::jsonb->'witnesses','[]'::jsonb)) w) AS witness_end,
        EXISTS(SELECT 1 FROM anomaly_detection.adp_case_requests m JOIN anomaly_detection.adp_case_signals s USING(signal_key)
          WHERE m.request_key=f.request_key AND s.state='ACTIVE' AND s.qualified=TRUE AND s.review_eligible=TRUE
          AND COALESCE((SELECT b.label FROM anomaly_detection.adp_case_feedback b WHERE b.case_key=s.case_key AND b.created_ns>=p.observed_ns AND b.reviewed_end_ns>f.at_ns ORDER BY b.id DESC LIMIT 1),'unreviewed')<>'reviewed_benign') AS training_quarantined
        FROM anomaly_detection.adp_facts f LEFT JOIN anomaly_detection.adp_profiles p USING(request_key)
        WHERE f.service_path=%s AND f.at_ns>=%s AND f.at_ns<%s AND f.session_key=ANY(%s)
          AND f.eligible=TRUE AND f.source_present=TRUE AND f.state='active'
        ORDER BY (f.session_key=%s) DESC,f.session_key,f.at_ns,f.request_key LIMIT %s""",
        (VERSION,VERSION,FIVE_NS,FIVE_NS,service,begin,end,identities,actor,MAX_ROWS+1)).fetchall()
    bounded=len(records)<=MAX_ROWS
    rows=[];missing=[]
    for r in records[:MAX_ROWS]:
        r=dict(r)
        for field in ('subjects','ip_keys'):
            if isinstance(r[field],str):r[field]=json.loads(r[field])
            r[field]=r[field] or []
        if r.pop('needs_refresh'):
            r['qualified']=False;missing.append(r['request_key'])
        r['reference_qualified']=bool(r['qualified'] and r['ended_ns'] is not None and int(r['ended_ns'])<target and r['witness_end'] is not None and r['witness_end']<target)
        r.pop('training_quarantined',None) # never train this actor against itself
        rows.append(r)
    reference_metrics,reference_missing=reference(store,service,target,begin,peers,durations)
    from .scenario_store import queue_keys
    missing=sorted(set(missing+reference_missing))
    existing={r['request_key'] for r in store.raw.execute('SELECT request_key FROM anomaly_detection.adp_profile_tasks WHERE request_key=ANY(%s)',(missing,)).fetchall()} if missing else set()
    repairs=[k for k in missing if k not in existing][:512]
    queue_keys(store,repairs,priority=1,force=True)
    # A LIMIT is a work bound, never an implicit complete census. Preserve this
    # job as pending while a larger workload requires a different execution plan.
    receipt={'coverage':'COMPLETE' if bounded else 'WORK_BOUND_EXCEEDED','projected_requests':len(rows),
        'missing_or_stale_profiles_at_least':len(missing),'queued_profile_repairs':len(repairs),
        'selected_reference_actors':len(peers),'complete_horizons_ns':durations,'row_limit':MAX_ROWS,
        'expected_current_requests':sum(r['session_key']==actor and target<=r['at_ns']<end for r in rows),
        'qualified_current_profiles':sum(r['session_key']==actor and target<=r['at_ns']<end and r['qualified'] for r in rows),
        'input_digest':digest(rows),'reference_metrics_digest':digest({str(k):[dict(v,groups={canonical(ns):g for ns,g in v['groups'].items()}) for v in values] for k,values in reference_metrics.items()}),
        'identity_limit':'NO_VERIFIED_CROSS_SESSION_PRINCIPAL'}
    return rows,covered,bounded,receipt,reference_metrics


def reference(store,service,target,begin,peers,durations):
    """Exact SQL aggregates: reference request bodies never enter Python.

    A busy thirty-day service may contain hundreds of thousands of requests;
    transfer is bounded by actors × horizons × typed fields, not request count.
    SQL timeout leaves the job pending rather than silently clipping a cohort.
    """
    if not peers:return {},[]
    from .request_profiles import VERSION
    from .snapshot import canonical
    records=store.raw.execute("""WITH facts AS MATERIALIZED (
        SELECT f.request_key,f.session_key,f.at_ns,p.body::jsonb AS body,
          COALESCE(p.body::jsonb->>'qualified'='true' AND p.body::jsonb->>'actor_qualified'='true'
            AND NOT EXISTS(SELECT 1 FROM anomaly_detection.adp_profile_tasks t WHERE t.request_key=f.request_key)
            AND p.body::jsonb->>'version'=%s
            AND p.body::jsonb->>'input_complete'='true' AND p.body::jsonb->>'semantic_active'='true'
            AND p.body::jsonb->>'semantic_revision'=f.revision::text AND p.body::jsonb->>'anchor_key'=f.anchor_key
            AND p.session_key=f.session_key AND p.service_path=f.service_path AND p.at_ns=f.at_ns
            AND (p.body::jsonb->>'ended_ns')::bigint<%s
            AND (SELECT MAX((w->>'at_ns')::bigint) FROM jsonb_array_elements(COALESCE(p.body::jsonb->'witnesses','[]'::jsonb)) w)<%s
            AND EXISTS(SELECT 1 FROM anomaly_detection.adp_window_members m WHERE m.request_key=f.request_key AND m.start_ns=(f.at_ns/%s)*%s)
            AND NOT EXISTS(SELECT 1 FROM anomaly_detection.adp_case_requests m JOIN anomaly_detection.adp_case_signals s USING(signal_key)
              WHERE m.request_key=f.request_key AND s.state='ACTIVE' AND s.qualified=TRUE AND s.review_eligible=TRUE
              AND COALESCE((SELECT b.label FROM anomaly_detection.adp_case_feedback b WHERE b.case_key=s.case_key AND b.created_ns>=p.observed_ns AND b.reviewed_end_ns>f.at_ns ORDER BY b.id DESC LIMIT 1),'unreviewed')<>'reviewed_benign'),FALSE) AS qualified,
          (p.request_key IS NULL OR COALESCE(p.body::jsonb->>'qualified','false')<>'true'
            OR EXISTS(SELECT 1 FROM anomaly_detection.adp_profile_tasks t WHERE t.request_key=f.request_key)
            OR p.body::jsonb->>'version' IS DISTINCT FROM %s
            OR p.body::jsonb->>'semantic_revision' IS DISTINCT FROM f.revision::text
            OR p.body::jsonb->>'anchor_key' IS DISTINCT FROM f.anchor_key
            OR p.session_key IS DISTINCT FROM f.session_key OR p.service_path IS DISTINCT FROM f.service_path OR p.at_ns IS DISTINCT FROM f.at_ns) AS needs_refresh
        FROM anomaly_detection.adp_facts f LEFT JOIN anomaly_detection.adp_profiles p USING(request_key)
        WHERE f.service_path=%s AND f.at_ns>=%s AND f.at_ns<%s AND f.session_key=ANY(%s)
          AND f.eligible=TRUE AND f.source_present=TRUE AND f.state='active'),
      expanded AS MATERIALIZED (SELECT h.duration,f.* FROM jsonb_to_recordset(%s::jsonb) AS h(duration BIGINT) JOIN facts f ON f.at_ns>=%s-h.duration),
      base AS (SELECT duration,session_key,COUNT(*) AS requests,BOOL_AND(qualified) AS qualified,
        COUNT(DISTINCT timezone('Asia/Tehran',to_timestamp(at_ns/1000000000))::date) AS active_days,
        MIN(request_key) FILTER(WHERE needs_refresh) AS missing FROM expanded GROUP BY duration,session_key),
      field_counts AS (SELECT e.duration,e.session_key,x->>'channel' AS channel,x->>'field' AS field,
        COUNT(DISTINCT x->>'key') AS distinct_values,COUNT(DISTINCT e.request_key) AS covered
        FROM expanded e CROSS JOIN LATERAL jsonb_array_elements(COALESCE(e.body->'subjects','[]'::jsonb)) x
        WHERE x->>'key' IS NOT NULL AND x->>'channel' IS NOT NULL AND x->>'field' IS NOT NULL
        GROUP BY e.duration,e.session_key,x->>'channel',x->>'field'),
      subjects AS (SELECT duration,session_key,jsonb_agg(jsonb_build_object('channel',channel,'field',field,'distinct',distinct_values,'covered',covered)) AS groups FROM field_counts GROUP BY duration,session_key),
      ips AS (SELECT e.duration,e.session_key,COUNT(DISTINCT x.value) AS ips,COUNT(DISTINCT e.request_key) AS covered
        FROM expanded e CROSS JOIN LATERAL jsonb_array_elements_text(COALESCE(e.body->'ip_keys','[]'::jsonb)) x GROUP BY e.duration,e.session_key)
      SELECT b.*,s.groups,COALESCE(i.ips,0) AS ips,COALESCE(i.covered,0) AS ip_covered FROM base b
      LEFT JOIN subjects s USING(duration,session_key) LEFT JOIN ips i USING(duration,session_key)
      ORDER BY b.duration,b.session_key""",(VERSION,target,target,FIVE_NS,FIVE_NS,VERSION,service,begin,target,peers,canonical([{'duration':v} for v in durations]),target)).fetchall()
    result=defaultdict(list);missing=[]
    for row in records:
        groups=row['groups'] or []
        if isinstance(groups,str):groups=json.loads(groups)
        result[row['duration']].append({'requests':row['requests'],'active_days':row['active_days'],'qualified':bool(row['qualified'] and not row['missing']),
            'groups':{(g['channel'],g['field']):{'distinct':g['distinct'],'covered':g['covered']} for g in groups},
            'ips':row['ips'],'ip_covered':row['ip_covered']})
        if row['missing']:missing.append(row['missing'])
    return dict(result),sorted(set(missing))


def seed(store,limit=8):
    """Finite old/new keyset passes include singleton and low-rate actors."""
    from .scenario_store import enqueue
    state=store.state('longitudinal_seed_v2')
    turn=state.get('turn',0);fresh=turn%4!=0
    lane='fresh' if fresh else 'old';cursor=state.get(lane,{})
    if not cursor.get('through'):
        high=store.raw.execute('SELECT MAX(start_ns) AS at FROM anomaly_detection.adp_source_windows WHERE complete=TRUE').fetchone()['at']
        if high is None:return
        low=max(0,high-2*DAY) if fresh else 0
        cursor={'through':high,'after':[low,'','']}
    after=cursor['after']
    # Fence the parent page BEFORE JSON expansion or qualification. A page
    # with no qualifying actor must advance, rather than re-scan all history.
    parent_limit=64
    relation='>' if after[2]=='\uffff' else '>='
    parents=store.raw.execute("SELECT w.start_ns,w.session_key,w.body,"
        "EXISTS(SELECT 1 FROM anomaly_detection.adp_source_windows p WHERE p.start_ns=w.start_ns AND p.complete=TRUE) AS source_complete "
        "FROM (SELECT start_ns,session_key,body FROM anomaly_detection.adp_windows "
        "WHERE (start_ns,session_key)"+relation+"(%s,%s) AND start_ns<=%s "
        "ORDER BY start_ns,session_key LIMIT %s) w ORDER BY w.start_ns,w.session_key",
        (after[0],after[1],cursor['through'],parent_limit)).fetchall()
    emitted=0;all_consumed=True
    for parent in parents:
        body=json.loads(parent['body']) if isinstance(parent['body'],str) else parent['body']
        prefix=[parent['start_ns'],parent['session_key']]
        counts=body.get('counts') if isinstance(body.get('counts'),dict) else {}
        coverage=body.get('coverage_complete')
        population=body.get('population_complete')
        if parent['source_complete'] and (coverage is True or coverage=='true') and (population is None or population is True or population=='true'):
            for service,value in sorted(counts.items()):
                if (prefix==after[:2] and service<=after[2]) or service=='Services.v1/InvoiceRegister':continue
                count=int(str(value))
                if not -(2**63)<=count<2**63:raise ValueError('invalid_summary_count')
                if count<=0:continue
                enqueue(store,'longitudinal',parent['session_key'],service,parent['start_ns'],invalidate=False)
                emitted+=1;cursor['after']=[*prefix,service]
                if emitted>=limit:all_consumed=False;break
        if not all_consumed:break
        cursor['after']=[*prefix,'\uffff']
    if all_consumed and len(parents)<parent_limit:
        high=cursor['through'];cursor={'after':[high,'\uffff','\uffff'],'through':high}
        next_high=store.raw.execute('SELECT MAX(start_ns) AS at FROM anomaly_detection.adp_source_windows WHERE complete=TRUE').fetchone()['at']
        if next_high is not None:cursor['through']=next_high
    state.update({lane:cursor,'turn':turn+1,'enqueued':state.get('enqueued',0)+emitted,'last_parent_rows':len(parents)})
    store.save_state('longitudinal_seed_v2',state)


def coverage_changed(store,target):
    """Both invalidation and completion of a source receipt affect long jobs."""
    from .scenario_store import invalidatable,record_queue_write
    cursor=store.raw.execute("UPDATE anomaly_detection.adp_scenario_jobs SET version=version+1,dirty=TRUE,due_ns=0 WHERE "+invalidatable()+" AND kind='longitudinal' AND target_ns>=%s AND target_ns<=%s",(target,target+30*DAY))
    record_queue_write(store,'coverage_change',cursor)


def publish(store,target,summaries):
    """New and late-completed windows enqueue every actor, even one request."""
    from .scenario_store import scope_key
    jobs=[{'scope':scope_key('longitudinal',r['session_key'],service,target),'actor':r['session_key'],'service':service,'target':target}
        for r in summaries if r['body'].get('coverage_complete') for service in r['body'].get('counts') or {}]
    if jobs:store.raw.execute("INSERT INTO anomaly_detection.adp_scenario_jobs(scope_key,kind,entity_key,service_path,target_ns) SELECT x.scope,'longitudinal',x.actor,x.service,x.target FROM jsonb_to_recordset(%s::jsonb) AS x(scope TEXT,actor TEXT,service TEXT,target BIGINT) ON CONFLICT(scope_key) DO NOTHING",(canonical(jobs),))


def upgrade_profiles(store):
    """Small automatic backfill, case evidence first, honoring retry backoff."""
    from .request_profiles import VERSION
    from .scenario_store import PROFILE_JOB_KINDS,queue_keys
    rows=store.raw.execute("SELECT DISTINCT p.request_key FROM anomaly_detection.adp_profiles p JOIN anomaly_detection.adp_case_requests m USING(request_key) WHERE COALESCE(p.body::jsonb->>'version','')<>%s AND NOT EXISTS(SELECT 1 FROM anomaly_detection.adp_profile_tasks t WHERE t.request_key=p.request_key) ORDER BY p.request_key LIMIT 16",(VERSION,)).fetchall()
    rows+=store.raw.execute("SELECT p.request_key FROM anomaly_detection.adp_profiles p WHERE COALESCE(p.body::jsonb->>'version','')<>%s AND NOT EXISTS(SELECT 1 FROM anomaly_detection.adp_profile_tasks t WHERE t.request_key=p.request_key) ORDER BY p.at_ns DESC,p.request_key LIMIT 16",(VERSION,)).fetchall()
    queue_keys(store,[r['request_key'] for r in rows],priority=1,force=True)
    # Existing case jobs can otherwise look current until their first member
    # happens to be refreshed. Work on a bounded set of materialized cases.
    store.raw.execute("WITH affected AS (SELECT DISTINCT j.scope_key FROM anomaly_detection.adp_case_signals s "
        "JOIN anomaly_detection.adp_scenario_jobs j USING(scope_key) WHERE s.source_kind='feature' "
        "AND s.state<>'WITHDRAWN' AND NOT j.dirty AND j.kind=ANY(%s) "
        "AND j.evaluation::jsonb->'input_receipt'->>'profile_version' IS DISTINCT FROM %s "
        "ORDER BY j.scope_key LIMIT 8) UPDATE anomaly_detection.adp_scenario_jobs j "
        "SET dirty=TRUE,version=version+1,due_ns=0 FROM affected a WHERE j.scope_key=a.scope_key AND NOT j.dirty",
        (list(PROFILE_JOB_KINDS),VERSION))
