from .sql_budget import statement_budget
"""Read-only grouped review views; no case merges and no anomaly inference."""
import json
from urllib.parse import urlencode
from .review_policy import sql as review_sql
from .cases import LABELS
from .scenario_store import PROFILE_JOB_KINDS,PROFILE_VERSION

BUCKETS={'READY':'آمادهٔ بررسی','PENDING':'تمام مواردِ در انتظار بازبینی یا شاهد','EVIDENCE_PENDING':'نامزد تازه؛ تکمیل شاهد در جریان است','RECHECK':'در صف بازبینی','WATCH':'مشاهدهٔ آماری؛ پشتوانهٔ بیشتر لازم است',
 'HISTORY':'سابقه؛ الگو در ارزیابی بعدی دیده نشده','REVIEWED':'بررسی‌شده توسط اپراتور','EVIDENCE':'منتظر شاهد طبق نظر اپراتور'}


_PROFILE_KINDS_SQL="("+",".join("'"+kind+"'" for kind in PROFILE_JOB_KINDS)+")"
CURRENT_SIGNAL_SQL=(
    "CASE WHEN s.source_kind='feature' THEN fj.scope_key IS NOT NULL AND NOT fj.dirty AND fj.version=s.job_version "
    "AND (fj.kind NOT IN "+_PROFILE_KINDS_SQL+" OR COALESCE(fj.evaluation::jsonb->'input_receipt'->>'profile_version','')='"+PROFILE_VERSION+"') "
    "WHEN s.source_kind='actor' THEN j.session_key IS NOT NULL AND (CASE WHEN s.primary_version IS NOT NULL "
    "THEN j.primary_version=s.primary_version ELSE NOT j.dirty AND j.version=s.job_version END) "
    "ELSE p.start_ns IS NOT NULL AND NOT p.dirty AND p.version=s.job_version END"
)


def signals(where='TRUE'):
    return "WITH signal_inputs AS (SELECT s.*,"+CURRENT_SIGNAL_SQL+" AS current_input,COALESCE(j.evaluation::jsonb->'pending_families' ? s.family,FALSE) AS method_pending FROM anomaly_detection.adp_case_signals s LEFT JOIN anomaly_detection.adp_jobs j ON s.source_kind='actor' AND j.session_key=s.job_session AND j.target_ns=s.target_ns LEFT JOIN anomaly_detection.adp_population_jobs p ON s.source_kind='population' AND p.start_ns=s.target_ns LEFT JOIN anomaly_detection.adp_scenario_jobs fj ON s.source_kind='feature' AND fj.scope_key=s.scope_key WHERE "+where+"), "


def cte():
    # Aggregate once per case, rather than rescanning the complete signal CTE
    # for every case and every readiness predicate. Policy and ordering match22.
    grouped="signal_state AS (SELECT s.case_key,BOOL_OR(s.current_input) AS fresh,BOOL_OR(s.state<>'WITHDRAWN' AND (NOT s.current_input OR s.method_pending)) AS needs_recheck,COUNT(*) FILTER(WHERE s.state<>'WITHDRAWN' AND NOT s.current_input) AS stale_signals,BOOL_OR(s.current_input AND ("+review_sql()+")) AS can_review,BOOL_OR(s.current_input AND NOT s.qualified AND ("+review_sql(qualified=False)+")) AS evidence_pending FROM signal_inputs s GROUP BY s.case_key), "
    chosen="current_signals AS (SELECT DISTINCT ON (case_key) case_key,body::jsonb AS current_signal FROM signal_inputs WHERE current_input AND state='ACTIVE' ORDER BY case_key,review_eligible DESC,end_ns DESC,score DESC,signal_key), latest_feedback AS (SELECT DISTINCT ON (case_key,case_revision) case_key,case_revision,label FROM anomaly_detection.adp_case_feedback ORDER BY case_key,case_revision,id DESC), "
    assessed="assessed AS (SELECT c.case_key,c.entity_type,c.entity_key,c.issue_kind,c.service_path,c.state,c.revision,c.content_digest,c.first_ns,c.last_ns,c.updated_ns,c.body AS stored_body,COALESCE(s.fresh,FALSE) AS fresh,COALESCE(s.needs_recheck,FALSE) AS needs_recheck,COALESCE(s.stale_signals,0) AS stale_signals,COALESCE(s.can_review,FALSE) AS can_review,COALESCE(s.evidence_pending,FALSE) AS evidence_pending,p.current_signal,b.label AS review_label FROM anomaly_detection.adp_cases c LEFT JOIN signal_state s USING(case_key) LEFT JOIN current_signals p USING(case_key) LEFT JOIN latest_feedback b ON b.case_key=c.case_key AND b.case_revision=c.revision), "
    effective="effective AS (SELECT a.*,jsonb_set(stored_body::jsonb,'{strongest}',COALESCE(current_signal,stored_body::jsonb->'strongest'))::text AS body,CASE WHEN fresh AND review_label IN ('confirmed_suspicious','reviewed_benign') THEN 'REVIEWED' WHEN fresh AND review_label='needs_evidence' THEN 'EVIDENCE' WHEN can_review THEN 'READY' WHEN evidence_pending THEN 'EVIDENCE_PENDING' WHEN needs_recheck OR NOT fresh THEN 'RECHECK' WHEN state='WITHDRAWN' OR stored_body::jsonb->>'phase'='NO_CURRENT_SIGNAL' THEN 'HISTORY' ELSE 'WATCH' END AS bucket FROM assessed a) "
    return signals()+grouped+chosen+assessed+effective


def statistics(store):
    rows=store.raw.execute(cte()+"SELECT bucket,COUNT(*) AS cases,COUNT(DISTINCT service_path) AS services,COUNT(DISTINCT entity_key) FILTER(WHERE entity_type='actor') AS actors FROM effective GROUP BY bucket").fetchall()
    return {r['bucket']:dict(r) for r in rows}


def case_status(store,key):
    return store.raw.execute(cte()+'SELECT bucket,fresh,can_review,review_label,body,stale_signals,evidence_pending FROM effective WHERE case_key=%s',(key,)).fetchone()


def filters(args):
    view=args.get('view',['services'])[0]
    if view not in ('services','actors','cases'):raise ValueError('invalid review view')
    state=args.get('state',[''])[0]
    if state not in ('','OPEN','ALL','NEEDS_REVIEW','HOLD','WITHDRAWN'):raise ValueError('invalid case filter')
    bucket=args.get('bucket',[{'ALL':'ALL','HOLD':'WATCH','WITHDRAWN':'HISTORY'}.get(state,'READY')])[0]
    if bucket not in (*BUCKETS,'ALL'):raise ValueError('invalid readiness filter')
    entity=args.get('entity',['ALL'])[0]
    if entity not in ('ALL','actor','service','system'):raise ValueError('invalid entity filter')
    service=args.get('service',[''])[0].strip();actor=args.get('actor',[''])[0].strip()
    if len(service)>256 or len(actor)>64:raise ValueError('invalid exact filter')
    page=args.get('page',['0'])[0]
    if not page.isdigit() or len(page)>5 or int(page)>10000:raise ValueError('invalid page')
    conditions=[];params=[]
    if bucket=='PENDING':conditions.append("e.bucket IN ('RECHECK','EVIDENCE','EVIDENCE_PENDING')")
    elif bucket!='ALL':conditions.append('e.bucket=%s');params.append(bucket)
    if view=='actors':conditions.append("e.entity_type='actor'")
    if entity!='ALL':conditions.append('e.entity_type=%s');params.append(entity)
    if service:conditions.append('e.service_path=%s');params.append(service)
    if actor:conditions.append('e.entity_type=%s AND e.entity_key=%s');params.extend(('actor',actor))
    return view,bucket,int(page),' AND '.join(conditions) or 'TRUE',params


RATIO="CASE WHEN jsonb_typeof(e.body::jsonb->'strongest'->'observed')='number' AND COALESCE(e.body::jsonb->'strongest'->>'family','') IN ('peer_service_rate_5m','continuous_rate') THEN (e.body::jsonb->'strongest'->>'observed')::numeric/GREATEST(1,COALESCE((e.body::jsonb->'strongest'->>'upper')::numeric,(e.body::jsonb->'strongest'->>'reference_max')::numeric,1)) ELSE 1 END"
INDEPENDENT="CASE WHEN e.body::jsonb->'strongest'->>'review_basis'='QUALIFIED_INDEPENDENT_DIMENSIONS' THEN 2 ELSE 1 END"


def groups(store,view,condition,params,page,limit=25):
    group='e.entity_key' if view=='actors' else 'e.service_path'
    query=cte().rstrip()+', grouped AS (SELECT '+group+" AS group_key,COUNT(*) AS cases,COUNT(*) FILTER(WHERE e.bucket='READY') AS ready_cases,COUNT(DISTINCT issue_kind) AS issue_count,string_agg(DISTINCT issue_kind,',') AS issues,COUNT(DISTINCT service_path) AS service_count,MIN(first_ns) AS first_ns,MAX(last_ns) AS last_ns,MAX("+RATIO+') AS contrast,MAX('+INDEPENDENT+') AS independent,ARRAY_AGG(e.case_key) AS case_keys,(ARRAY_AGG(e.case_key ORDER BY e.can_review DESC,'+INDEPENDENT+' DESC,'+RATIO+" DESC,e.last_ns DESC,e.case_key))[1] AS lead_key FROM effective e WHERE "+condition+' GROUP BY '+group+') SELECT g.*,l.body AS lead_body FROM grouped g JOIN effective l ON l.case_key=g.lead_key ORDER BY independent DESC,contrast DESC,ready_cases DESC,g.last_ns DESC,group_key LIMIT %s OFFSET %s'
    rows=store.raw.execute(query,(*params,limit+1,page*limit)).fetchall()
    shown=rows[:limit];keys=sorted({k for r in shown for k in r['case_keys']})
    leads={r['group_key']:{'body':r['lead_body'],'case_key':r['lead_key']} for r in shown}
    if not keys:return rows,{},leads
    unknown={r['group_key']:{'executions':None,'sessions':None,'current_executions':None} for r in shown}
    # Optional counts must not discard an already-read, current issue list.
    if len(keys)>5000:
        store.summary_counts_unavailable=True
        return rows,unknown,leads
    metric_group='c.entity_key' if view=='actors' else 'c.service_path'
    try:
        with statement_budget(store.raw,500):
            metric=store.raw.execute(signals('s.case_key=ANY(%s)')+'counts AS (SELECT '+metric_group+" AS group_key,COUNT(DISTINCT r.request_key) AS executions,COUNT(DISTINCT r.session_key) AS sessions,COUNT(DISTINCT r.request_key) FILTER(WHERE s.current_input AND s.state='ACTIVE') AS current_executions FROM anomaly_detection.adp_case_requests r JOIN anomaly_detection.adp_cases c ON c.case_key=r.case_key JOIN signal_inputs s ON s.signal_key=r.signal_key WHERE r.case_key=ANY(%s) AND s.state<>'WITHDRAWN' GROUP BY "+metric_group+') SELECT * FROM counts',(keys,keys)).fetchall()
        metrics={r['group_key']:{'executions':0,'sessions':0,'current_executions':0} for r in shown}
        metrics.update({r['group_key']:dict(r) for r in metric})
    except Exception as exc:
        if getattr(exc,'sqlstate',None)!='57014':raise
        metrics=unknown
        store.summary_counts_unavailable=True
    return rows,metrics,leads


def explanation(body):
    value=body['strongest'];observed=value.get('observed');expected=value.get('expected');bound=value.get('upper',value.get('reference_max'))
    if value.get('family')=='input_subject_burst':
        return value['explanation_fa']
    if observed is None:return value.get('explanation_fa') or 'جزئیات معیار در پرونده موجود است.'
    duration=(value.get('duration_ns') or value.get('end_ns',0)-value.get('begin_ns',0))/60e9
    unit={'activity':'اجرا','service_population':'اجرا','service_health':'نتیجهٔ ناموفق','latency':'ثانیه','targets':'شناسهٔ نوع‌دار','repeat_target':'درخواست با همان موضوع','subject_enumeration':'شناسه یا موضوع متمایز','network':'IP متفاوت','workflow':'مرحلهٔ تغییرکرده','service_traversal':'خدمت متفاوت','response_schema':'تغییر ساختار پاسخ','response_content':'تغییر محتوای پاسخ','service_volume':'درخواست','service_coordination':'کاربر / نشست'}.get(body['issue_kind'],'مقدار معیار')
    out=f'{observed:g} {unit}'
    if value.get('family')=='service_volume':out=('کاهش فعالیت: ' if value.get('direction')=='decrease' else 'افزایش فعالیت: ' if value.get('direction')=='increase' else '')+out
    if duration>0:out+=f' در {duration:g} دقیقه'
    if expected is not None:out+=f'؛ مقدار مرجع {expected:g}'
    if body['issue_kind']=='service_population':
        if value.get('score') is not None:out+=f"؛ امتیاز تغییر جمعی {value['score']:g}"
        if bound is not None:out+=f'؛ کران امتیاز {bound:g}'
    elif body['issue_kind']=='service_health' and value.get('error_rate') is not None:
        out+=f"؛ نرخ خطا {value['error_rate']*100:g}٪"
        if bound is not None:out+=f'؛ حد نرخ خطای مرجع {bound*100:g}٪'
    elif bound is not None:out+=f'؛ کران مرجع {bound:g}'
    if value.get('observed_requests') is not None and body['issue_kind'] in ('subject_enumeration','network','repeat_target'):out+='؛ در '+str(value['observed_requests'])+' درخواست یکتا'
    if value.get('active_days') is not None:out+='؛ '+str(value['active_days'])+' روز فعال'
    if body['issue_kind']=='service_health' and value.get('supporting_failure_sessions') is not None:out+='؛ '+str(value['supporting_failure_sessions'])+' نشست دارای خطا'
    if body.get('phase')=='NO_CURRENT_SIGNAL':out='این الگو در ارزیابی بعدی دیده نشده؛ سابقه: '+out
    elif body.get('phase')=='RETURNED':out='الگو دوباره دیده شده؛ '+out
    return out


def cards(stats):
    from .product_web import text
    if stats is None:return '<p class="muted">شمار کل در حال به‌روزرسانی است؛ مقدار نامعلوم صفر نیست.</p>'
    ready=stats.get('READY',{});pending=sum(stats.get(b,{}).get('cases',0) for b in ('RECHECK','EVIDENCE','EVIDENCE_PENDING'))
    items=[('خدمت با مورد آمادهٔ بررسی',ready.get('services',0),'services','READY'),('کاربر / نشست آمادهٔ بررسی',ready.get('actors',0),'actors','READY'),
        ('در انتظار',pending,'services','PENDING'),('نیازمند پشتوانه',stats.get('WATCH',{}).get('cases',0),'services','WATCH')]
    return '<div class="grid">'+''.join('<a class="card" href="/incidents?'+text(urlencode({'view':v,'bucket':b}))+'"><div class="muted">'+text(label)+'</div><div class="number">'+text(n)+'</div></a>' for label,n,v,b in items)+'</div>'


def render(store,args,*,preview=False):
    from .product_web import text,when
    view,bucket,page,condition,params=filters(args)
    stats={}
    if not preview:
        try:
            with statement_budget(store.raw,200):
                stats=statistics(store)
        except Exception as exc:
            if getattr(exc,'sqlstate',None)!='57014':raise
            stats=None
    from .unified_review import progress
    body=progress(store)+('' if preview else cards(stats))
    if not preview:
        body+='<section><div class="review-tabs">'
        for key,label in (('services','مسائل مرتبط با خدمت‌ها'),('actors','کاربران دارای اولویت بررسی'),('cases','پرونده‌های ثبت‌شده')):
            body+='<a class="'+('selected' if key==view else '')+'" href="/incidents?'+text(urlencode({'view':key,'bucket':bucket}))+'">'+label+'</a>'
        body+='</div><form class="filters"><input type="hidden" name="view" value="'+view+'"><select name="bucket">'
        for key,label in [*BUCKETS.items(),('ALL','تمام وضعیت‌ها')]:body+='<option value="'+key+'"'+(' selected' if key==bucket else '')+'>'+text(label)+'</option>'
        body+='</select><select name="entity">'
        for key,label in (('ALL','تمام دامنه‌ها'),('actor','پروندهٔ کاربر / نشست'),('service','پروندهٔ جمعی خدمت'),('system','پروندهٔ کل سامانه')):
            body+='<option value="'+key+'"'+(' selected' if key==args.get('entity',['ALL'])[0] else '')+'>'+label+'</option>'
        body+='</select>'
        if args.get('actor'):body+='<input type="hidden" name="actor" value="'+text(args['actor'][0])+'">'
        body+='<input name="service" value="'+text(args.get('service',[''])[0])+'" placeholder="مسیر دقیق خدمت"><button>نمایش</button></form>'
        body+='<p class="muted">گروه‌بندی برای مرور است؛ پرونده‌ها، شاهدها و بازخورد هر کاربر جدا می‌مانند. اولویت بر اساس شاهد مستقل، عبور از کران همان مرجع و تازگی رخداد است.</p>'
        body+='<p class="muted">شمار اجرا و نشست با رفع هم‌پوشانیِ پرونده‌های همین گروه محاسبه می‌شود؛ نشست، دورهٔ ورود کاربر است.</p>'
    else:body+='<section><h2>مسائل آمادهٔ بررسی</h2>'
    if view=='cases':
        rows=store.raw.execute(cte()+'SELECT e.* FROM effective e WHERE '+condition+' ORDER BY '+INDEPENDENT+' DESC,'+RATIO+' DESC,e.last_ns DESC,e.case_key LIMIT 26 OFFSET %s',(*params,page*25)).fetchall()
        if rows:
            body+='<div class="scroll"><table><tr><th>مسئله و خدمت</th><th>کاربر / دامنه</th><th>دلیل و وضعیت</th><th>زمان رخداد</th><th>بررسی</th></tr>'
            for row in rows[:25]:
                value=json.loads(row['body']);who=row['entity_key'] if row['entity_type']=='actor' else 'کل سامانه' if row['entity_type']=='system' else 'جمعیت خدمت'
                body+='<tr><td>'+text(value['title_fa'])+'<br><small class="ltr">'+text(row['service_path'])+'</small></td><td class="identity">'+text(who)+'</td><td>'+text(explanation(value))+'<br><small>'+text(BUCKETS[row['bucket']])+'</small></td><td>'+text(when(row['last_ns']))+'</td><td><a href="/case/'+text(row['case_key'])+'">شواهد و تاریخچه</a></td></tr>'
            body+='</table></div>'
    else:
        limit=5 if preview else 25
        rows,metrics,leads=groups(store,view,condition,params,page,limit)
        if rows:
            body+='<div class="scroll"><table class="summary-table"><tr><th>'+('کاربر / نشست' if view=='actors' else 'خدمت')+'</th><th>موضوع‌ها</th><th>شواهد یکتا</th><th>مهم‌ترین مقایسه</th><th>آخرین رخداد / پیگیری</th></tr>'
            for row in rows[:limit]:
                key=row['group_key'];metric=metrics.get(key,{});lead=leads[key];value=json.loads(lead['body'])
                query={'view':'cases','bucket':bucket,('actor' if view=='actors' else 'service'):key}
                if args.get('entity'):query['entity']=args['entity'][0]
                issues='، '.join(LABELS.get(k,k) for k in row['issues'].split(','))
                body+='<tr><td class="identity"><span class="ltr">'+text(key)+'</span></td><td>'+text(issues)+'<br><small>'+text(row['cases'])+' پرونده'+(' در '+text(row['service_count'])+' خدمت' if view=='actors' else '')+'</small></td>'
                body+='<td>'+text(metric.get('executions'))+' اجرا در کل سابقه<br><small>'+text(metric.get('current_executions'))+' اجرا در معیارهای جاری</small><br>'+text(metric.get('sessions'))+' نشست</td><td>'+text(explanation(value))+('<small> — شاهد این مقایسه در حال تکمیل است</small>' if value['strongest'].get('evidence_verified') is not True else '')+'<details><summary>دلیل ثبت این نمونه</summary><p>'+text(value['strongest'].get('explanation_fa',''))+'</p><a href="/case/'+text(lead['case_key'])+'">شواهد همین پرونده</a></details></td>'
                body+='<td>'+text(when(row['last_ns']))+'<p><a class="button" href="/incidents?'+text(urlencode(query))+'">'+('مسئله‌های این کاربر' if view=='actors' else 'کاربران و پرونده‌های این خدمت')+'</a></p></td></tr>'
            body+='</table></div>'
    if getattr(store,'summary_counts_unavailable',False):body+='<p class="muted">شمار شواهدِ بعضی گروه‌ها هنوز آماده نیست و با — مشخص شده است؛ پرونده‌ها قابل بازکردن‌اند.</p>'
    if not rows:
        body+='<div class="empty">موردی در این وضعیت آماده نیست. موارد منتظر بازبینی و شاهد از فیلتر بالا قابل مشاهده‌اند؛ نبود مورد آماده، تأیید عادی بودن همهٔ رفتارها نیست.</div>'
    if preview:body+='<p><a href="/incidents">همهٔ مسائل خدمت‌ها</a> · <a href="/incidents?view=actors">کاربران دارای اولویت</a></p>'
    elif len(rows)>25:
        query={k:v[0] for k,v in args.items() if k not in ('after','page')};query['page']=page+1
        body+='<p><a class="button" href="/incidents?'+text(urlencode(query))+'">صفحهٔ بعد</a></p>'
    return body+'</section>'
