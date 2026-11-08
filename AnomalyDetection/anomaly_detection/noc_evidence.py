"""One case, one operational dossier: reason, content, IPs, days and witnesses.

All reads use owned tables. No web GET reads raw payloads or enqueues work.
Incomplete profile projection is unknown, never zero distinct bills or IPs.
"""
from collections import defaultdict,Counter
from urllib.parse import urlencode
import json,re
from .longitudinal import day,DAY
from .sql_budget import statement_budget

MAX_REQUESTS=5000
PAGE_SIZE=25


def aggregate(rows):
    unique={r['request_key']:r for r in rows};tokens={};fields=defaultdict(set);coverage=Counter();ips={};days={};qualified=0;with_ips=0
    for r in unique.values():
        d=days.setdefault(day(r['at_ns']),{'requests':0,'qualified':0,'sessions':set(),'ips':set()})
        d['requests']+=1
        if r.get('session_key'):d['sessions'].add(r['session_key'])
        if not r.get('qualified'):continue
        qualified+=1;d['qualified']+=1;seen=set()
        for t in r.get('subjects') or []:
            if not all(t.get(k) for k in ('key','field','channel')):continue
            namespace=(t['channel'],t['field']);fields[namespace].add(t['key'])
            item=tokens.setdefault((namespace,t['key']),{'channel':namespace[0],'field':namespace[1],'key':t['key'],'display':t.get('display'),
                'requests':set(),'sessions':set(),'ips':set(),'first_ns':r['at_ns'],'last_ns':r['at_ns'],'witness':r['request_key']})
            item['requests'].add(r['request_key']);item['sessions'].add(r.get('session_key'));item['ips'].update(r.get('ip_keys') or [])
            item['first_ns']=min(item['first_ns'],r['at_ns']);item['last_ns']=max(item['last_ns'],r['at_ns'])
            if item['display'] is None and t.get('display'):item['display']=t['display']
            seen.add(namespace)
        coverage.update(seen)
        ipkeys=set(r.get('ip_keys') or [])
        if ipkeys:with_ips+=1
        for ip in ipkeys:
            item=ips.setdefault(ip,{'key':ip,'display':(r.get('ip_display') or {}).get(ip),'requests':set(),'sessions':set(),'first_ns':r['at_ns'],'last_ns':r['at_ns'],'witness':r['request_key']})
            item['requests'].add(r['request_key']);item['sessions'].add(r.get('session_key'));d['ips'].add(ip)
            item['first_ns']=min(item['first_ns'],r['at_ns']);item['last_ns']=max(item['last_ns'],r['at_ns'])
            if item['display'] is None:item['display']=(r.get('ip_display') or {}).get(ip)
    return {'requests':len(unique),'qualified':qualified,'unknown_profiles':len(unique)-qualified,'fields':fields,'field_coverage':coverage,
        'tokens':sorted(tokens.values(),key=lambda v:(-len(v['requests']),v['field'],v['key'])),'ips':sorted(ips.values(),key=lambda v:(-len(v['requests']),v['key'])),
        'ip_covered_requests':with_ips,'days':dict(sorted(days.items()))}


def read(store,key):
    members="WITH members AS (SELECT r.request_key,MIN(r.at_ns) AS at_ns,MIN(r.session_key) AS session_key FROM anomaly_detection.adp_case_requests r JOIN anomaly_detection.adp_case_signals s USING(signal_key) WHERE r.case_key=%s AND s.state<>'WITHDRAWN' GROUP BY r.request_key) "
    total=store.raw.execute(members+'SELECT COUNT(*) AS n FROM members',(key,)).fetchone()['n']
    records=store.raw.execute(members+"""SELECT m.request_key,m.at_ns,m.session_key,
        p.body::jsonb->'subjects' AS subjects,p.body::jsonb->'ip_keys' AS ip_keys,p.body::jsonb->'ip_display' AS ip_display,
        p.body::jsonb->'result' AS result,
        COALESCE(p.body::jsonb->>'qualified'='true' AND p.body::jsonb->>'input_complete'='true'
            AND p.at_ns=m.at_ns AND p.session_key IS NOT DISTINCT FROM m.session_key
            AND ((f.request_key IS NULL AND p.body::jsonb->>'semantic_active'='false') OR
              (f.source_present=TRUE AND f.state='active' AND f.eligible=TRUE AND p.body::jsonb->>'semantic_revision'=f.revision::text
               AND p.body::jsonb->>'anchor_key'=f.anchor_key AND p.service_path=f.service_path)),FALSE) AS qualified
        FROM members m LEFT JOIN anomaly_detection.adp_profiles p USING(request_key)
        LEFT JOIN anomaly_detection.adp_facts f USING(request_key)
        ORDER BY m.at_ns DESC,m.request_key LIMIT %s""",(key,MAX_REQUESTS+1)).fetchall()
    rows=[]
    for r in records[:MAX_REQUESTS]:
        r=dict(r)
        for field in ('subjects','ip_keys','ip_display','result'):
            if isinstance(r[field],str):r[field]=json.loads(r[field])
        rows.append(r)
    return rows,total,len(records)<=MAX_REQUESTS


def reason(value,*,fresh=True):
    from .product_web import text,when,FAMILIES
    family=value.get('family');direction=value.get('direction')
    title='کاهش فعالیت خدمت' if family=='service_volume' and direction=='decrease' else 'افزایش فعالیت خدمت' if family=='service_volume' and direction=='increase' else FAMILIES.get(family,family)
    entries=[('روش',title),('چرا این مورد ثبت شده',value.get('explanation_fa') or value.get('reason')),
        ('بازهٔ دقیق تهران',when(value.get('begin_ns'))+' تا '+when(value.get('end_ns'))),
        ('ورودی جاری', 'ارزیابی شده' if fresh else 'تغییر کرده؛ بازبینی لازم است'),
        ('شاهدِ همین معیار','تأیید شده' if value.get('evidence_verified') is True else 'کامل یا تأییدشده نیست'),
        ('اولویت مستقل بررسی','شرایط لازم برقرار است' if value.get('single_signal_review_eligible') is True else 'هنوز پشتوانهٔ کافی ندارد')]
    for key,label in (('observed','مقدار مشاهده‌شده'),('observed_requests','درخواست‌های یکتای بررسی‌شده'),('expected','مقدار مرجع'),
        ('lower','کران پایین مرجع'),('upper','کران بالای مرجع'),('reference_max','بیشینهٔ مرجع'),('active_days','روزهای فعال نشست'),
        ('reference_actors','نشست‌های مرجع قابل مقایسه'),('supporting_failure_sessions','نشست‌های دارای نتیجهٔ ناموفق'),
        ('reference_actor_units','واحدهای نشست مرجع'),('reference_requests','درخواست‌های مرجع'),('reference_windows','بازه‌های مرجع'),
        ('current_result_requests','درخواست‌های دارای نتیجهٔ صریح'),('observed_failure_share','سهم خطای جاری؛ نسبت بین صفر و یک'),
        ('reference_failure_share','سهم خطای مرجع؛ نسبت بین صفر و یک'),
        ('comparison_count','تعداد مقایسه‌های تعدیل‌شده'),('adjusted_tail_rank','رتبهٔ دُم تعدیل‌شده'),('reference_cutoff_ns','پایان دادهٔ مرجع')):
        if value.get(key) is not None:
            if key=='upper' and family=='service_health' and value.get('error_rate') is not None:entries.append(('حد نرخ خطای مرجع',str(round(value[key]*100,2))+'٪'))
            elif key=='upper' and family=='service_population':entries.append(('کران امتیاز تغییر جمعی',value[key]))
            else:entries.append((label,when(value[key]) if key.endswith('_ns') else value[key]))
    if family=='service_population' and value.get('score') is not None:entries.append(('امتیاز تغییر جمعی',value['score']))
    if value.get('error_rate') is not None:entries.append(('نرخ خطای مشاهده‌شده',str(round(value['error_rate']*100,2))+'٪'))
    if value.get('repeated_subject_basis'):entries.append(('مبنای موضوع تکرارشده','شناسهٔ اصلی قبض در خدمت و فیلد یکسان' if value['repeated_subject_basis']=='typed_bill' else 'اثر انگشت ورودی کسب‌وکار'))
    scopes={'canonical_meaningful_executions':'اجراهای معنادارِ منتشرشده توسط Viewer',
        'canonical_meaningful_executions_exact_request_membership':'اجراهای معنادار Viewer با عضویت دقیق RequestID',
        'complete_root_client_request_census':'درخواست‌های منطقی API، شامل API فنی؛ شمارش اقدام دستی نیست',
        'independent_request_sample_no_user_identity_inferred':'نمونهٔ مستقل درخواست‌ها؛ هویت کاربر استنتاج نمی‌شود'}
    if value.get('count_scope'):entries.append(('دامنهٔ شمارش',scopes.get(value['count_scope'],value['count_scope'])))
    state='در صف بازبینی ورودی تازه' if not fresh else 'شاهد تأییدشده' if value.get('evidence_verified') is True else 'شاهد ناکامل'
    html='<section><h3>چرا فعال شده و چقدر قابل اتکاست؟</h3><p><strong>'+text(title)+'</strong> · <span class="badge">'+text(state)+'</span></p><p>'+text(value.get('explanation_fa') or value.get('reason'))+'</p>'
    html+='<p>مشاهده: <strong>'+text(value.get('observed'))+'</strong> · مرجع: <strong>'+text(value.get('expected'))+'</strong> · '+text(when(value.get('begin_ns')))+' تا '+text(when(value.get('end_ns')))+'</p>'
    if value.get('activation_rule_fa'):html+='<p><strong>شرط فعال‌شدن:</strong> '+text(value['activation_rule_fa'])+'</p>'
    html+='<details><summary>روش، شرط فعال‌شدن و جزئیات مرجع</summary><table>'+''.join('<tr><th>'+text(k)+'</th><td>'+text(v)+'</td></tr>' for k,v in entries)+'</table></details>'
    if family=='service_health':html+='<p>این معیار افزایش خطای صریحِ گزارش‌شده را یافته است. علت اختلال و قطعی قطعیِ سرویس‌دهنده از این شواهد به‌تنهایی مشخص نیست. درخواست مجدد و بازگشت خطاها، تاریخچهٔ همین پرونده را تکمیل می‌کند.</p>'
    if family=='service_volume':html+='<p>کاهش درخواست با قطعی یکسان نیست. صفر فقط با پوشش کامل منبع قابل استفاده است؛ کمبود داده باعث وضعیت نامعلوم می‌شود.</p>'
    return html+'<p class="muted">رتبهٔ آماری، احتمال تقلب یا درصد اطمینان نیست. تأیید کارایی عملیاتی به آزمون دادهٔ واقعی وابسته است.</p></section>'


def related(store,case,tokens):
    """Shared subject evidence is a relation, not a cross-session identity."""
    if case['entity_type']!='actor' or not tokens:return ''
    from .product_web import text,when
    keys=sorted({t['key'] for t in tokens})[:32]
    try:
        with statement_budget(store.raw,500):
            rows=store.raw.execute("""SELECT p.session_key,x->>'key' AS topic,COUNT(DISTINCT p.request_key) AS requests,
              MIN(p.at_ns) AS first_ns,MAX(p.at_ns) AS last_ns,MIN(p.request_key) AS witness
              FROM anomaly_detection.adp_profiles p JOIN anomaly_detection.adp_facts f USING(request_key)
              CROSS JOIN LATERAL jsonb_array_elements(COALESCE(p.body::jsonb->'subjects','[]'::jsonb)) x
              WHERE p.service_path=%s AND p.at_ns>=%s AND p.at_ns<%s AND p.session_key<>%s
                AND x->>'key'=ANY(%s) AND p.body::jsonb->>'qualified'='true' AND p.body::jsonb->>'actor_qualified'='true'
                AND p.body::jsonb->>'input_complete'='true' AND p.body::jsonb->>'semantic_revision'=f.revision::text
                AND p.body::jsonb->>'anchor_key'=f.anchor_key AND f.source_present=TRUE AND f.state='active' AND f.eligible=TRUE
              GROUP BY p.session_key,x->>'key' ORDER BY last_ns DESC,p.session_key,topic LIMIT 51""",
              (case['service_path'],max(0,case['first_ns']-30*DAY),case['last_ns'],case['entity_key'],keys)).fetchall()
    except Exception as exc:
        if getattr(exc,'sqlstate',None)!='57014':raise
        return '<p>خواندن ارتباطِ شناسه‌ها با نشست‌های دیگر در این نوبت کامل نشد؛ نبود ارتباط نتیجه نمی‌شود.</p>'
    html='<details><summary>همین موضوع‌ها در نشست‌های دیگر</summary><p>این ارتباط در پروفایل‌های خوانده‌شدهٔ همین خدمت، از ۳۰ روز پیش از پرونده تا آخرین شاهد آن جست‌وجو شده است؛ همهٔ لاگ‌های منبع یا همهٔ نشست‌ها نیست. موضوع یا قبض مشترک، اثبات یک نفر بودن نشست‌ها یا تبانی نیست.</p>'
    if len({t['key'] for t in tokens})>32:html+='<p>جست‌وجوی ارتباط فقط روی ۳۲ شناسهٔ اول بر اساس کلید پایدار انجام شده است.</p>'
    if not rows:return html+'<p>در این محدوده و پروفایل‌های معتبر خوانده‌شده، ارتباطی ثبت نشده است؛ نبودن رابطه در کل سامانه اثبات نمی‌شود.</p></details>'
    html+='<table><tr><th>شناسه / نشست دیگر</th><th>درخواست</th><th>از / تا</th><th>مدرک</th></tr>'
    for r in rows[:50]:html+='<tr><td class="ltr">'+text(r['topic'][:12])+'<br><a href="http://127.0.0.1:5021/session/'+text(r['session_key'])+'/behavior">'+text(r['session_key'][:16])+' ↗</a></td><td>'+text(r['requests'])+'</td><td>'+text(when(r['first_ns']))+'<br>'+text(when(r['last_ns']))+'</td><td><a href="http://127.0.0.1:5021/request/'+text(r['witness'])+'">لاگ شاهد ↗</a></td></tr>'
    if len(rows)>50:html+='<tr><td colspan="4">۵۰ ارتباط اخیر نمایش داده شده؛ فهرست کامل نیست.</td></tr>'
    return html+'</table></details>'


def render(store,key,args,*,case=None):
    from .product_web import text,when
    p=args.get('evidence_page',['0'])[0];topic=args.get('topic',[''])[0];ip=args.get('ip',[''])[0]
    if not p.isdigit() or len(p)>4 or int(p)>1000:raise ValueError('invalid evidence page')
    if topic and not re.fullmatch('[0-9a-f]{64}',topic):raise ValueError('invalid topic')
    if ip and not re.fullmatch('[0-9a-f]{64}',ip):raise ValueError('invalid ip')
    page=int(p)
    try:
        with statement_budget(store.raw,900):rows,total,complete=read(store,key)
    except Exception as exc:
        if getattr(exc,'sqlstate',None)!='57014':raise
        return '<section><h3>جزئیات محتوا و IP</h3><p>جزئیات در زمان این خواندن آماده نشد؛ تعداد قبض یا IP نامعلوم است. پرونده و دلیل ثبت‌شده در دسترس‌اند.</p></section>'
    a=aggregate(rows)
    def link(request,label='لاگ و مراحل در Viewer ↗'):
        return '<a href="http://127.0.0.1:5021/request/'+text(request)+'">'+text(label)+'</a>'
    def filter_link(**extra):return '/case/'+key+'?'+urlencode(extra)+'#request-evidence'
    html='<section><h3>محتوا، قبض‌ها و IPهای همین پرونده</h3>'
    html+='<p>کل درخواست‌های مرتبطِ یکتا: <strong>'+text(total)+'</strong>؛ پروفایل محتوایی معتبرِ خوانده‌شده: <strong>'+text(a['qualified'])+'</strong>؛ محتوای نامعلوم یا قدیمی در این خواندن: <strong>'+text(a['unknown_profiles'])+'</strong>.</p>'
    if not complete:html+='<div class="notice">این بخش حداکثر ۵۰۰۰ درخواست اخیر را خوانده است. همهٔ اعداد محتوا، IP و روزها در زیر فقط مربوط به این زیرمجموعه‌اند؛ جمع کل پرونده نیستند.</div>'
    html+='<p class="muted">محدوده: عضویت درخواست‌های معیارهای بازپس‌گرفته‌نشدهٔ پرونده، شامل تاریخچه. شمارش هر RequestID یک بار است. خواندن این صفحه چیزی را آموزش نمی‌دهد و ارزیابی تازه ایجاد نمی‌کند.</p>'
    html+='<h3>یک قبض یا چند قبض؟</h3>'
    if not a['fields']:html+='<p>شناسهٔ نوع‌دار قابل اتکا در پروفایل‌های این خواندن موجود نیست؛ تعداد قبض نامعلوم است. لینک شاهد، محتوای ثبت‌شده را در Viewer باز می‌کند.</p>'
    else:
        html+='<table><tr><th>خدمت / فیلد اصلی</th><th>شناسهٔ متمایز</th><th>درخواست دارای این فیلد / درخواست خوانده‌شده</th></tr>'
        for namespace,values in sorted(a['fields'].items()):
            n=a['field_coverage'][namespace];suffix=' · کامل در این خواندن' if complete and n==total else ' · حداقل مشاهده‌شده؛ بقیه نامعلوم'
            html+='<tr><td class="ltr">'+text(namespace[0])+'<br>'+text(namespace[1])+'</td><td>'+text(len(values))+text(suffix)+'</td><td>'+text(n)+' / '+text(a['requests'])+'</td></tr>'
        html+='</table><details open><summary>شناسه‌ها و تعداد تکرار هرکدام</summary><table><tr><th>شناسه / فیلد</th><th>اجرا / نشست / IP</th><th>اولین و آخرین مشاهده</th><th>مدرک</th></tr>'
        for t in a['tokens'][page*PAGE_SIZE:(page+1)*PAGE_SIZE]:
            html+='<tr><td><a href="'+text(filter_link(topic=t['key']))+'">'+text(t['display'] or 'شناسهٔ پوشیده')+'</a><div class="muted ltr">'+text(t['key'][:12])+' · '+text(t['field'])+'</div></td><td>'+text(len(t['requests']))+' / '+text(len(t['sessions']-{None}))+' / '+text(len(t['ips']))+'</td><td>'+text(when(t['first_ns']))+'<br>'+text(when(t['last_ns']))+'</td><td>'+link(t['witness'])+'</td></tr>'
        html+='</table>'
        if len(a['tokens'])>(page+1)*PAGE_SIZE:html+='<a href="'+text(filter_link(evidence_page=page+1))+'">شناسه‌های بعدی</a>'
        if page:html+=' · <a href="'+text(filter_link(evidence_page=page-1))+'">شناسه‌های قبلی</a>'
        html+='</details>'
    html+='<details><summary>IPهای سمت مشتری: '+text(len(a['ips']) if a['ip_covered_requests'] else 'نامعلوم')+' IP مشاهده‌شده؛ '+text(a['ip_covered_requests'])+' درخواست دارای شاهد IP</summary><p>IPهای سرویس‌دهنده در این شمارش نیستند. یک IP مشترک، هویت مشترک نمی‌سازد؛ تغییر IP هم به‌تنهایی سوءاستفاده نیست.</p><table><tr><th>IP</th><th>درخواست / نشست</th><th>از / تا</th><th>مدرک</th></tr>'
    for item in a['ips'][:100]:
        html+='<tr><td class="ltr"><a href="'+text(filter_link(ip=item['key']))+'">'+text(item['display'] or 'IP #'+item['key'][:12])+'</a></td><td>'+text(len(item['requests']))+' / '+text(len(item['sessions']-{None}))+'</td><td>'+text(when(item['first_ns']))+'<br>'+text(when(item['last_ns']))+'</td><td>'+link(item['witness'])+'</td></tr>'
    if len(a['ips'])>100:html+='<tr><td colspan="4">فقط ۱۰۰ IP اول نشان داده شده؛ تعداد بالا مربوط به همهٔ IPهای مشاهده‌شده در همین خواندن است.</td></tr>'
    html+='</table></details><details><summary>سیر روزانهٔ درخواست‌های مرتبط</summary><table><tr><th>روز تهران</th><th>درخواست / محتوای معتبر</th><th>نشست / IP دارای شاهد</th></tr>'
    for date,v in a['days'].items():html+='<tr><td>'+text(date)+'</td><td>'+text(v['requests'])+' / '+text(v['qualified'])+'</td><td>'+text(len(v['sessions']))+' / '+text(len(v['ips']))+'</td></tr>'
    html+='</table><p>روزِ غایب از این جدول، صفر مصرف در کل سامانه نیست؛ این جدول فقط درخواست‌های مرتبط با همین پرونده را نشان می‌دهد.</p></details>'
    selected=[r for r in rows if (not topic or any(t.get('key')==topic for t in r.get('subjects') or [])) and (not ip or ip in (r.get('ip_keys') or []))]
    html+='<details id="request-evidence"'+(' open' if topic or ip else '')+'><summary>درخواست‌ها و مدارک: '+text(len(selected))+' مورد در این خواندن</summary>'
    if topic or ip:html+='<a href="/case/'+key+'#request-evidence">پاک‌کردن فیلتر شناسه / IP</a>'
    html+='<table><tr><th>زمان تهران</th><th>شناسه / IP مشاهده‌شده</th><th>نتیجهٔ صریح / پوشش</th><th>مدرک</th></tr>'
    for r in selected[page*PAGE_SIZE:(page+1)*PAGE_SIZE]:
        topics='، '.join(dict.fromkeys(t.get('display') or t['key'][:12] for t in r.get('subjects') or [])) if r['qualified'] else 'محتوا نامعلوم یا قدیمی'
        displays=r.get('ip_display') or {};shown_ips='، '.join(displays.get(k,'IP #'+k[:12]) for k in r.get('ip_keys') or [])
        html+='<tr><td>'+text(when(r['at_ns']))+'</td><td>'+text(topics)+'<br><span class="ltr">'+text(shown_ips)+'</span></td><td>'+text((r.get('result') or {}).get('code'))+'<br>'+('پروفایل معتبر' if r['qualified'] else 'شاهد محتوایی نامعلوم')+'</td><td>'+link(r['request_key'])+'</td></tr>'
    html+='</table>'
    if len(selected)>(page+1)*PAGE_SIZE:html+='<a href="'+text(filter_link(evidence_page=page+1,**({'topic':topic} if topic else {}),**({'ip':ip} if ip else {})))+'">درخواست‌های بعدی</a>'
    if page:html+=' · <a href="'+text(filter_link(evidence_page=page-1,**({'topic':topic} if topic else {}),**({'ip':ip} if ip else {})))+'">درخواست‌های قبلی</a>'
    return html+'</details>'+(related(store,case,a['tokens']) if case else '')+'</section>'
