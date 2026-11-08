"""Issue-first Persian review: summary rows, inline episodes and provenance."""
import json,re
from urllib.parse import urlencode
from .cases import current,LABELS as ISSUES,review_token

STATES={'EVIDENCE_PENDING':'نامزد آماری؛ در انتظار تکمیل شاهد','WATCH':'مشاهدهٔ آماری؛ پشتوانهٔ بیشتر لازم است','HISTORY':'سابقه؛ الگو در ارزیابی بعدی دیده نشده','NEEDS_REVIEW':'نیازمند بررسی','HOLD':'در انتظار شاهد','WITHDRAWN':'یافتهٔ بازپس‌گرفته‌شده',
 'RECHECK_REQUIRED':'در حال بازبینی','reviewed_benign':'بررسی‌شده؛ عادی','confirmed_suspicious':'مشکوک با تأیید اپراتور',
 'needs_evidence':'اپراتور شاهد بیشتری خواسته است'}


def render(store,path,args,csrf):
    from .product_web import text,when,badge
    def read(row):
        from .case_summary import case_status
        state=case_status(store,row['case_key'])
        shown={'EVIDENCE_PENDING':'EVIDENCE_PENDING','READY':'NEEDS_REVIEW','RECHECK':'RECHECK_REQUIRED','WATCH':'WATCH','HISTORY':'HISTORY','EVIDENCE':'needs_evidence','REVIEWED':state['review_label']}[state['bucket']]
        body=json.loads(state['body']);body['_historical_signals_pending']=state['stale_signals']
        return body,shown,state['fresh']
    def metric(body):
        strongest=body['strongest'];observed=strongest.get('observed');expected=strongest.get('expected')
        if strongest.get('family')=='input_subject_burst':return text(strongest['explanation_fa'])
        duration=strongest.get('duration_ns',strongest['end_ns']-strongest['begin_ns'])/60e9
        label={'activity':'اجرا','targets':'شناسهٔ نوع‌دار متمایز','service_health':'نتیجهٔ ناموفق','service_population':'اجرا',
            'latency':'ثانیه'}.get(body['issue_kind'],'مقدارِ معیار')
        result=f'{observed} {label} در {duration:g} دقیقه' if observed is not None else 'مقدار مقایسه در این ارزیابی ذخیره نشده است'
        if expected is not None:result+='؛ مرجع '+str(round(expected,3))
        return text(result)
    def header(body,state,fresh):
        entity=body['entity_key'];scope=body['entity_type']
        who=('نشست '+entity if scope=='actor' else 'کل سامانه' if scope=='system' else 'خدمت '+entity)
        phase={'OBSERVED':'مشاهده‌شده','RETURNED':'بازگشته','NO_CURRENT_SIGNAL':'در ارزیابی بعدی این الگو دیده نشده'}.get(body.get('phase'),'')
        return '<strong>'+text(body['title_fa'])+'</strong><div class="muted">'+text(who)+'</div><div>'+text(STATES.get(state,state))+' · '+text(phase)+'</div>'
    def signals(key,limit=8):
        rows=store.raw.execute('SELECT * FROM anomaly_detection.adp_case_signals WHERE case_key=%s '
            'ORDER BY begin_ns DESC,end_ns DESC,signal_key LIMIT %s',(key,limit)).fetchall()
        content='<table><tr><th>بازهٔ مشاهدهٔ تهران</th><th>شاهد / روش</th><th>نتیجه</th></tr>'
        for row in rows:
            value=json.loads(row['body']);url='/scenario-evaluation/'+row['scope_key'] if row['source_kind']=='feature' else '/evaluation/'+row['job_session']+'/'+str(row['target_ns']) if row['job_session'] else None
            content+='<tr><td>'+text(when(row['begin_ns']))+' تا '+text(when(row['end_ns']))+'</td><td>'+text(value.get('explanation_fa') or value.get('reason'))
            if url:content+=' <a href="'+text(url)+'">دلیل و شاهد</a>'
            content+='</td><td>'+text({'ACTIVE':'یافتهٔ ثبت‌شده','DEFERRED':'شاهد یا پوشش ناقص','WITHDRAWN':'معیار قبلی برقرار نیست'}.get(row['state'],row['state']))+'</td></tr>'
        return content+'</table>'
    if path=='/incidents':
        from .case_summary import render as summary_render
        return summary_render(store,args)
    match=re.fullmatch(r'/case/(ac1:[0-9a-f]{64})',path)
    if not match:raise LookupError()
    key=match[1];row=store.raw.execute('SELECT * FROM anomaly_detection.adp_cases WHERE case_key=%s',(key,)).fetchone()
    if not row:raise LookupError()
    data,status,fresh=read(row)
    body='<section><h2>'+header(data,status,fresh)+'</h2><p class="ltr">'+text(key)+'</p><p>'+metric(data)+'</p>'
    body+='<p>'+text(data['distinct_executions'])+' اجرای مرتبطِ یکتا؛ '+text(data['distinct_sessions'])+' نشست؛ '+text(data['episodes'])+' دورهٔ مرتبطِ معیار. دوره‌های هم‌پوشان ادغام می‌شوند؛ این عدد تعداد تلاش دستی افراد نیست.</p>'
    body+='<p>اولین رخداد: '+text(when(data['first_ns']))+' · آخرین رخداد: '+text(when(data['last_ns']))+' · آخرین تغییر پرونده: '+text(when(row['updated_ns']))+'</p>'
    if data.get('last_comparable_normal_end_ns'):body+='<p>آخرین ارزیابی مقایسه‌پذیر بدون این الگو، تا '+text(when(data['last_comparable_normal_end_ns']))+' بوده است. این وضعیت، عادی‌بودن کل رفتار یا سلامت قطعی سرویس را ثابت نمی‌کند؛ سابقه برای بررسی محفوظ است.</p>'
    if data.get('evidence_last_change_ns'):body+='<p>آخرین تکمیل یا اصلاح شاهد: '+text(when(data['evidence_last_change_ns']))+'</p>'
    if status=='WATCH':
        body+='<div class="notice">این یافته هنوز پشتوانهٔ لازم برای اولویت مستقل بررسی را ندارد. نادر بودن آماری به‌تنهایی رفتار مشکوک را تأیید نمی‌کند؛ شواهد و نسخه‌های قبلی محفوظ‌اند.</div>'
    body+='<p>ارزیابی ورودی جاری: '+('بله' if fresh else 'در صف بازبینی؛ نتیجهٔ قبلی عادی فرض نمی‌شود')+'</p>'
    if data.get('_historical_signals_pending'):
        body+='<p>تعداد معیارهای تاریخیِ منتظر بازبینی: '+text(data['_historical_signals_pending'])+'؛ وضعیت آماده بر پایهٔ یافتهٔ جاریِ دارای شاهد است و به معنی پایان بازبینی تمام سابقه نیست.</p>'
    if data['entity_type']=='actor':body+='<a href="http://127.0.0.1:5021/session/'+text(data['entity_key'])+'/behavior">رفتار پیوستهٔ نشست در Viewer ↗</a>'
    from .noc_evidence import reason as noc_reason,render as evidence
    body+='</section>'+noc_reason(data['strongest'],fresh=fresh)+evidence(store,key,args,case=data)
    body+='<section><details><summary>دوره‌ها، روش‌ها و ارزیابی‌های مرتبط</summary>'+signals(key,50)+'</details></section>'
    related=store.raw.execute('SELECT case_key,body FROM anomaly_detection.adp_cases WHERE case_key<>%s '
        'AND (entity_type=%s AND entity_key=%s OR service_path=%s) ORDER BY last_ns DESC LIMIT 20',
        (key,data['entity_type'],data['entity_key'],data['service_path'])).fetchall()
    linked=store.raw.execute('SELECT DISTINCT b.case_key,v.basis FROM anomaly_detection.adp_case_requests a '
        'JOIN anomaly_detection.adp_viewer_relations v ON (a.request_key=v.from_request OR a.request_key=v.to_request) '
        'JOIN anomaly_detection.adp_journeys j ON j.request_key=v.origin_request '
        'JOIN anomaly_detection.adp_facts f ON f.request_key=j.request_key AND f.revision=j.semantic_revision '
        'JOIN anomaly_detection.adp_case_requests b ON b.request_key=(CASE WHEN a.request_key=v.from_request THEN v.to_request ELSE v.from_request END) '
        'WHERE a.case_key=%s AND b.case_key<>%s AND v.current_verified=TRUE AND f.source_present=TRUE LIMIT 20',(key,key)).fetchall()
    body+='<section><details><summary>پرونده‌ها و ارتباط‌های مرتبط</summary><p>خدمت یا نشست مشترک، زمینهٔ بررسی است؛ رابطهٔ علت‌ومعلولی یا اجرای مشترک فرض نمی‌شود.</p>'
    for item in related:
        value=json.loads(item['body']);body+='<p><a href="/case/'+item['case_key']+'">'+text(value['title_fa'])+' · '+text(value['service_path'])+'</a></p>'
    for item in linked:body+='<p><a href="/case/'+text(item['case_key'])+'">رابطهٔ نوع‌دار ثبت‌شده در Viewer</a> · '+text(item['basis'])+'</p>'
    token=None
    try:
        from .sql_budget import statement_budget
        with statement_budget(store.raw,800):token=review_token(store,key)
    except Exception as exc:
        if getattr(exc,'sqlstate',None)!='57014':raise
    body+='</details></section><section><h3>بازخورد همین پرونده</h3><p>بازخورد روی همین نسخه و شواهدِ دیده‌شده ثبت می‌شود و بررسی مدل‌های وابسته را در صف می‌گذارد. «عادی» می‌تواند شواهد بررسی‌شده را دوباره وارد مرجع کند؛ «مشکوک» و «شاهد بیشتر» دادهٔ همان یافتهٔ معتبر را برای مدل محتوایی در قرنطینه نگه می‌دارند. این فرایند کاربر، IP یا خدمت را مسدود نمی‌کند و فهرست سفید دائمی نمی‌سازد. شاهد تازه نیازمند بازبینی دوباره است.</p><form method="post" action="/feedback"><input type="hidden" name="csrf" value="'+text(csrf)+'"><input type="hidden" name="incident" value="'+key+'"><input type="hidden" name="case_revision" value="'+text(row['revision'])+'"><input type="hidden" name="review_input_token" value="'+text(token)+'">'
    body+='<select name="label">'+''.join('<option value="'+v+'">'+text(STATES[v])+'</option>' for v in ('needs_evidence','reviewed_benign','confirmed_suspicious'))+'</select>'
    body+='<p><textarea name="note" maxlength="2000" placeholder="شاهد و دلیل تصمیم"></textarea></p><button'+('' if token else ' disabled')+'>ثبت بازخورد</button></form>'
    if not token:body+='<p>اطلاعات لازم برای ثبت نظرِ همین ورودی در این نوبت کامل خوانده نشد؛ برای ثبت بازخورد صفحه را تازه کنید. پرونده و سابقه حفظ شده‌اند.</p>'
    feedback=store.raw.execute('SELECT * FROM anomaly_detection.adp_case_feedback WHERE case_key=%s ORDER BY id DESC LIMIT 20',(key,)).fetchall()
    for item in feedback:body+='<p>'+text(STATES.get(item['label'],item['label']))+' · '+text(when(item['created_ns']))+' · نسخهٔ بررسی‌شده '+text(item['case_revision'])+' · شواهد تا '+text(when(item.get('reviewed_end_ns')))+'<br>'+text(item['note'])+'</p>'
    legacy=store.raw.execute('SELECT DISTINCT f.id,f.label,f.note,f.created_ns FROM anomaly_detection.adp_case_signals s '
        'JOIN anomaly_detection.adp_incidents i ON i.session_key=s.job_session AND i.target_ns=s.target_ns '
        'JOIN anomaly_detection.adp_feedback f ON f.incident_key=i.incident_key WHERE s.case_key=%s ORDER BY f.id DESC LIMIT 20',(key,)).fetchall()
    if legacy:body+='<h3>بازخوردهای قبلیِ مرتبط با نشست و بازه</h3>'
    for item in legacy:body+='<p>'+text(STATES.get(item['label'],item['label']))+' · '+text(when(item['created_ns']))+'<br>'+text(item['note'])+'</p>'
    body+='</section><section><details><summary>نسخه‌ها و اصلاح شواهد</summary>'
    versions=store.raw.execute('SELECT revision,observed_ns FROM anomaly_detection.adp_case_versions WHERE case_key=%s ORDER BY revision DESC LIMIT 20',(key,)).fetchall()
    body+=''.join('<p>نسخه '+text(v['revision'])+' · '+text(when(v['observed_ns']))+'</p>' for v in versions)
    return body+'</details></section>'
