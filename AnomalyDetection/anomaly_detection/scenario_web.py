"""Read-only scenario coverage and persisted content/network decisions."""
import json,re

SCENARIOS=(
 (1,'تغییر ساختار یا معنای پاسخ با کد موفق',('response_schema_change','response_content_change'),'مقایسهٔ ساختار و مقادیر خروجی؛ نتیجهٔ مالی قطعی مستقل است.'),
 (2,'افزایش خطا و قطعی احتمالی خدمت',('service_health',),'نتیجهٔ صریح هم‌دامنه، نمونهٔ مستقل و پروندهٔ پایدار با تاریخچه.'),
 (3,'افزایش یا کاهش فعالیت خدمت',('service_volume',),'مرجع زمانی خودکار و پوشش کامل؛ نداشتن داده، صفر نیست.'),
 (4,'استعلام چند موضوع یا شناسه توسط یک نشست',('subject_enumeration','repeated_target'),'شناسهٔ موضوع و تکرار همان محتوا؛ شناسهٔ فاکتور جای قبض اصلی نیست.'),
 (5,'تغییر مراحل معمول اجرای خدمت',('workflow_change','service_workflow_change'),'مقایسهٔ مراحل تقریباً همیشگی همان خدمت؛ درخواست بی‌نشست هم در دامنهٔ خدمت بررسی می‌شود؛ اثبات دورزدن مجوز نیست.'),
 (6,'تکرار API فنی با چند IP یا چند نشست',('client_ip_rotation','multi_session_service'),'درخواست‌های فنی هم رصد می‌شوند؛ رفتار تجاری جعلی ساخته نمی‌شود.'),
 (7,'تغییر IP همراه الگوی پیمایش یا محتوا',('client_ip_rotation','service_traversal'),'SessionID در تغییر IP حفظ می‌شود؛ تغییر IP به‌تنهایی مستقل تأیید نمی‌شود.'),
 (8,'نشست تازه با رفتار غیرمعمول',('repeated_target','subject_enumeration','client_ip_rotation'),'مرجع هم‌خدمت از نشست‌های دیگر؛ تازه‌بودن به‌تنهایی آنومالی نیست.'),
 (9,'فعالیت غیرمعمول چندنشستی روی یک خدمت',('multi_session_service','multi_session_target'),'حجم/تعداد نشست یا اشتراک غیرمعمول موضوع؛ تبانی قطعی استنتاج نمی‌شود.'),
)


def render(store,path,args):
    from .product_web import text,when,FAMILIES
    from .scenario_store import PROFILE_JOB_KINDS,PROFILE_VERSION,report
    if path=='/scenarios':
        value=report(store);rows=value['readiness_latest_256_job_sample'];byfamily={}
        for r in rows:byfamily.setdefault(r['family'],[]).append(r)
        body='<section><h2>پوشش سناریوهای محتوا، شبکه و خدمت</h2><p>وجود کد، قبولی سناریوی واقعی نیست. جدول، نمونهٔ آخرین ۲۵۶ کار ذخیره‌شده را نشان می‌دهد؛ مرجع ناکافی یا شاهد ناقص عادی بودن نیست.</p>'
        body+='<p>پروفایل درخواستِ خوانده‌شده: '+text(value['profiles'])+' · درخواست منتظر استخراج محتوا: '+text(value['profile_tasks'])+'</p><table><tr><th>سناریو</th><th>مرز تفسیر</th><th>وضعیت تصمیم‌های نمونه</th></tr>'
        for n,title,families,note in SCENARIOS:
            states=[r['status']+': '+str(r['decisions']) for f in families for r in byfamily.get(f,[])]
            body+='<tr><td>'+text(n)+' · '+text(title)+'</td><td>'+text(note)+'</td><td>'+text('، '.join(states) or 'هنوز ارزیابی ثبت نشده')+'</td></tr>'
        body+='</table><p>مرجع خدمت از نمونه‌های مستقل از انتخاب نامزدهاست. درخواست‌های یکسان با RequestID متفاوت جدا می‌مانند؛ محتوای مشابه فقط ارتباط موضوع را نشان می‌دهد.</p></section>'
        where='';params=[]
        session=args.get('session_key',[''])[0]
        if session:
            if not re.fullmatch('[0-9a-f]{64}',session):raise ValueError('invalid session')
            where=' WHERE entity_key=%s';params=[session]
        rows=store.raw.execute('SELECT scope_key,kind,entity_key,service_path,target_ns,dirty,last_evaluated_ns FROM anomaly_detection.adp_scenario_jobs'+where+' ORDER BY target_ns DESC,scope_key LIMIT 40',params).fetchall()
        body+='<section><h3>ارزیابی‌های محتوایی و شبکه‌ای</h3><table><tr><th>خدمت / دامنه</th><th>زمان تهران</th><th>وضعیت</th><th>مدرک</th></tr>'
        for r in rows:body+='<tr><td class="ltr">'+text(r['service_path'])+'<br>'+text(r['entity_key'])+'</td><td>'+text(when(r['target_ns']))+'</td><td>'+('منتظر بررسی ورودی جاری' if r['dirty'] else 'تصمیم ثبت شده؛ جزئیات هر روش را ببینید')+'</td><td><a href="/scenario-evaluation/'+text(r['scope_key'])+'">دلیل و شاهد</a></td></tr>'
        return body+'</table></section>'
    match=re.fullmatch(r'/scenario-evaluation/(sc1:[0-9a-f]{64})',path)
    if not match:raise LookupError()
    row=store.raw.execute('SELECT * FROM anomaly_detection.adp_scenario_jobs WHERE scope_key=%s',(match[1],)).fetchone()
    if not row:raise LookupError()
    value=json.loads(row['evaluation'] or '{}');body='<section><h2>ارزیابی محتوا و شبکه</h2><p class="ltr">'+text(row['entity_key'])+' · '+text(row['service_path'])+'</p><p>'+text(when(row['target_ns']))+'</p>'
    receipt=value.get('input_receipt') or {}
    if row['dirty'] or row['kind'] in PROFILE_JOB_KINDS and receipt.get('profile_version')!=PROFILE_VERSION:
        body+='<div class="notice">بازبینی این ارزیابی با شواهد و قرارداد جاری پروفایل در صف است.</div>'
    if receipt.get('expected_current_requests') is not None:
        body+='<p>پروفایل دارای شاهد / درخواست‌های مورد انتظار این بررسی: '+text(receipt.get('qualified_current_profiles',0))+' / '+text(receipt['expected_current_requests'])+'</p>'
    body+='<table><tr><th>روش</th><th>نتیجه</th><th>مشاهده / مرجع</th><th>دلیل و شاهد</th></tr>'
    labels={'CANDIDATE':'یافتهٔ نیازمند بررسی','NO_DEVIATION_OBSERVED':'در این روش از معیار عبور نکرده','INSUFFICIENT_DATA':'داده یا مرجع ناکافی'}
    for d in value.get('decisions',[]):
        body+='<tr><td>'+text(FAMILIES.get(d['family'],d['family']))+'</td><td>'+text(labels.get(d['status'],d['status']))+'</td><td>'+text(d.get('observed','—'))+' / '+text(d.get('expected','—'))+'</td><td>'+text(d.get('explanation_fa',''))
        for k in ('changed_stages','changed_fields'):
            if d.get(k):body+='<details><summary>تغییرهای دارای شاهد</summary><pre>'+text(json.dumps(d[k],ensure_ascii=False,indent=2))+'</pre></details>'
        if d.get('witness_request_key'):body+='<p><a href="http://127.0.0.1:5021/request/'+text(d['witness_request_key'])+'">شاهد اصلی در Viewer</a></p>'
        if d.get('duration_ns'):body+='<p>مدت مقایسه: '+text(d['duration_ns']/60e9)+' دقیقه؛ '+text(d.get('active_days'))+' روز فعال؛ '+text(d.get('observed_requests'))+' درخواست یکتا.</p>'
        if d.get('reference_actors') is not None:body+='<p>نشست مرجع قابل مقایسه: '+text(d['reference_actors'])+'؛ شناسهٔ هویت: فقط SessionID معتبر، بدون ادغام بر پایهٔ IP.</p>'
        body+='</td></tr>'
    body+='</table><p>کیفیت شاهد، مرجع و واحد شمارش هر روش مستقل است؛ این ارزیابی حکم تقلب، مالکیت شناسه یا تسویهٔ بانکی نیست.</p></section>'
    return body
