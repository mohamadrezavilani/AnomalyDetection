"""Bounded read-only views of evaluated AND pending session windows."""
import json
import re
from urllib.parse import urlencode

from . import FIVE_NS

LABELS={'COVERAGE_ONLY':'پوشش تاریخی بدون رفتار؛ خارج از صف ارزیابی',
    'SCOPE_PENDING':'در انتظار تفکیک صف قدیمی','PENDING':'در صف ارزیابی','RECHECK_REQUIRED':'در صف بازبینی','INSUFFICIENT_DATA':'دادهٔ ناکافی',
    'CANDIDATE':'یافتهٔ آماری ثبت شده','NO_DEVIATION_OBSERVED':'انحرافی در روش‌های ارزیابی‌شده گزارش نشد',
    'NOT_EVALUATED':'نتیجهٔ ارزیابی ثبت نشده'}
REASONS={
    'INSUFFICIENT_POOLED_SESSION_REFERENCE':'تعداد نشست‌های دیگر یا گسترهٔ زمانی مرجع همین خدمت کافی نیست.',
    'DIRECT_HTTP_REFERENCE_NOT_COMPARABLE':'مسیر واقعی HTTP این درخواست با مرجع مستقیم API یکسان نیست.',
    'POOLED_RATE_EXCEEDED':'نرخ در دُم توزیع مرجع نشست‌های دیگر قرار دارد.',
    'POOLED_RATE_WITHIN_RANGE':'نرخ از معیار مرجع نشست‌های دیگر عبور نکرده است.',
    'insufficient_complete_series_history':'سابقهٔ معتبر برای ساخت مدل زمانی کافی نیست.',
    'INSUFFICIENT_POSITIVE_HISTORY':'تعداد بازه‌های فعالِ معتبر همین خدمت کافی نیست.',
    'ROLLING_SCOPE_HAS_GAPS':'پوشش معتبرِ بازهٔ یک‌ساعته کامل نیست.',
    'TARGET_COVERAGE_UNKNOWN':'کامل‌بودن داده یا هویت رفتارهای این پنجره تأیید نشده است.',
    'INSUFFICIENT_COMPARABLE_VOLUME_HISTORY':'سابقهٔ کافی با حجم فعالیت قابل مقایسه وجود ندارد.',
    'INSUFFICIENT_MULTIVARIATE_HISTORY':'سابقهٔ کافی برای مقایسهٔ چندمتغیره وجود ندارد.',
    'INSUFFICIENT_ORDERED_HISTORY':'سابقه و پوشش لازم برای بررسی ترتیب خدمات کافی نیست.',
    'INSUFFICIENT_INTERARRIVAL_HISTORY':'سابقهٔ زمانی لازم برای مقایسهٔ فاصلهٔ اجراها کافی نیست.',
    'INSUFFICIENT_QUALIFIED_BUSINESS_RESULTS':'سابقهٔ نتیجهٔ تجاریِ دارای شاهد کافی نیست.',
    'QUALIFIED_CONTEXT_HISTORY_INSUFFICIENT':'سابقهٔ دارای شاهد در این محور کافی نیست.',
    'LEARNED_RANGE_NOT_EXCEEDED':'مقدار مشاهده‌شده از محدودهٔ آموخته‌شده عبور نکرده است.',
    'RELATIVE_INCREASE':'افزایش نسبت به مرجع آموخته‌شده گزارش شده است.'}


def parse_session(value):
    if not value:return None
    if re.fullmatch('[0-9a-f]{64}',value):return value
    match=re.search(r'/session/([0-9a-f]{64})(?:[/?#]|$)',value)
    if match:return match[1]
    raise ValueError('paste the Viewer session page link')


def evaluation_state(job):
    if job.get('target_scope','BEHAVIOR_TARGET')=='COVERAGE_ONLY':return 'COVERAGE_ONLY'
    if 'target_scope' in job and job['target_scope'] is None and not job.get('last_evaluated_ns'):return 'SCOPE_PENDING'
    if job.get('dirty') or job.get('processed_version')!=job.get('version'):
        return 'RECHECK_REQUIRED' if job.get('last_evaluated_ns') else 'PENDING'
    value=json.loads(job['evaluation']) if isinstance(job.get('evaluation'),str) else job.get('evaluation') or {}
    decisions=value.get('decisions',[])
    if any(d.get('status')=='CANDIDATE' for d in decisions):return 'CANDIDATE'
    if any(d.get('status')=='INSUFFICIENT_DATA' for d in decisions):return 'INSUFFICIENT_DATA'
    if decisions and all(d.get('status')=='NO_DEVIATION_OBSERVED' for d in decisions):return 'NO_DEVIATION_OBSERVED'
    return 'NOT_EVALUATED'


def render(store,path,args):
    from .product_web import text,when,FAMILIES
    proof_match=re.fullmatch(r'/evaluation/([0-9a-f]{64})/(\d{1,19})/proof',path)
    if proof_match:
        from .presentation_proof import render as render_proof
        return render_proof(store,proof_match[1],int(proof_match[2]))
    def label(job):
        value=json.loads(job.get('evaluation') or '{}')
        primary_current=job.get('primary_version') is not None and value.get('primary_version')==job['primary_version']
        name='مقایسهٔ نرخ جاری؛ بازبینی روش‌های تکمیلی' if job.get('dirty') and primary_current else LABELS[evaluation_state(job)]
        return '<span class="badge">'+text(name)+'</span>'
    def counts(summary):
        if not summary or summary.get('counts') is None:return 'نامشخص'
        return str(sum(summary['counts'].values()))
    if path=='/evaluations':
        original=args.get('session_key',[''])[0].strip();session=parse_session(original)
        state=args.get('state',['ALL'])[0]
        if state not in ('ALL','PENDING','ASSESSED'):raise ValueError('invalid evaluation filter')
        after_at=args.get('after_at',[''])[0];after_session=args.get('after_session',[''])[0]
        conditions=["j.target_scope IS DISTINCT FROM 'COVERAGE_ONLY'"];params=[]
        if session:conditions.append('j.session_key=%s');params.append(session)
        if state=='PENDING':conditions.append('j.dirty=TRUE')
        elif state=='ASSESSED':conditions.append('j.dirty=FALSE')
        if after_at or after_session:
            if not after_at.isdigit() or not re.fullmatch('[0-9a-f]{64}',after_session):raise ValueError('invalid evaluation cursor')
            at=int(after_at)
            if not 0<at<2**63 or at%FIVE_NS:raise ValueError('invalid evaluation time')
            conditions.append('(j.target_ns,j.session_key)<(%s,%s)');params.extend((at,after_session))
        sql='SELECT j.*,w.body AS summary,sw.complete AS source_window_complete FROM anomaly_detection.adp_jobs j LEFT JOIN anomaly_detection.adp_windows w '
        sql+='ON w.session_key=j.session_key AND w.start_ns=j.target_ns'
        sql+=' LEFT JOIN anomaly_detection.adp_source_windows sw ON sw.start_ns=j.target_ns'
        if conditions:sql+=' WHERE '+' AND '.join(conditions)
        rows=store.raw.execute(sql+' ORDER BY j.target_ns DESC,j.session_key DESC LIMIT 26',params).fetchall()
        body='<section><h2>ارزیابی رفتارها و علتِ نداشتن پرونده</h2><p>نشست را از لینک صفحهٔ همان نشست در Viewer انتخاب کنید. هر ردیف یک نشست و یک بازهٔ پنج‌دقیقه‌ای است.</p>'
        body+='<form class="filters"><input name="session_key" value="'+text(original)+'" placeholder="لینک صفحهٔ نشست در Viewer" style="width:560px"><select name="state">'
        for value,name in (('ALL','همه'),('PENDING','در صف'),('ASSESSED','ارزیابی ثبت‌شده')):
            body+='<option value="'+value+'"'+(' selected' if value==state else '')+'>'+name+'</option>'
        body+='</select><button>نمایش</button></form><p class="muted">دادهٔ ناکافی یا انتظار در صف، تأیید عادی‌بودن نیست. این صفحه شامل موارد فاقد پرونده هم هست.</p>'
        if not rows:body+='<div class="empty">در محدودهٔ این فیلتر، کار ارزیابی ثبت نشده است.</div>'
        else:
            body+='<div class="scroll"><table><tr><th>آغاز بازهٔ تهران</th><th>رفتار ثبت‌شده</th><th>وضعیت</th><th>آمادگی پنجره</th><th>آخرین ارزیابی</th><th>نشست</th></tr>'
            for row in rows[:25]:
                summary=json.loads(row['summary']) if row['summary'] else None
                url='/evaluation/'+row['session_key']+'/'+str(row['target_ns'])
                readiness='آمادهٔ ارزیابی' if row.get('source_window_complete') else 'منتظر تکمیل خواندن پنجره'
                body+='<tr><td><a href="'+text(url)+'">'+text(when(row['target_ns']))+'</a></td><td>'+counts(summary)+'</td><td>'+label(row)+'</td><td>'+readiness+'</td><td>'+text(when(row['last_evaluated_ns']))+'</td><td class="ltr">'+text(row['session_key'])+'</td></tr>'
            body+='</table></div>'
            body+='<p class="muted">شمار رفتار، مجموع خدمات همین نشست است؛ نرخ هر خدمت جداگانه با مرجع همان خدمت مقایسه می‌شود.</p>'
        if len(rows)>25:
            last=rows[24];query={'state':state,'after_at':last['target_ns'],'after_session':last['session_key']}
            if session:query['session_key']=session
            body+='<p><a class="button" href="/evaluations?'+text(urlencode(query))+'">صفحهٔ بعد</a></p>'
        return body+'</section>'
    match=re.fullmatch(r'/evaluation/([0-9a-f]{64})/(\d{1,19})',path)
    if not match:raise LookupError()
    session,at=match[1],int(match[2])
    if not 0<at<2**63 or at%FIVE_NS:raise ValueError('invalid evaluation target')
    job=store.raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(session,at)).fetchone()
    if job is None:raise LookupError()
    window=store.raw.execute('SELECT body FROM anomaly_detection.adp_windows WHERE session_key=%s AND start_ns=%s',(session,at)).fetchone()
    summary=json.loads(window['body']) if window else None
    proof=store.raw.execute('SELECT complete FROM anomaly_detection.adp_source_windows WHERE start_ns=%s',(at,)).fetchone()
    case=store.raw.execute('SELECT incident_key,state FROM anomaly_detection.adp_incidents WHERE session_key=%s AND target_ns=%s LIMIT 1',(session,at)).fetchone()
    body='<section><h2>نتیجهٔ ارزیابی این نشست</h2><p>'+text(when(at))+' تا '+text(when(at+FIVE_NS))+' تهران · '+label(job)+'</p>'
    body+='<p>تعداد رفتار ثبت‌شده در خلاصه: <strong>'+counts(summary)+'</strong> · آخرین ارزیابی: '+text(when(job['last_evaluated_ns']))+'</p>'
    body+='<p><a href="http://127.0.0.1:5021/session/'+session+'/behavior">رفتارهای نشست در Viewer ↗</a> · <a href="/evaluations?session_key='+session+'">همهٔ بازه‌های همین نشست</a></p>'
    body+='<p><a href="/incidents?view=cases&amp;bucket=ALL&amp;actor='+session+'">همهٔ آنومالی‌ها و مشاهدات همین کاربر</a></p>'
    body+='<p>خواندن کامل پنجره از منبع: '+('تأیید شده' if proof and proof['complete'] else 'هنوز تأیید نشده')+'</p>'
    if case:body+='<p><a class="button" href="/incident/'+text(case['incident_key'])+'">بازکردن پرونده</a></p>'
    else:body+='<div class="notice">برای این بازه پرونده‌ای ثبت نشده است. دلیل ارزیابی یا وضعیت صف در همین صفحه نمایش داده می‌شود.</div>'
    current=evaluation_state(job) not in ('PENDING','RECHECK_REQUIRED','SCOPE_PENDING','COVERAGE_ONLY')
    primary_value=json.loads(job.get('evaluation') or '{}')
    primary_current=job.get('primary_version') is not None and primary_value.get('primary_version')==job['primary_version']
    if primary_current:
        body+='<p>مقایسهٔ نرخ خدمت با نسخهٔ جاریِ داده ثبت شده است؛ بررسی روش‌های تکمیلی جدا ادامه دارد.</p>'
    if primary_value.get('pending_families'):
        body+='<p>روش‌های تکمیلی در صف مستقل: '+text(len(primary_value['pending_families']))+'؛ وجود نتیجه برای یک روش، کامل‌بودن همهٔ روش‌ها نیست.</p>'
    body+='<p><a class="button" href="/evaluation/'+session+'/'+str(at)+'/proof">مدرک قابل ارائهٔ همین ارزیابی</a></p>'
    if not current and not primary_current:body+='<p>نتیجهٔ نسخهٔ فعلی هنوز آماده نیست. اگر نتیجهٔ قبلی در پایین دیده می‌شود، مربوط به پیش از تغییر ورودی‌هاست.</p>'
    if summary and summary.get('counts') is not None:
        body+='<table><tr><th>خدمت</th><th>تعداد اجرای مشاهده‌شده</th><th>شاهد</th></tr>'
        for service,n in sorted(summary['counts'].items()):
            witness=(summary.get('witnesses') or {}).get(service)
            link='<a href="http://127.0.0.1:5021/request/'+witness+'">شاهد در Viewer ↗</a>' if isinstance(witness,str) and re.fullmatch('[0-9a-f]{64}',witness) else '—'
            body+='<tr><td class="ltr">'+text(service)+'</td><td>'+text(n)+'</td><td>'+link+'</td></tr>'
        body+='</table>'
    body+='</section>'
    value=json.loads(job['evaluation']) if job.get('evaluation') else {}
    decisions=value.get('decisions',[])
    if decisions:
        body+='<section><h2>'+('تصمیم‌های ثبت‌شده؛ وضعیت هر روش جداست' if current or primary_current else 'تصمیم‌های نسخهٔ قبلی')+'</h2><div class="scroll"><table><tr><th>روش</th><th>خدمت</th><th>نتیجه</th><th>مشاهده / انتظار</th><th>دلیل</th></tr>'
        for decision in decisions:
            status=decision.get('status','NOT_EVALUATED');reason=decision.get('reason','')
            explanation=decision.get('explanation_fa') or REASONS.get(reason) or reason
            extra={k:decision[k] for k in ('history_windows','personal_history_windows','positive_history_windows','peer_windows','peer_qualified_windows',
                'baseline_origin','upper','empirical_tail_rank','adjusted_empirical_tail_rank','comparison_count','screening_level','calibration_status') if decision.get(k) is not None}
            detail='<details><summary>جزئیات مبنای تصمیم</summary><pre>'+text(json.dumps(extra,ensure_ascii=False,indent=2))+'</pre></details>' if extra else ''
            body+='<tr><td>'+text(FAMILIES.get(decision['family'],decision['family']))+'</td><td class="ltr">'+text(decision.get('service_path','—'))+'</td><td>'+text(LABELS.get(status,status))+'</td><td>'+text(decision.get('observed','—'))+' / '+text(decision.get('expected','—'))+'</td><td>'+text(explanation)+detail+'</td></tr>'
        body+='</table></div><p class="muted">ارزیابی‌های قدیمی ممکن است مقدار مشاهده یا مرجع مقایسه را ذخیره نکرده باشند. نبود مقدار، صفر فرض نمی‌شود.</p></section>'
    return body
