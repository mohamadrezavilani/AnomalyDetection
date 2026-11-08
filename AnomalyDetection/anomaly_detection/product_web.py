"""Private RTL review UI. GETs read owned PostgreSQL; training stays in worker."""
from datetime import datetime
from zoneinfo import ZoneInfo
from http import cookies
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from html import escape
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import time
from urllib.parse import parse_qs,urlparse,quote
import threading

from . import BUILD_ID
from .native_pg import database
from .product_store import ProductStore
from .process_control import OwnedProcessLock,read_json
from .snapshot import ContractError

LABELS={'NEEDS_REVIEW':'نیازمند بررسی','HOLD':'در انتظار شواهد کافی','RECHECK_REQUIRED':'در حال بازبینی','WITHDRAWN':'بازپس‌گرفته‌شده',
    'ACTIVE':'فعال','DEFERRED':'دادهٔ ناکافی','reviewed_benign':'عادی تشخیص داده شد','confirmed_suspicious':'مشکوک تأیید شد','needs_evidence':'شاهد بیشتر لازم است'}
FAMILIES={'repeated_target':'تکرار همان موضوع استعلام','subject_enumeration':'تنوع موضوع استعلام','client_ip_rotation':'تغییر IP نشست','service_traversal':'پیمایش چند خدمت','workflow_change':'تغییر مراحل مشاهده‌شده','service_workflow_change':'تغییر مراحل خدمت، شامل درخواست بی‌نشست','response_schema_change':'تغییر ساختار پاسخ','response_content_change':'تغییر محتوای پاسخ','service_volume':'افزایش یا کاهش حجم خدمت','multi_session_service':'فعالیت چندنشستی خدمت','multi_session_target':'اشتراک موضوع بین نشست‌ها','continuous_rate':'نرخ پیوستهٔ رخدادها در چند مقیاس','service_population':'الگوی جمعی خدمت و سامانه','service_health':'خطای گزارش‌شدهٔ خدمت','rate_5m':'نرخ پنج‌دقیقه‌ای','peer_service_rate_5m':'نرخ خدمت نسبت به نشست‌های دیگر','rate_60m':'نرخ یک‌ساعته','service_mix':'ترکیب خدمات','isolation_forest':'دورافتادگی چندمتغیره',
    'service_sequence':'ترتیب آماری خدمات','timing_regularization':'ریتم زمانی','business_result_change':'تغییر نتیجهٔ تجاری','request_latency':'فاصلهٔ اولین تا آخرین شاهد درخواست','otp_result_change':'نتیجهٔ تأیید OTP','payment_result_change':'نتیجهٔ گزارش‌شدهٔ پرداخت','typed_target_diversity':'تنوع مراجع وابستهٔ درخواست','journey_profile_change':'الگوی سفر مشاهده‌شده'}
FAMILIES['input_subject_burst']='چند موضوع ورودی در زمان کوتاه'
FAMILIES.update(long_subject_enumeration='تنوع تجمعی موضوع در ساعت‌ها و روزها',long_client_ip_rotation='تنوع تجمعی IP نشست در ساعت‌ها و روزها')
CSS="""*{box-sizing:border-box}body{margin:0;background:#f3f6fa;color:#172b43;font:15px/1.9 Tahoma,Arial,sans-serif}a{color:#087d83;text-decoration:none}header{background:#112b44;color:white;padding:20px max(24px,calc((100% - 1250px)/2));border-bottom:4px solid #18b6a6}header h1{margin:0;font-size:23px}header small{color:#b9cedd}nav{display:flex;gap:24px;margin-top:12px;flex-wrap:wrap}nav a{color:#d8eeef}main{max-width:1250px;margin:28px auto;padding:0 20px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:16px}.card,section{background:white;border:1px solid #dde5ee;border-radius:12px;padding:20px;margin-bottom:20px;box-shadow:0 4px 12px #15324d05}.number{font-size:30px;font-weight:bold;color:#0c7c80}.muted{color:#63788c;font-size:13px}.badge{display:inline-block;padding:3px 10px;border-radius:20px;background:#e6f6f2;color:#08796b;font-size:12px}.HOLD,.DEFERRED{background:#fff4df;color:#89651c}.NEEDS_REVIEW{background:#ffebdf;color:#a34a14}.WITHDRAWN{background:#edf0f4;color:#667}table{border-collapse:collapse;width:100%;text-align:right}td,th{padding:12px 10px;border-bottom:1px solid #e8edf3;vertical-align:top}th{font-size:13px;color:#596f82}code,pre,.ltr{direction:ltr;unicode-bidi:embed;font-family:Consolas,monospace;overflow-wrap:anywhere}pre{background:#f4f7fa;padding:16px;border-radius:8px;white-space:pre-wrap;max-height:450px;overflow:auto}button,.button{border:0;border-radius:7px;background:#087d83;color:white;padding:9px 18px;cursor:pointer}input,select,textarea{border:1px solid #ccd8e3;border-radius:6px;padding:8px;background:white;font:inherit;max-width:100%}textarea{width:100%;min-height:90px}.notice{padding:14px;border-right:4px solid #dab764;background:#fff9ec;border-radius:8px;margin:16px 0}.empty{padding:45px;text-align:center;color:#63788c}details{margin-top:12px}footer{color:#718597;font-size:12px;margin:30px 0}.scroll{overflow-x:auto}h2{font-size:20px}h3{font-size:16px}.summary-table{min-width:850px}.summary-table td:first-child{max-width:260px}.identity{overflow-wrap:anywhere;max-width:260px}.review-tabs{display:flex;gap:20px;flex-wrap:wrap;border-bottom:1px solid #e2e9ef;margin-bottom:18px;padding-bottom:12px}.review-tabs .selected{font-weight:bold;color:#112b44;border-bottom:3px solid #18b6a6}.case-table{min-width:1100px}.case-table td:first-child{width:240px;overflow-wrap:anywhere}.case-table details table{min-width:650px}form.filters{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px}@media(max-width:700px){table{font-size:12px}main{padding:0 10px}header{padding:16px}td,th{padding:8px 5px}}"""


def text(value):return escape(str(value if value is not None else '—'))
def when(value):
    return datetime.fromtimestamp(value/1e9,ZoneInfo('Asia/Tehran')).strftime('%Y-%m-%d %H:%M:%S') if value else '—'
def badge(state):return '<span class="badge '+text(state)+'">'+text(LABELS.get(state,state))+'</span>'
def layout(title,body):
    return ('<!doctype html><html lang="fa" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>'+text(title)+' · AnomalyDetection</title><style>'+CSS+'</style><header><h1>دیدبان رفتار پیشخوان۲۴</h1>'
        '<small>AnomalyDetection · شواهد، الگوهای آموخته‌شده و بازبینی تاریخی</small><nav><a href="/">داشبورد</a><a href="/incidents">همهٔ آنومالی‌ها</a>'
        '<details><summary>ابزارهای بررسی</summary><a href="/evaluations">ارزیابی و شاهدها</a> · <a href="/coverage">پوشش روش‌ها</a> · <a href="/legacy">سوابق نسخهٔ قبل</a></details><a href="http://127.0.0.1:5021/">رفتارها در Viewer ↗</a></nav></header><main>'+
        body+'<footer>'+text(BUILD_ID)+' · PostgreSQL · زمان‌ها به وقت تهران · امتیاز آماری، احتمال تقلب نیست.</footer></main></html>')


def render(store,status,path,args,csrf):
    if path=='/scenarios':
        from .case_summary import render as unified
        shown=dict(args)
        if args.get('session_key'):shown.update(actor=args['session_key'],view=['cases'],bucket=['ALL'])
        return layout('همهٔ آنومالی‌ها',unified(store,shown))
    if path.startswith('/scenario-evaluation/'):
        from .scenario_web import render as detail
        return layout('دلیل و شاهد',detail(store,path,args)+'<p><a href="/incidents">بازگشت به همهٔ آنومالی‌ها</a></p>')
    if path=='/incidents' or path.startswith('/case/'):
        from .case_web import render as render_cases
        return layout('همهٔ آنومالی‌ها',render_cases(store,path,args,csrf))
    if path=='/evaluations' or path.startswith('/evaluation/'):
        from .product_evaluations import render as render_evaluations
        return layout('ارزیابی رفتارها',render_evaluations(store,path,args))
    if path=='/':
        stats=status.get('statistics',{});counts=stats.get('stable_cases',stats.get('incidents',{}));jobs=stats.get('jobs',{})
        from .case_summary import render as render_summary,cards as review_cards,statistics as review_statistics
        body=review_cards(review_statistics(store))+render_summary(store,{},preview=True)
        readiness=stats.get('readiness',[]);families={r['family'] for r in readiness}
        cold={family for family in families if all(r['status']=='INSUFFICIENT_DATA' for r in readiness if r['family']==family)}
        if cold:body+='<div class="notice">در نمونهٔ آخرین ۲۵۶ ارزیابی، '+text(len(cold))+' روش فقط دادهٔ ناکافی داشته‌اند. <a href="/coverage">وضعیت پوشش و آمادگی روش‌ها</a>؛ این نمونه نمایندهٔ همهٔ رفتارهای سامانه نیست.</div>'
        source=status.get('source_status') or {}
        floor=status.get('analysis_history_floor_ns')
        if floor:
            scope='<div class="notice">آغاز دامنهٔ تحلیل به وقت تهران <span class="ltr">'+text(when(floor))+'</span>.'
            if source.get('scope_status')=='WAITING_FOR_FIRST_SCOPE_WINDOW':
                scope+=' تحلیل منتظر انتشار اولین پنجرهٔ این دامنه در Viewer است.'
            body=scope+'</div>'+body
        body+='<section><details><summary>پوشش و سلامت پردازش</summary><p>'+badge(status.get('state','STARTING'))+' <span class="ltr">'+text(status.get('phase'))+'</span></p>'
        if (stats.get('statistics_collection') or {}).get('status')=='PARTIAL':body+='<div class="notice">بخشی از آمار هنوز کامل نیست؛ مقدار نامعلوم صفر محسوب نمی‌شود. وضعیت هر بخش و زمان مقدار قبلی در گزارش ثبت است؛ این گزارش‌گیری پردازش تشخیص را متوقف نمی‌کند.</div>'
        body+='<p>آخرین heartbeat: <span class="ltr">'+text(when(status.get('heartbeat_ns')))+'</span> · عقب‌ماندگی منبع: '+text(source.get('backlog_seconds'))+' ثانیه</p>'
        body+='<p>آخرین بازهٔ ارزیابی‌شده: '+text(when(stats.get('latest_evaluated_target_end_ns')))+' · پنجره‌های مشترک کامل: '+text(stats.get('complete_shared_windows',0))+'</p>'
        body+='<p>کارهای معلق: '+text(jobs.get('pending',0))+' · ارزیابی‌شده: '+text(jobs.get('evaluated',0))+' · بازبینی شاهد در این اجرا: '+text(status.get('audited_requests',0))+'</p>'
        body+='<p class="muted">بازه‌های صرفاً پوشش تاریخی: '+text(jobs.get('coverage_only',0))+' · در انتظار تفکیک صف قدیمی: '+text(jobs.get('scope_pending',0))+' · این شمارنده‌ها نتیجهٔ عادی‌بودن رفتار نیستند.</p>'
        migration=stats.get('case_migration') or {}
        body+='<p>انتقال پرونده‌های قبلی: '+('کامل' if migration.get('done') else 'در حال تکمیل خودکار')+' · بررسی خدمت و کل سامانه نیز جدا از صف نشست‌ها اجرا می‌شود.</p>'
        population=stats.get('population_queue',{})
        body+='<p>صف جمعی خدمت/سامانه: '+text(population.get('pending'))+' کار معلق · جدیدترین هدفِ رسیدگی‌شده: '+text(when(population.get('newest_attempted_target_ns')))+'؛ رسیدگی به یک هدف، تکمیل همهٔ هدف‌های قبل از آن را ثابت نمی‌کند.</p>'
        for key in ('last_source_failure','last_storage_failure'):
            if status.get(key):body+='<div class="notice">'+text(status[key])+'</div>'
        body+='<div class="notice">شواهد دیررس، پرونده و مدل‌های وابستهٔ تاریخی را دوباره وارد صف می‌کنند. بازبینی در دامنهٔ فعال تحلیل انجام می‌شود. دادهٔ ناکافی، عادی بودن نیست.</div></details></section>'
        body+='<section><h2>چرا یک رفتار پرونده ندارد؟</h2><p>در صفحهٔ ارزیابی‌ها می‌توانید نشست را انتخاب کنید و دریافت رفتار، انتظار در صف، دادهٔ ناکافی و تصمیم ثبت‌شده را جدا ببینید.</p><a class="button" href="/evaluations">بررسی ارزیابی یک نشست</a></section>'
        return layout('داشبورد',body)
    if path=='/coverage':
        body='<section><h2>روش‌های فعال و کیفیت پوشش</h2><table><tr><th>خانواده</th><th>روش و مرز تفسیر</th></tr>'
        descriptions={'continuous_rate':'شمارش دقیق بر اساس زمان رخداد در بازه‌های لغزان ۵ دقیقه، یک ساعت، یک روز و یک هفته؛ مرجع هم‌مدت، فقط از نشست‌های دیگر و گذشته. مرز پنجره یا روز، تحلیل و پرونده را قطع نمی‌کند.',
            'service_population':'حجم اجرا، تعداد نشست و تمرکز مصرف در سطح خدمت و کل سامانه؛ مدل عمومی تغییر الگو با ارزیابی زمانی و زمینهٔ ساعتی/روزانه/هفتگی در صورت کفایت داده.',
            'service_health':'فقط افزایش نتیجهٔ ناموفقِ صریح و هم‌دامنه با پوشش کامل؛ نمونهٔ انتخاب‌شده برای audit یا افزایش ترافیک، قطعیت اختلال محسوب نمی‌شود.',
            'rate_5m':'مدل خودکار rolling/hourly/daily/weekly و مرجع جمعیت فعال همان API؛ آموزش فقط از گذشته.',
            'peer_service_rate_5m':'مرجع همان خدمت در طول زمان؛ یک بیشینه برای هر Session دیگر، دست‌کم ۱۰۰ نشست و ۲۴ ساعت گسترهٔ مشاهده. مرجع HTTP فقط با مسیر واقعی HTTP یکسان مقایسه می‌شود؛ دادهٔ تست در آموزش وارد نمی‌شود.',
            'rate_60m':'تجمیع پیوستهٔ یک ساعت با کنترل کامل‌بودن پنجره‌ها؛ همان بُعد فعالیت.',
            'service_mix':'فاصلهٔ ترکیب خدمات با حجم مشابه و انتخاب زمینهٔ زمانی بر مبنای ارزیابی گذشته.',
            'isolation_forest':'مدل کم‌حجم چندمتغیره با ارزیابی زمانی و بدون سهم اجباری ناهنجاری.',
            'service_sequence':'انتخاب خودکار مدل فراوانی یا گذار مرتبهٔ یک؛ توالی با مرز پنجره قطع نمی‌شود.',
            'timing_regularization':'منظم‌تر و سریع‌تر شدن هم‌زمان نسبت به سابقه؛ به‌تنهایی اثبات ربات نیست.',
            'business_result_change':'فقط محور نتیجهٔ تجاری دارای شاهد؛ نتیجهٔ HTTP یا Provider جای نتیجهٔ کسب‌وکار نیست.',
            'request_latency':'فاصلهٔ زمانی مشاهدات همان RequestID؛ زمان قطعی پاسخ HTTP نیست و علت به مشتری نسبت داده نمی‌شود.',
            'otp_result_change':'فقط کد صریح تأیید OTP؛ اشتراک Session یا زمان، اتصال OTP نمی‌سازد.',
            'payment_result_change':'هزینهٔ استعلام و پرداخت قبض جدا؛ وضعیت گزارش‌شده، تسویه بانکی نیست.',
            'typed_target_diversity':'مقایسهٔ مراجع وابسته مانند فاکتور و آیتم نتیجه برای توضیح زمینه.',
            'input_subject_burst':'شمار موضوع ورودی معتبر در اجراهای یکتا. مرجع محافظه‌کارانه بر پایهٔ تعداد اجراهای نشست‌های دیگر است.',
            'journey_profile_change':'خروجی محدود خود Viewer؛ retry و اجراهای مستقل ادغام نمی‌شوند.'}
        descriptions.update({
            'long_subject_enumeration':'تجمیع محتوای شناسهٔ نوع‌دار یک Session معتبر در یک ساعت، یک روز، یک هفته و ۳۰ روز؛ همچنین بازهٔ پیوستهٔ فعلاً موجود از دو روز به بالا. مرجع، نشست‌های دیگرِ همین خدمت با مدت، حجم و روزهای فعال مشابه است. پوشش کامل تمام پنجره‌ها و همهٔ درخواست‌های نشست لازم است؛ این روش به ۱۰۰ درخواست محدود نیست.',
            'long_client_ip_rotation':'تعداد IPهای سمت مشتری برای همان SessionID در بازه‌های بلند؛ IPهای Provider و IP مشترک به‌عنوان هویت اشخاص استفاده نمی‌شوند. اولویت مستقل نیازمند شاهد محتوایی همراه است.',
            'repeated_target':'مقایسهٔ تکرار محتوای ورودی و همان شناسهٔ موضوع در درخواست‌های مستقل؛ Trace/Session و شناسهٔ فاکتور جای موضوع اصلی نیستند.',
            'subject_enumeration':'تنوع شناسهٔ موضوع یا امضای محتوای ورودی با مرجعِ دارای حجم مشاهدهٔ قابل مقایسه؛ تعداد اشخاص یا سوءاستفاده اثبات نمی‌شود.',
            'client_ip_rotation':'IP فقط از رویداد root همان نشست؛ شبکهٔ backend کنار گذاشته می‌شود. اولویت مستقل با پشتوانهٔ رفتاری همراه است.',
            'service_traversal':'تعداد خدمات پیموده‌شده در دنبالهٔ همان Session، با مرجع نشست‌های دیگر؛ تغییر IP هویت نشست را نمی‌شکند.',
            'service_workflow_change':'نمونهٔ مستقل درخواست‌های خدمت، شامل درخواست‌های فاقد نشست؛ نبود مرحلهٔ تقریباً همیشگی با سابقهٔ کامل همان مسیر مقایسه می‌شود؛ هویت کاربر ساخته نمی‌شود.',
            'workflow_change':'تغییر مراحل تقریباً همیشگیِ مشاهده‌شده در همان خدمت؛ شاهد ناقص یا مرحلهٔ اختیاری، دورزدن مجوز فرض نمی‌شود.',
            'response_schema_change':'تغییر ساختار/نوع فیلدهای پاسخ در نمونهٔ مستقل چندنشستی، حتی با کد موفق API؛ payload ناقص نتیجهٔ عادی ندارد.',
            'response_content_change':'تغییر توزیع مقادیر پاسخ یا غالب‌شدن نتیجهٔ تکراری، با مقایسهٔ قبل از هدف و تعدیل چند مقایسه؛ صحت مالی مستقل است.',
            'service_volume':'افزایش و کاهش حجم در census کامل، با مدل زمانی rolling/hour/day/week و انتخاب بر مبنای گذشته؛ شکاف داده صفر نیست.',
            'multi_session_service':'افزایش نامعمول تعداد نشست‌های فعال همان خدمت، در census کامل و مرجع هم‌واحد.',
            'multi_session_target':'هم‌پوشانی موضوع ورودی بین چند نشست در نمونهٔ مستقل، در برابر مرجع با حجم قابل مقایسه؛ اشتراک IP یا موضوع، هویت مشترک یا تبانی قطعی نیست.',
            'service_health':'نتیجهٔ صریح هم‌دامنه در census کامل یا نمونهٔ مستقل چندنشستی؛ نمونهٔ انتخاب‌شده صرفاً برای نامزدها و افزایش ترافیک، دلیل قطعی نیست.'})
        body+=''.join('<tr><td>'+text(label)+'</td><td>'+text(descriptions[key])+'</td></tr>' for key,label in FAMILIES.items())+'</table>'
        body+='<div class="notice">سوابق و بازخوردها در PostgreSQL باقی می‌مانند. خواندن و محاسبه صفحه‌ای و محدود است؛ محدودیت حافظه به معنی حذف تاریخ قدیمی نیست. کامل‌بودن CDC منبع و تاریخچه‌ای که پیش از مشاهده حذف شده باشد تضمین نمی‌شود.</div>'
        body+='<p>تشخیص هدف مشترک، معنای payload، اتصال OTP و قطعیت مالی فقط با قرارداد و شاهد مناسب قابل ارزیابی‌اند؛ در دادهٔ فاقد این شاهد، نتیجه نامعلوم باقی می‌ماند. دقت و recall واقعی هنوز با برچسب مستقل اندازه‌گیری نشده‌اند.</p></section>'
        body+='<section><h3>زمان، نگهداری و بازخورد</h3><p>پنج دقیقه، واحد انتشار و تکمیل منبع است؛ عمر رفتار یا پرونده نیست. تحلیل نرخ تا یک هفته و تحلیل محتوای تجمعی تا ۳۰ روز روی زمان رخداد انجام می‌شوند؛ زمینهٔ مدل‌های تاریخی تا ۵۶ روز است. سابقهٔ پرونده، نسخه‌های شاهد و بازخوردها در PostgreSQL نگه داشته می‌شوند و با پایان پنجره یا روز پاک نمی‌شوند. حذف یا بازنشانی منبع، دادهٔ گذشتهٔ ازدست‌رفته را قابل بازسازی نمی‌کند.</p><p>یک SessionID در تغییر IP حفظ می‌شود. اتصال چند Session به یک شخص نیازمند شناسهٔ معتبر شخص در قرارداد منبع است؛ اشتراک قبض یا IP چنین هویتی نمی‌سازد.</p><p>نظر اپراتور بازبینی مدل‌های وابسته را در صف می‌گذارد؛ مدل محتوایی شواهدِ مشکوک یا بازبینی‌نشدهٔ واجد معیار را از مرجع کنار می‌گذارد. تأیید عادی می‌تواند شواهد همان نسخه را برگرداند. شاهد تازه بازبینی دوباره می‌خواهد؛ بازخورد، دستور مسدودسازی نیست.</p></section>'
        readiness=(status.get('statistics') or {}).get('readiness',[])
        body+='<section><h2>آمادگی در ۲۵۶ ارزیابی اخیر</h2><p class="muted">این نمونهٔ ارزیابی‌های اخیر است؛ پوشش تمام جمعیت و دقت واقعی را ثابت نمی‌کند.</p><table><tr><th>خانواده</th><th>نتیجه</th><th>تعداد تصمیم</th></tr>'
        for row in readiness:body+='<tr><td>'+text(FAMILIES.get(row['family'],row['family']))+'</td><td>'+text(row['status'])+'</td><td>'+text(row['decisions'])+'</td></tr>'
        body+='</table></section>'
        content=(status.get('statistics') or {}).get('scenario_analysis') or {}
        body+='<section><h3>آمادگی محتوا، IP و تجمیع چندروزه</h3><p>این جدول نمونهٔ آخرین ۲۵۶ کار محتوایی است؛ نمونهٔ خالی، نبود آنومالی را ثابت نمی‌کند. تعداد درخواست منتظر استخراج محتوا: '+text(content.get('profile_tasks'))+'</p><table><tr><th>روش</th><th>وضعیت</th><th>تصمیم</th></tr>'
        for row in content.get('readiness_latest_256_job_sample') or []:body+='<tr><td>'+text(FAMILIES.get(row['family'],row['family']))+'</td><td>'+text(row['status'])+'</td><td>'+text(row['decisions'])+'</td></tr>'
        body+='</table></section>'
        body+='<section><p>یافته‌های محتوا، مسیر اجرا، IP و رفتار جمعی همراه یافته‌های نرخ در فهرست واحد هستند.</p><a href="/incidents">همهٔ آنومالی‌ها</a></section>'
        return layout('پوشش',body)
    if path=='/legacy-incidents':
        state=args.get('state',['NEEDS_REVIEW'])[0]
        if state not in ('ALL','NEEDS_REVIEW','HOLD','RECHECK_REQUIRED','WITHDRAWN'):raise ValueError('invalid filter')
        after=args.get('after',[''])[0];conditions=[];params=[]
        if state!='ALL':conditions.append('state=%s');params.append(state)
        if after:
            if not re.fullmatch(r'ai1:[0-9a-f]{64}',after):raise ValueError('invalid cursor')
            conditions.append('incident_key>%s');params.append(after)
        rows=store.raw.execute('SELECT * FROM anomaly_detection.adp_incidents'+(' WHERE '+' AND '.join(conditions) if conditions else '')+
            ' ORDER BY incident_key LIMIT 26',params).fetchall()
        body='<section><h2>پرونده‌های رفتاری</h2><form class="filters"><select name="state">'+''.join('<option value="'+value+'"'+(' selected' if value==state else '')+'>'+text(label)+'</option>' for value,label in
            [('NEEDS_REVIEW','نیازمند بررسی'),('HOLD','در انتظار شاهد'),('RECHECK_REQUIRED','در حال بازبینی'),('WITHDRAWN','بازپس‌گرفته‌شده'),('ALL','همه')])+'</select><button>نمایش</button></form>'
        if not rows:body+='<div class="empty">پرونده‌ای در این وضعیت وجود ندارد. نبود پرونده، به‌تنهایی تأیید عادی بودن یا تکمیل پوشش نیست.</div>'
        else:
            body+='<div class="scroll"><table><tr><th>زمان رفتار</th><th>کلید Session</th><th>وضعیت</th><th>آخرین تغییر</th></tr>'
            for row in rows[:25]:body+='<tr><td><a href="/incident/'+text(row['incident_key'])+'">'+text(when(row['target_ns']))+'</a></td><td class="ltr">'+text(row['session_key'])+'</td><td>'+badge(row['state'])+'</td><td class="ltr">'+text(when(row['updated_ns']))+'</td></tr>'
            body+='</table></div>'
        if len(rows)>25:body+='<p><a class="button" href="/legacy-incidents?state='+quote(state)+'&after='+quote(rows[24]['incident_key'])+'">صفحهٔ بعد</a></p>'
        return layout('پرونده‌ها',body+'</section>')
    if path.startswith('/incident/'):
        key=path.rsplit('/',1)[-1]
        if not re.fullmatch(r'ai1:[0-9a-f]{64}',key):raise LookupError()
        row=store.raw.execute('SELECT * FROM anomaly_detection.adp_incidents WHERE incident_key=%s',(key,)).fetchone()
        if row is None:raise LookupError()
        case=json.loads(row['body']);findings=store.raw.execute('SELECT * FROM anomaly_detection.adp_findings WHERE session_key=%s AND target_ns=%s ORDER BY family',
            (row['session_key'],row['target_ns'])).fetchall()
        feedback=store.raw.execute('SELECT * FROM anomaly_detection.adp_feedback WHERE incident_key=%s ORDER BY id DESC LIMIT 20',(key,)).fetchall()
        body='<section><h2>پروندهٔ '+text(when(row['target_ns']))+'</h2><p>'+badge(row['state'])+' · نسخهٔ '+text(row['revision'])+'</p><p>'+text(case['explanation_fa'])+'</p>'
        body+='<p>کلید Session: <span class="ltr">'+text(row['session_key'])+'</span> · <a href="http://127.0.0.1:5021/session/'+text(row['session_key'])+'">بازکردن Session در Viewer ↗</a></p>'
        body+='<p>بُعدهای متمایز: '+text('، '.join(case['dimensions']))+' · شاهد بازبینی‌شده: '+('بله' if case['evidence_verified'] else 'هنوز کامل نشده')+'</p></section>'
        for finding in findings:
            value=json.loads(finding['body'])
            body+='<section><h3>'+text(FAMILIES.get(finding['family'],finding['family']))+' · '+badge(finding['state'])+'</h3><p>'+text(value.get('explanation_fa'))+'</p>'
            body+='<p>API: <span class="ltr">'+text(value.get('service_path'))+'</span> · امتیاز: '+text(round(finding['score'],4))+'</p>'
            request_key=value.get('witness_request_key')
            if request_key and re.fullmatch('[0-9a-f]{64}',request_key):
                body+='<a href="/request/'+request_key+'">شاهد و تاریخچهٔ درخواست</a> · <a href="http://127.0.0.1:5021/request/'+request_key+'">جزئیات در Viewer ↗</a>'
            compact={key:value[key] for key in ('reason','observed','expected','upper','baseline_origin','observed_distribution','source_observed_ns','model_id') if key in value}
            body+='<details><summary>مبنای مقایسه</summary><pre>'+text(json.dumps(compact,ensure_ascii=False,indent=2))+'</pre></details></section>'
        body+='<section><h3>بازخورد اپراتور</h3><form method="post" action="/feedback"><input type="hidden" name="csrf" value="'+text(csrf)+'"><input type="hidden" name="incident" value="'+text(key)+'">'
        body+='<select name="label">'+''.join('<option value="'+label+'">'+text(LABELS[label])+'</option>' for label in ('needs_evidence','reviewed_benign','confirmed_suspicious'))+'</select><p><textarea name="note" maxlength="2000" placeholder="یادداشت و دلیل تصمیم"></textarea></p><button>ثبت بازخورد</button></form>'
        for item in feedback:body+='<p>'+badge(item['label'])+' · نسخهٔ '+text(item['incident_revision'])+' · '+text(when(item['created_ns']))+'<br>'+text(item['note'])+'</p>'
        return layout('جزئیات پرونده',body+'</section>')
    if path.startswith('/request/'):
        key=path.rsplit('/',1)[-1]
        if not re.fullmatch('[0-9a-f]{64}',key):raise LookupError()
        fact=store.raw.execute('SELECT * FROM anomaly_detection.adp_facts WHERE request_key=%s',(key,)).fetchone()
        if fact is None:raise LookupError()
        versions=store.raw.execute('SELECT change_type,observed_ns,body FROM anomaly_detection.adp_versions WHERE request_key=%s ORDER BY id DESC LIMIT 25',(key,)).fetchall()
        body='<section><h2>شاهد و تاریخچهٔ درخواست</h2><p class="ltr">'+text(key)+'</p><p>زمان رفتار: '+text(when(fact['at_ns']))+' · آخرین بازبینی شاهد: '+text(when(fact['last_audit_ns']))+'</p>'
        body+='<p><a href="http://127.0.0.1:5021/request/'+key+'">بازکردن شاهد اصلی در Viewer ↗</a></p><pre>'+text(json.dumps(json.loads(fact['details'] or fact['body']),ensure_ascii=False,indent=2))+'</pre></section>'
        journey=store.raw.execute('SELECT body,observed_ns FROM anomaly_detection.adp_journeys WHERE request_key=%s',(key,)).fetchone()
        if journey:body+='<section><h3>مراحل و روابط دریافت‌شده از Viewer</h3><p>مشاهده: '+text(when(journey['observed_ns']))+'</p><pre>'+text(json.dumps(json.loads(journey['body']),ensure_ascii=False,indent=2))+'</pre></section>'
        for version in versions:body+='<section><h3>'+text(when(version['observed_ns']))+' · '+text(version['change_type'])+'</h3><details><summary>نسخهٔ مشاهده‌شده</summary><pre>'+text(version['body'])+'</pre></details></section>'
        return layout('تاریخچهٔ شاهد',body)
    if path=='/legacy':
        exists=store.raw.execute("SELECT to_regclass('anomaly_detection.ad2_findings') AS name").fetchone()['name']
        rows=store.raw.execute('SELECT finding_key,state,body,target_ns FROM anomaly_detection.ad2_findings ORDER BY target_ns DESC LIMIT 25').fetchall() if exists else []
        body='<section><h2>سوابق PostgreSQL نسخهٔ قبل</h2><p class="muted">یافته‌ها و بازخوردهای قبلی حفظ شده‌اند. این فهرست مشاهدهٔ ذخیره‌شده است؛ بازبینی تازهٔ شاهد نیست.</p>'
        for row in rows:
            value=json.loads(row['body']);body+='<p>'+badge(row['state'])+' · '+text(when(row['target_ns']))+' · '+text(value.get('explanation_fa',''))+'</p>'
        return layout('سوابق قبلی',body+'</section>')
    raise LookupError()


def serve(root,sha, *, server_class=ThreadingHTTPServer):
    root=Path(root);secret=secrets.token_bytes(32);limit=threading.BoundedSemaphore(2)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def send(self,code,body, *, content_type='text/html; charset=utf-8',cookie=None,location=None):
            payload=body.encode('utf-8');self.send_response(code)
            for key,value in {'Content-Type':content_type,'Content-Length':str(len(payload)),'Cache-Control':'no-store',
                'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer',
                'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"}.items():self.send_header(key,value)
            if cookie:self.send_header('Set-Cookie','ad_session='+cookie+'; HttpOnly; SameSite=Strict; Path=/')
            if location:self.send_header('Location',location)
            self.end_headers();self.wfile.write(payload)
        def session(self):
            jar=cookies.SimpleCookie()
            try:jar.load(self.headers.get('Cookie',''))
            except cookies.CookieError:pass
            value=jar['ad_session'].value if 'ad_session' in jar else ''
            if not re.fullmatch('[A-Za-z0-9_-]{20,100}',value):value=secrets.token_urlsafe(24)
            return value,hmac.new(secret,value.encode(),hashlib.sha256).hexdigest()
        def do_GET(self):
            if self.headers.get('Host') not in ('127.0.0.1:5022','localhost:5022'):self.send(403,'Forbidden');return
            parsed=urlparse(self.path);session,csrf=self.session()
            stage='connect_postgresql';observed=None
            try:
                if parsed.path=='/api/status':
                    value=read_json(root/'reports/product_status.json',{})
                    self.send(200,json.dumps(value,ensure_ascii=False),content_type='application/json; charset=utf-8',cookie=session);return
                with limit,database(root,readonly=True) as raw:
                    from .owned_sql import ObservedConnection
                    observed=ObservedConnection(raw)
                    with observed.transaction():
                        stage='read_only_snapshot'
                        observed.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
                        stage='render_owned_page'
                        page=render(ProductStore(observed),read_json(root/'reports/product_status.json',{}),parsed.path,parse_qs(parsed.query),csrf)
                self.send(200,page,cookie=session)
            except LookupError:self.send(404,layout('یافت نشد','<section>پرونده یا شاهد پیدا نشد.</section>'))
            except ValueError:self.send(400,'Invalid request')
            except Exception as exc:
                from .web_diagnostics import record
                key=record(root,parsed.path,stage,exc,observed.metrics() if observed else [])
                if getattr(exc,'sqlstate',None)=='57014':
                    title='خواندن صفحه کامل نشد';message='خواندن این صفحه از زمان مجاز گذشت. این خطا به معنی نبود پرونده یا قطع اتصال دیتابیس نیست. صفحه را دوباره تازه کنید.';code=503
                elif stage=='connect_postgresql':
                    title='اتصال PostgreSQL آماده نیست';message='اتصال خواندنی صفحه به PostgreSQL برقرار نشد. وضعیت Worker و گزارش خطا را بررسی کنید.';code=503
                else:
                    title='خطا در نمایش صفحه';message='نمایش این صفحه کامل نشد. جزئیات فنی در گزارش ثبت شده است.';code=500
                self.send(code,layout(title,'<section><p>'+message+'</p><small>شناسهٔ خطا: '+key+'</small></section>'))
        def do_POST(self):
            if self.path!='/feedback' or self.headers.get('Host') not in ('127.0.0.1:5022','localhost:5022'):
                self.send(403,'Forbidden');return
            if self.headers.get('Origin') not in (None,'http://127.0.0.1:5022','http://localhost:5022'):self.send(403,'Forbidden');return
            try:
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<=32768:raise ValueError()
                values=parse_qs(self.rfile.read(length).decode('utf-8'));_,csrf=self.session()
                if not hmac.compare_digest(values.get('csrf',[''])[0],csrf):self.send(403,'Invalid token');return
                incident=values.get('incident',[''])[0]
                if not re.fullmatch(r'(ai1|ac1):[0-9a-f]{64}',incident):raise ValueError()
                with limit,database(root) as raw:
                    if incident.startswith('ac1:'):
                        from .cases import feedback
                        revision=values.get('case_revision',[''])[0]
                        if not revision.isdigit() or len(revision)>18:raise ValueError('missing case revision')
                        token=values.get('review_input_token',[''])[0]
                        if not re.fullmatch('[0-9a-f]{64}',token):raise ValueError('missing input receipt')
                        feedback(ProductStore(raw),incident,values.get('label',[''])[0],values.get('note',[''])[0],time.time_ns(),expected_revision=int(revision),expected_input_token=token)
                    else:ProductStore(raw).feedback(incident,values.get('label',[''])[0],values.get('note',[''])[0],time.time_ns())
                self.send(303,'',location=('/case/' if incident.startswith('ac1:') else '/incident/')+incident)
            except ContractError as exc:
                if str(exc) in ('CASE_CHANGED_SINCE_DISPLAY','CASE_INPUT_CHANGED_SINCE_DISPLAY'):self.send(409,'پرونده یا شواهد آن پس از نمایش تغییر کرده است؛ صفحه را تازه کنید و ورودی جدید را ببینید.')
                else:self.send(400,'Invalid review')
            except ValueError:self.send(400,'Invalid review')
            except Exception as exc:
                if getattr(exc,'sqlstate',None)=='57014':self.send(503,'خواندن اطلاعات لازم برای ثبت نظر از زمان مجاز گذشت؛ نظر ثبت نشد. صفحه را تازه کنید.')
                else:self.send(503,'PostgreSQL unavailable')
    with OwnedProcessLock(root,'product_web',sha,resource='web') as owner:
        server=server_class(('127.0.0.1',5022),Handler);server.daemon_threads=True;server.timeout=.5
        try:
            while True:
                if read_json(root/'data/web_stop_request.json',{}).get('instance_token')==owner.owner['instance_token']:break
                manifest=read_json(root/'RELEASE_MANIFEST.json',{})
                if manifest.get('source_sha256')!=sha:break
                server.handle_request()
        finally:server.server_close()
    return 0
