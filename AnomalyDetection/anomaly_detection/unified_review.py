from .sql_budget import statement_budget
"""A compact status line on the existing anomaly list; no second incident store."""
from .case_summary import cte


def progress(store):
    from .product_web import text
    try:
        with statement_budget(store.raw,200):
            features={r['bucket']:r['n'] for r in store.raw.execute(cte()+"SELECT e.bucket,COUNT(*) AS n FROM effective e JOIN (SELECT DISTINCT case_key FROM signal_inputs WHERE source_kind='feature' AND state<>'WITHDRAWN') f USING(case_key) GROUP BY e.bucket").fetchall()}
            queue=store.raw.execute("SELECT COUNT(*) FILTER(WHERE dirty OR version<>processed_version) AS pending,COUNT(*) FILTER(WHERE NOT dirty AND version=processed_version AND evaluation::jsonb->>'pending_evidence_or_reference'='true') AS insufficient,COUNT(*) FILTER(WHERE processed_version>0) AS assessed FROM anomaly_detection.adp_scenario_jobs").fetchone()
    except Exception as exc:
        if getattr(exc,'sqlstate',None)!='57014':raise
        return '<section><p>یافته‌های نرخ، محتوا، مسیر اجرا و شبکه همگی در همین فهرست‌اند. شمار وضعیت بررسی‌های تازه در حال به‌روزرسانی است؛ مقدار نامعلوم صفر نیست.</p></section>'
    ready=features.get('READY',0);watch=features.get('WATCH',0);waiting=sum(features.get(k,0) for k in ('RECHECK','EVIDENCE','EVIDENCE_PENDING'))
    body='<section><p>یافته‌های نرخ، محتوا، مسیر اجرا، شبکه و رفتار جمعی همگی در جدول همین صفحه نمایش داده می‌شوند.</p><details><summary>وضعیت بررسی‌های محتوا و رفتار</summary><p>'
    body+=text(ready)+' پروندهٔ آمادهٔ بررسی · '+text(watch)+' مشاهدهٔ نیازمند پشتوانه · '+text(waiting)+' پرونده در انتظار تکمیل یا بازبینی</p>'
    if not ready:
        body+='<p>روش‌های محتوا و رفتار هنوز یافتهٔ آمادهٔ بررسی نداده‌اند. '
        body+=('بررسی‌ها شروع نشده‌اند یا هنوز نتیجه‌ای ذخیره نشده است.' if not queue['assessed'] else 'نتیجهٔ بررسی‌های انجام‌شده هنوز یافتهٔ آمادهٔ بررسی نداده است.')+'</p>'
    body+='<p class="muted">'+text(queue['pending'])+' بررسی در صف · '+text(queue['insufficient'])+' بررسی منتظر داده یا مرجع کافی. دادهٔ ناکافی تأیید عادی بودن نیست.</p>'
    body+='</details></section>'
    return body
