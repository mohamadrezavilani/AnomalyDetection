# نسخهٔ 20 — رفع توقف پردازش پشت آمار صف

Build: AD-PRODUCT-20261105-20. فقط کد AnomalyDetection تغییر می‌کند؛ migration/DDL جدید ندارد و Viewer، public، Core، صف، مرجع و دادهٔ مالک پاک یا reset نمی‌شوند. SQLite وارد محصول نمی‌شود. مدل‌ها، آستانه‌ها و سیاست پروندهٔ 19 تغییر نکرده‌اند.

## شاهد واقعی و علت

Anomaly_Case_Review_20261105_074842_7ee9be53.zip با SHA256 برابر 3bd91254bc948bc7bcf68b745929b7f5396d4197724eae0f38a8df7fffbe430e خوانده شد. Build19 و source9dbb5cf88c5a779ae156a22697b60ca44fc6f772e62483d0b8eeb1cb7447b425 درست و production_source_matches_manifest=true هستند. snapshot Worker در ۵نوامبر۱۱:۱۸تهران، DEGRADED_STORAGE و صفر ارزیابی/audit/تلاش منبع در اجرای تازه دارد. پروفایل، سناریو و sample جدید همگی با export کامل همان بخش صفرند.

trace آخر، statement_id=523fc7dc5c10cad5 با SQLSTATE57014 و۳٫۶۵۶ثانیه است. این hash دقیقاً SELECT CASE/COUNT/GROUP BY روی adp_jobs در ProductStore.report است، نه import تاریخچه یا تحلیل رفتار. Worker پیش از دریافت منبع report را اجرا می‌کرد؛ cancellation آن از مسیر خطای عمومی، اتصال را می‌بست و initialization را تکرار می‌کرد. نام phase=owned_historical_import در19 برای این شکست دقیق نبود. این توقف، عادی بودن رفتارها یا آماده‌شدن محتوای ۹سناریو را نشان نمی‌دهد.

## اصلاح

- runtime_statistics: بخش‌های آمار مستقل‌اند؛ هر بخش transaction/savepoint با statement_timeout محلی۲۰۰ms و بودجهٔ آغاز کلی۱ثانیه دارد. timeout بخش خودش rollback می‌شود و مقادیر بخش‌های دیگر حفظ می‌شوند. مقدار ناموجود null است؛ مقدار cache با timestamp اصلی و وضعیت stale مشخص می‌شود. timeout اتصال اصلی را نمی‌بندد و شمارش ناقص، صفر اعلام نمی‌شود. خطای غیرtimeout همچنان به مسیر خطای اصلی می‌رود. محدودیت قبلی اتصال پس از transaction خودکار برمی‌گردد؛ بودجهٔ منبع افزایش نیافته است. این بودجه، تضمین سقف latency شبکه/لغو بومی نیست.
- worker/UI: phase تازه refresh_statistics، وضعیت PARTIAL و بخش‌های نامعلوم/کش‌شده در گزارش، با پیام روشن در داشبورد. دریافت منبع، مدل primary، محتوا و سناریو به موفقیت آمار کل صف وابسته نیستند. مشاهدهٔ Worker شمارِ content_reads و scenario_evaluations و خطای همان مسیر را هم ذخیره می‌کند.
- case-review05: خواندن job/window و fact هر کلید پرونده با LATERAL/LIMIT1 به lookup کلید اصلی محدود شده است؛ join برنامه‌ریز نباید برای چند پرونده همهٔ جدول بزرگ را بخواند. خروجی و روابط همان‌اند؛ read-only و سقف۶۰ثانیه/۲۵۶MiB/PARTIAL حفظ‌اند. سرعت یا کامل‌شدن export بومی هنوز سنجیده نشده است.
- acceptance-report: یک ZIP شامل مشاهدهٔ Worker و case-review تولید می‌کند. پیش‌فرض۶۰ثانیه مشاهده؛ همان نقش خواندنی، بدون اجرای مدل/دریافت تازهٔ Viewer/تغییر baseline هنگام گزارش. report ناقص یا شکست export با وضعیت واقعی حفظ می‌شود؛ جمع‌آوری گزارش، حکم قبولی پروژه صادر نمی‌کند.

## نتیجهٔ بررسی تست‌های قبلی مالک

در گزارش واقعی، WaterBills۱۰۰/کران۳۴، ExchangeGold۲۲/۸ و ExchangeCurrency۲۰/۳ و۱۶/۳ دارای signal جاری، qualified و review_eligible هستند. پس گزارش نمی‌گوید این تست‌ها همگی گم یا عادی شده‌اند. برق۲۰/۲۴ از نظر نرخ qualified/current ولی واجد اولویت مستقل نیست؛ محتوا هنوز هیچ پروفایلی ندارد و آزمون همان قبض پذیرفته نشده است. گزارش case_facts و case_jobs به57014 خورده؛ نبود ردیف export نبود دادهٔ DB نیست و شاهد خام این نوبت مستقلاً audit نشده است.

## آزمون و حد پذیرش

۱۵۱ unit پاس:۱۴۸ قبلی+۳ ترکیب گزارش. check_revision20 همان statement شکست‌خوردهٔ بومی را با cancellation واقعی SQL تکرار می‌کند؛ در همان اتصال، sectionهای دیگر، بودجهٔ اتصال، cache/timestamp، RO/RTL، deferral budget و انتشار خطای غیرtimeout را می‌سنجد. Worker با timeoutهای تکراری آمار، روی یک lease/connection مدل primary و دو پروفایل و نتیجهٔ سناریو را ثبت می‌کند؛ source packet این آزمون مصنوعی است، ظرفیت/اجرای بومی نیست.

برای build20 آزمون‌های اصلی SQL/Worker/HTTP، revision15 (لغو واقعی و ادامه)، revision19 (محتوا/فنی/دیررس)، exporter و نصب/ارتقای ایزوله دوباره اجرا می‌شوند. گزارش‌های سایر نسخه‌ها در validation تاریخی‌اند و به20 تغییر برچسب نداده‌اند. قبولی Windows PostgreSQL20، precision/recall عمومی و ۹سناریوی واقعی هنوز تأیید نشده‌اند؛ تمام‌شدن پیاده‌سازی و قبولی تست ایزوله، پایان پذیرش واقعی نیست.

## پس از نصب

با Python موجود والد و پروژهٔ معمول، این یک فرمان را اجرا و فقط ZIP چاپ‌شده را بفرستید:

```powershell
$p = 'C:\Users\Administrator\PycharmProjects\TestProject\pishkhan24'
$py = 'C:\Users\Administrator\PycharmProjects\TestProject\.venv\Scripts\python.exe'
& $py "$p\AnomalyDetection\run_anomaly.py" acceptance-report --seconds 60
```

فرمان حدود یک دقیقه مشاهده و حداکثر یک دقیقه دریافت case-review دارد؛ ممکن است گزارش ناقص باشد و همان نیز ارسال شود. معیار گام بعد، عبور Worker از refresh_statistics، پیشرفت source/evaluation/audit، ساخته‌شدن پروفایل و تصمیم‌های شاهددار، و دلیل روش‌های ناکافی است. تمام ۹ سناریو باید با شاهد و نمونهٔ کنترل‌شدهٔ خودشان پذیرفته شوند؛ صحت مالی وابسته به لاگ تکمیلی Backend باقی است. برای این جمع‌آوری، استعلام پولی تازه یا reset دیتا لازم نیست.
