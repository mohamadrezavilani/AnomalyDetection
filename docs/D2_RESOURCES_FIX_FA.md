# اصلاح منابع PostgreSQL و مسیر تعارض — ۲۰۲۶/۱۰/۲۷

**وضعیت جاری — تحویل مرحلهٔ آزمون اجرایی:** پایلوت بومی همین runtime شش forward و دو recheck را با ۶۴۴٬۶۲۸ رویداد و چرخه‌های 122.860 تا 220.172 ثانیه کامل کرده است. پیش‌دریافت در پنج پنجره، checkpoint و اتصال مجدد DB موفق و backlog از ۵۶ به ۵۴ رسیده‌اند. **نتیجهٔ کل CONDITIONAL است: ۸ خطای HTTP با علت ثبت‌نشده داریم.** رفع کندی این نمونه تأیید شده؛ پذیرش کامل پروژه، restart واقعی/restore، مرورگر و ظرفیت بازند. سورس پردازش نسبت به نسخهٔ بومی تغییر نکرده؛ ابزار مستقل `LogManagment_HTTP_Check.py` برای تشخیص کوتاه دوپنجره‌ای اضافه شده است. راهنمای تحویل جاری `docs/D2_FINALIZED_WRITES_HANDOFF_FA.md` و گزارش جاری `validation/operational_handoff_report.json` است. گزارش بومی اصلی در `validation/owner_live_acceptance_20261027.json` بدون تغییر CONDITIONAL نگه داشته شده است. مطالب قدیمی زیر سوابق‌اند.

## نسخهٔ جاری: Prefetch پس از موفقیت Resources v2

خروجی بومی `d2_resources_one_window.json` با runtime `f04092f275acf1242976d7b447b4c6a3aace68cccf0dc612e8795954a8e6bf30` موفق است: ۱۰۸٬۴۵۲ رویداد، ۲۴٬۶۴۲ درخواست متأثر، ۲۷۳٫۲۶۶ ثانیه کل شامل ۶۲٫۵ ثانیه Capture و ۲۱۰٫۷۶۶ ثانیه اعتبارسنجی/انتشار. مرز قطعی از ۰۶:۰۵ به ۰۶:۱۰ UTC، receipt از ۲۳ به ۲۴ و generation از ۴۸ به ۵۰ رسیده و کنترل checkpoint موفق است. تنظیمات فعال گزارش‌شده shared_buffers=8GB و wal_buffers=16MB است؛ fsync، synchronous_commit و full_page_writes روشن‌اند. merge رویدادها ۲۶٫۱۵۶، raw برابر ۱۴٫۴۵۴، capture-link برابر ۴٫۴۲۱ و links برابر ۸٫۶۲۵ ثانیه بود. این موفقیت یک پنجره است؛ نتایج قبلی روی بار و پنجره‌های متفاوت اثبات درصد بهبود نیستند.

### دو تغییر جاری

۱. Worker پیوسته و Pilot به‌صورت پیش‌فرض فقط یک Capture جلوتر را پس از دریافت پنجرهٔ فعلی شروع می‌کنند، آن هم فقط اگر پنجرهٔ بعدی طبق همان lag بسته شده باشد. کار پس‌زمینه فقط REST/PIT و فایل private دارد؛ هیچ اتصال DB، Ingest، Projection، commit یا تغییر checkpoint در آن نیست. مراحل DB و انتشار پنجره‌ها به‌ترتیب روی همان اتصال اجرا می‌شوند. فایل پیش‌دریافت‌شده دوباره از همان دروازهٔ کامل proof/hash/count/window/identity عبور می‌کند. صف بیشتر از یک پنجره نمی‌شود. آخرین forward در smoke، دریافت بلااستفادهٔ پنجرهٔ سوم را شروع نمی‌کند.

فایل با عمر بیش از ۳۰۰ ثانیه از شروع Capture، پنجرهٔ نامنطبق یا خطای پس‌زمینه، فقط یک بار تازه دریافت می‌شود؛ فایل کامل قبلی حذف نمی‌شود. هیچ cache دیسکی پس از restart به‌طور خودکار پذیرفته نمی‌شود. در تست قطع/اتصال DB در همان process، یک job حافظه‌ای می‌تواند باقی بماند؛ مصرف آن همچنان به cursor قطعی و کنترل پنجره/عمر وابسته است. recheck و manual_recheck همیشه traversal تازه دارند. snapshot زودتر ممکن است شواهدی را که بعد از Capture برسند نداشته باشد؛ finality همچنان not_established است، overlap و الزام بازبینی دستی خارج از overlap حفظ‌اند. این تغییر ادعای کامل‌بودن منبع یا پوشش فاصلهٔ تاریخی ۲۳۰ پنجره‌ای ندارد.

لغو Worker به Capture علامت می‌دهد تا در مرز صفحه، PIT/scroll و فایل ناقص را پاک‌سازی کند. درخواست HTTP در حال اجرا با همان request timeout قبلی محدود می‌ماند؛ thread پس‌زمینه daemon است تا توقف Worker منتظر کل بودجهٔ Capture نماند. فایل‌های کامل و شواهد واردشده دست‌نخورده‌اند.

۲. در گزارش بومی، فاصلهٔ rebuild_request_roots تا rebuild_request_conflicts برابر ۶۲٫۱۲۵ ثانیه است. Query انتخاب root هنوز دو NOT EXISTS روی نسخه‌های global داشت. فقط مسیر incremental PostgreSQL به COUNT=1 محدود به origin تغییر کرده؛ PK(origin_key,version_key) هم‌ارزی با نبود نسخهٔ دیگر را تضمین می‌کند و نسخهٔ متعلق به RequestID خارج از scope نیز بررسی می‌شود. ترتیب انتخاب root، تعارض‌های root، Session، درخواست مستقل، نقش‌ها و روابط پرداخت همان‌اند. bootstrap و SQLite از SQL قدیمی استفاده می‌کنند. زمان دقیق root اکنون با rebuild_request_roots_complete ثبت می‌شود. علت انتخاب plan و میزان بهبود این تغییر، تا آزمون بومی فرضیه‌اند.

### زمان‌سنجی و آزمون کوتاه

`capture_seconds` کل کار دریافت آن فایل است؛ `capture_wait_seconds` زمان انتظار همین چرخه برای آماده‌شدن فایل؛ `capture_overlap_seconds` سهم هم‌پوشانی است. `total_cycle_seconds` و `cycle_seconds` رسید، انتظار Capture به‌علاوهٔ اعتبارسنجی/انتشار را می‌سنجند؛ زمان دریافت در گزارش حذف نشده و دوباره هم شمرده نمی‌شود. زمان اولین پنجرهٔ سرد، هم‌پوشانی قبلی ندارد. برآورد حدود ۲۱۱ ثانیه در حالت پایدار صرفاً از هم‌پوشانیِ نمونهٔ قبلی است؛ رقابت CPU/دیسک و بار متفاوت می‌تواند آن را تغییر دهد. با backlog فعلی، رسیدن به آنلاین تدریجی است و از یک پنجره تضمین نمی‌شود.

فرمان جاری پس از استخراج بسته و توقف Worker/وب:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\viewer.ps1 -Action Smoke
Get-Content .\validation\d2_prefetch_smoke.json -Raw
```

این مسیر صحت نصب را بررسی، دو forward و یک recheck و تست اتصال مجدد/HTTP اجرا می‌کند. سقف هر چرخه ۳۰۰ ثانیه و سقف کل ۱۲ دقیقه است؛ تنظیمات PostgreSQL دوباره اعمال یا سرویس restart نمی‌شود. SMOKE_PASS به معنی پذیرش عملیاتی نیست. در JSON، windows[1].prefetched و prefetch.windows_prefetched و زمان root/mergeها اثر تغییرها را نشان می‌دهند. `--no-prefetch` در CLI live و Pilot مسیر سری را برای مقایسه برمی‌گرداند؛ تغییر داده/کلید/cursor لازم نیست. آزمون محلی سریع: `python tools/run_viewer_tests.py --out validation/viewer_tests.json`؛ نیازی به پایلوت طولانی برای تغییرهای صرفاً محلی نیست.

گزارش همین کاندید در `validation/d2_prefetch_report.json` است؛ آزمون‌های failure، دریافت ناقص/کهنه، recheck تازه، تعارض نسخهٔ بین دو RequestID، پیوستگی بین پنجره‌ها و برابری Projection با بازسازی کامل را پوشش می‌دهند. آزمون SQL با موتور PostgreSQL آزمایشگاهی، native COPY/Windows/سرعت یا هم‌زمانی چند اتصال بومی را اثبات نمی‌کند. پیش از پذیرش نهایی، گیت‌های شش forward/دو recheck، restart واقعی/restore و ظرفیت همچنان بازند.

## سابقهٔ Resources v2

نسخهٔ قبلی **Resources v2** بود که نتیجهٔ موفق تک‌پنجره‌ای آن در ابتدای این سند آمده است. نسخهٔ اول روی سیستم مالک پیش از restart با `new_postgres_config_error` برگشت و هیچ آزمون پردازشی اجرا نکرد. ایرادِ تشخیص در کد قطعی است؛ چون جزئیات خطاهای فایل در آن نسخه ثبت نشده، انتساب قطعی خطای همان اجرا به این ایراد ممکن نیست.

مالک پس از دیدن اثر بر دیتابیس‌های دیگر، اعمال منابع و restart همان instance را صریحاً تأیید کرده است. دامنهٔ تغییر تنظیمات عمومی فقط چهار مورد زیر است. داده، schema و جدول دیتابیس‌های دیگر تغییر نمی‌کنند.

| تنظیم | مقدار مشاهده‌شده | مقدار جدید |
|---|---|---|
| shared_buffers | 128MB | 8GB |
| wal_buffers | 4MB | 16MB |
| max_wal_size | 1GB | 8GB |
| min_wal_size | 80MB | 1GB |

مبنای انتخاب: حافظهٔ فیزیکی حدود ۱۸۰GiB، حدود ۱۳۰GiB آزاد، فضای آزاد درایو داده حدود ۱۷۹GiB و مشاهدهٔ انتظار WAL/flush در اجرای بومی. Windows دیسک‌ها را HDD/SAS گزارش کرده است. این انتخاب یک نقطهٔ شروع متناسب با شواهد است، نه تضمین زمان یا ظرفیت. چهار دیتابیس دیگر و چهار اتصال به دیتابیس‌های دیگر روی instance وجود داشت.

## اصلاح کد

در v2، پس از موفقیت هر چهار ALTER SYSTEM، فایل‌ها پیش از restart بررسی می‌شوند. PostgreSQL مقدار را در ALTER SYSTEM اعتبارسنجی می‌کند؛ `pg_file_settings` با وجود معتبر بودن مقدار، تغییر postmaster را تا restart با `setting could not be applied` نشان می‌دهد. فقط همین پیام برای آخرین ورودی مؤثر shared_buffers یا wal_buffers، با context=postmaster، مقدار دقیق هدف و مسیر دقیق فایل auto.conf همان instance پذیرفته می‌شود. خطاهای دیگر، خطای نحو، مقدار یا فایل متفاوت، override و نبود یکی از چهار مقدار مانع restart هستند. کنترل قبل از تغییر همچنان هیچ خطایی را نمی‌پذیرد. reload پیش از restart حذف شده، چون دو مقدار postmaster را فعال نمی‌کرد و اعتبارسنجی view به reload نیاز ندارد. ردیف‌های تشخیصی با نام پارامتر و شمارهٔ خط و دلیل ثابت ثبت می‌شوند؛ مقدار config، متن خام خطا و اطلاعات خصوصی منتشر نمی‌شوند.

این اصلاح تنها ابزار تنظیم منابع و آزمون آن را تغییر می‌دهد. سورس پردازش پنجره، تراکنش انتشار، checkpoint، سقف تست، کلید و معناشناسی نسبت به Resources قبلی تغییر نکرده‌اند. آزمون جریان apply با خطای منتظر restart باید دقیقاً یک restart و تأیید مقدارهای فعال را طی کند؛ جریان خطای واقعی باید هر چهار override قبلی را برگرداند و restart نکند. اجرای واقعی سرویس Windows همچنان NOT_RUN است.

مراجع: [pg_file_settings در PostgreSQL 17](https://www.postgresql.org/docs/17/view-pg-file-settings.html)، [pg_settings و context](https://www.postgresql.org/docs/17/view-pg-settings.html)، [کد رسمی اعتبارسنجی ALTER SYSTEM](https://doxygen.postgresql.org/guc_8c_source.html).

در اجرای قبلی، بین تجمیع و مرحلهٔ root حدود ۴۳ ثانیه مصرف شد. اکنون پس از ساخت درخواست‌های موقت، آمار آن‌ها پیش از anti-join تازه می‌شود. تشخیص نسخهٔ متعارض در مسیر incremental PostgreSQL، با scalar COUNT روی origin جهانی انجام می‌شود؛ PK(origin,version) تضمین می‌کند COUNT>1 همان وجود نسخهٔ رقیب است. نسخهٔ درخواست دیگری هم لحاظ می‌شود. برای missing/conflict مرحله و زمان جدا ثبت شده است.

ساخت نهایی درخواست و قرارداد پرداخت، مرز تراکنش، raw/capture، SessionID، RequestID، روابط پرداخت و نقش‌ها حفظ هستند. bootstrap و full rebuild تغییر رفتاری نکرده‌اند.

## فرمان یکپارچهٔ مالک

PowerShell با Run as Administrator و Worker/وب Viewer متوقف باشد. پس از استخراج بستهٔ کامل:

```powershell
python .\tools\apply_postgres_resources.py --config .\viewer_config.local.py --probe --out .\validation\d2_resources_probe.json
```

ابزار نصب را بررسی و قفل Worker را کنترل می‌کند؛ instance و سرویس Windows را از اتصال واقعی شناسایی می‌کند. پیش از ALTER SYSTEM، نسخهٔ اصلی `postgresql.auto.conf` و وضعیت چهار تنظیم در `private/pg_resource_backups/` ذخیره می‌شود. سپس فقط چهار تنظیم بالا اعمال، همان سرویس restart و مقدارهای فعال و هویت instance دوباره بررسی می‌شوند. checkpoint و شمار رسیدها پیش و پس از restart باید برابر باشند. تنظیمات دوام و سقف تست تغییر نمی‌کنند.

پس از موفقیت تنظیم منابع، فقط یک چرخه با سقف شش دقیقه و معیار پذیرش ۳۰۰ ثانیه اجرا می‌شود. نتیجهٔ همهٔ مراحل داخل `validation/d2_resources_probe.json` است. اجرای واقعی service restart در محیط Linux توسعه NOT_RUN است؛ بررسی‌های تشخیص سرویس، جلوگیری از هدف اشتباه و rollback محلی/SQL با تست انجام می‌شوند.

اگر تست سرعت شکست بخورد، تنظیمات سالم منابع صرفاً به‌خاطر آن برگردانده نمی‌شوند و تست دیگری خودکار شروع نمی‌شود. اگر اعمال/راه‌اندازی/تأیید تنظیمات شکست بخورد، ابزار تلاش به برگشت می‌کند. در خطای بازیابی یا تغییر هم‌زمان config توسط شخص دیگر، RECOVERY_REQUIRED ثبت می‌شود و فایل شخص دیگر بازنویسی نمی‌شود.

## برگشت دستی در صورت نیاز

نام فایل state واقعی در `rollback_state` گزارش است. از همان فایل استفاده شود:

```powershell
python .\tools\apply_postgres_resources.py --config .\viewer_config.local.py --action rollback --state "private\pg_resource_backups\TOKEN\state.json" --out .\validation\d2_resource_rollback.json
```

مقدار TOKEN نمونه است؛ مسیر واقعی گزارش جای آن قرار می‌گیرد. برگشت متصل فقط همان چهار پارامتر را به override قبلی بازمی‌گرداند؛ RESET ALL استفاده نمی‌شود. اگر سرور بالا نیاید، بازگردانی فایل اصلی تنها با تطبیق hash فایل تغییرکردهٔ خود ابزار مجاز است. فایل‌های private شامل backup تنظیمات‌اند و نباید همراه JSON عمومی ارسال شوند.

## حد شواهد

گزارش این سورس در `validation/d2_resource_fix_report.json` قرار دارد. PASS محلی یا موتور SQL آزمایشگاهی به معنی سرعت بومی، اجرای واقعی Windows service، ظرفیت ۸۰۰هزار RequestID/h یا پذیرش نهایی نیست. شش انتشار و دو recheck، UI هم‌زمان، restart/recovery کامل و باقی گیت‌ها پس از موفقیت این آزمون باقی‌اند.
