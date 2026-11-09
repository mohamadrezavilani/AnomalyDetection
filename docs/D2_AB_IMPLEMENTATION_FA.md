# LogManagment — اجرای D2-A / آماده‌سازی D2-B

تاریخ: ۲۰۲۶-۱۰-۲۷. مبنا: `LogManagment_D2_FastSmoke_Candidate_20261027.zip`.

## وضعیت

- **D2-A / ابزار اندازه‌گیری:** انجام‌شده در سورس؛ آزمون منطقی محلی PASS؛ اجرای ابزار روی PostgreSQL مالک هنوز NOT_RUN.
- **D2-B / مقایسهٔ روش نوشتن:** ابزار A/B روی `p24_design_*_qualification` آماده؛ اجرای native PostgreSQL و انتخاب روش بهینه هنوز NOT_RUN؛ **روش Worker عوض نشده است**.
- **D2-C / Prefetch:** NOT_STARTED. **D2/D3/D4/D5/D6 پذیرش نهایی ندارند.**
- مبنای D1: `d1_one_window.json` و مبنای D2: `d2_fast_smoke.json`. انتشار پنجرهٔ اول D2 انجام شد ولی 414.625s بیشتر از هدف 300s بود؛ دوم rollback شده/انتشار آن ثابت نشده است. 

## تغییرات محدود

1. `p24_foundation/viewer_data.py`: زمان server-side export/sort، حجم فایل spool، rollover از RAM به دیسک و زمان `COPY FROM STDIN` تا اتمام command ثبت می‌شود. آمار خام/کلید/توکن یا payload ثبت نمی‌شود. هیچ قید، lock، ordering، dedup، guard نسخه، checkpoint، نقش یا Payment تغییر نکرده است. در Worker همچنان `COPY BINARY` پیش‌فرض است.
2. `tools/viewer_pg_observer.py`: نمونه‌برداری اختیاری تنها برای یک probe؛ اتصال دوم خواندنی با `statement_timeout=2000`، مشاهدهٔ backend PID، انتظار/قفل/پیشرفت COPY؛ snapshot محدود جدول‌ها، IO/WAL/checkpointer، حداکثر ۳۹۰ نمونه با فاصلهٔ ۲ ثانیه. SQL متن، رمز، مشخصات مشتری و payload خارج نمی‌شود. آمار cluster-wide الزاماً متعلق به این Worker نیست؛ sample می‌تواند wait کوتاه را از دست بدهد؛ کمبود privilege در خروجی NOT_AVAILABLE است، نه تغییر config.
3. `tools/profile_viewer_window.py`: observer دقیقاً به PID اتصال Publisher وصل می‌شود؛ نتیجه در `pg_observer` کنار progress و status نهایی یک پنجره ذخیره می‌شود. پرش checkpoint یا تغییر سقف زمان انجام نشده است.
4. `tools/benchmark_viewer_pg_writes.py`: ۳ جفت اجرای AB/BA روی جداول **TEMP** با ایندکس/قیود مشابه، تاریخچهٔ مصنوعی ثابت و stage یکسان؛ روش‌های `copy_binary`، `insert_select_ordered` و `insert_select_unordered`. full multiset equality با `EXCEPT ALL` برای تمام ستون‌ها، همراه زمان انتقال. دیتابیس باید نامی با الگوی `p24_design_*_qualification` داشته باشد؛ هرگز به `p24_design_viewer` وصل نمی‌شود. benchmark با دادهٔ مصنوعی و TEMP نه سنجش تولید و نه جایگزین آزمون بومی است.
5. `tools/qualify_viewer_postgres.py`: assertion قدیمی «یک Merge برای هر جدول» اکنون مسیر native COPY را هم می‌شمارد؛ به‌صورت خودکار مسیر native تغییر نمی‌کند.

## تست‌های انجام‌شده

- ۶۰ آزمون هدفمند Ingest، D1، انتقال، Request، پرداخت و role: PASS (۲ مورد skip).
- ۳۴ آزمون بازپخش/جابه‌جایی ترتیب، روابط مالی و سفر: PASS.
- `compileall`: PASS.
- PostgreSQL native و A/B: NOT_RUN — میزبان این محیط نه PostgreSQL Server دارد و نه بستهٔ psycopg قابل نصب آفلاین. بنابراین **هیچ ادعای بهبود عملکرد نهایی نداریم**.
- آزمون‌های Flask/HTTP: NOT_RUN — Flask/Werkzeug در این محیط موجود نبودند. falseهای HTTP در D2 قبلی را خطای اثبات‌شدهٔ UI تفسیر نکنید.

## راه استفاده و گیت پذیرش

بعد از نصب ZIP و توقف Worker و UI قبلی، فقط `check_viewer_install.py` و سپس در صورت PASS بررسی خواندنی وضعیت انجام شود. اولین probe بومی حداکثر **یک پنجره** و با تله‌متری تازه است؛ نصب، تست A/B محلی و probe صاحب سامانه را در چرخه‌های متعدد حدسی تکرار نکنید. A/B را فقط روی دیتابیس qualification مستقل (با مجوز مالک) اجرا کنید؛ خود harness هیچ جدول دائمی ایجاد، حذف یا تغییر نمی‌دهد و schema Viewer باید از قبل وجود داشته باشد. `D2-B` تا انتخاب گزینه به پشتوانهٔ native A/B و کنترل invariants، باز می‌ماند.

خروجی بومی یک‌پنجره‌ای باید شامل `status`, `result`, `progress`, `pg_observer`, `runtime_source_sha256` باشد؛ در زمان failure نیز تمام نمونه‌های جمع‌آوری‌شده ذخیره می‌شوند. مقایسهٔ صرف stage، جای زمان کامل چرخه را نمی‌گیرد. نتیجهٔ سرعت در صورت عبور از ۳۰۰ ثانیه FAIL است حتی اگر انتشار سالم commit شود.

## Invariants غیرقابل معامله

- SessionID مرجع نشست؛ RequestIDهای مستقل؛ منشأ هر نسخه و raw؛ اتصال پنجره‌ها، ورود دیررس، cross-window و تضاد سراسری.
- inquiry و payment مستقل؛ ارتباط پرداخت مستند با PaymentKey و scope؛ Callback و تصمیم دستی اپراتور؛ role تجاری لزوماً initiation دستی نیست.
- `Public.v1/ExchangeCurrency`, `ExchangeGold`, `ExchangeCrypto`: business/unknown؛ پنج سرویس خودکار اصلی: support/confirmed_automatic؛ AddUserData/GetUserData/InvoiceRegister اقدام تجاری مستقل نیستند.
- انتشار همهٔ شواهد، read models، رسید و checkpoint در **یک تراکنش** باقی می‌ماند. تنظیمات خصوصی، کلیدها، LIVE_START_UTC، Core/Collector/Anomaly و `pishkhan24_shadow` دست‌نخورده است.

## موارد باز برای ارزیاب

1. علت واقعی زمان طولانی `COPY FROM STDIN`: index/IO یا WAL/CPU/lock؟ تنها مشاهدهٔ PID و delta آمار و A/B کنترل‌شده می‌تواند آن را تفکیک کند.
2. شرط انتخاب server INSERT نسبت به COPY پس از آزمون A/B روی تاریخچهٔ نماینده؛ در صورت عدم برتری یا mismatch هیچ تغییر Worker مجاز نیست.
3. شروع Prefetch حداکثر یک پنجره در آینده صرفاً پس از سنجش؛ هیچ Publish موازی، حذف رسید یا تغییر recheck نباید ایجاد شود.
4. ۶ forward + ۲ recheck، restart واقعی، HTTP در حین publication، recovery و ظرفیت ۸۰۰هزار RequestID در ساعت هنوز NOT_PROVEN هستند.
