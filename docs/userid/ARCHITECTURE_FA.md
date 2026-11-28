# معماری نسخهٔ مستقل مبتنی بر UserID

مبنای ممیزی، commit ba2a0605724491aa2ade2054497e9897c4bfb458 و بستهٔ COMPACT-PRODUCT-20261125-38 است. این ممیزی مسیر فعال Compact و وابستگی‌های لازم را پوشش می‌دهد؛ بازبینی خط‌به‌خط منطق هر Detector در WP03 و پیاده‌سازی هر جزء در بستهٔ خودش انجام می‌شود.

## آنچه در منبع و نمونهٔ واقعی تأیید شد

Core/Shared در CreateScope یک RequestID تازه و UserID nullable ایجاد می‌کنند. Authentication قبل از Session.Info دسترسی را بررسی می‌کند؛ Info ستون نهم ud_prc_userSessionInfo را به SetUserID می‌دهد. GetUserID و NLog خروجی مستقل UserID را می‌سازند. بعضی ردها، skipها، Jobها و callbackها بدون شناسه می‌مانند.

مالک ثبات شناسهٔ حساب اصلی میان سشن‌ها و تغییر مهمان به حساب پس از ورود را تأیید کرده است. چون Info پیش از Verify اجرا می‌شود، خود درخواست موفق Login ممکن است هنوز شناسهٔ مهمان داشته باشد. metadata نمونه، نوع هویت صریح ندارد؛ مثبت‌بودن عدد ورود را اثبات نمی‌کند.

چهار پنجرهٔ جدید ۳۰۶٬۹۳۵ سند، ۶۷٬۰۹۵ RequestID و ۵٬۰۱۶ UserID شامل مهمان و حساب داشتند. ۶۱٬۶۴۲ درخواست دارای یک شناسهٔ قابل انتساب، ۵٬۴۵۳ درخواست فاقد آن و تعارض داخل RequestID صفر بود. ۶۰ درخواست از مرز پنجره گذشتند. همهٔ UserIDهای موجود، رشتهٔ مثبت استاندارد Int64 بودند. چهار پنجرهٔ قدیمی ۳۴۹٬۹۱۰ سند، Session و هیچ UserID نداشتند.

در نمونهٔ جدید ۹۴۸ سند دارای UserID برای IP/UA جای‌نگهدار داشتند. N/A و ماسک سشن هویت نیستند. SQL نیمهٔ پایانی session/token را ماسک می‌کند؛ serializer JSON قاعدهٔ جدا دارد. شکل ماسک، توکن کامل یا نگاشت حساب نیست.

## نقشهٔ وضع موجود و حکم معماری

| جزء فعلی | وابستگی یا رفتار مؤثر | حکم برای نسخهٔ جدید |
|---|---|---|
| compact_behavior/source.py، ElasticWindow.records | projection شامل Session و فاقد UserID؛ کنترل PIT/scroll و تمامیت محدود | دریافت UserID در adapter مستقل؛ حفظ کنترل snapshot و بودجه |
| compact_behavior/extract.py، facts/merge/materialize | هویت از Session؛ یک رفتار از RequestID؛ محتوای منتخب و eligibility | هویت جدید و DTO مستقل؛ استفادهٔ انتخابی از parserهای خالص پس از آزمون |
| compact_behavior/context.py | metadata محیطی و payload کمکی؛ هویت حساب تولید نمی‌کند | حفظ منشأ/محدودیت؛ IP/UA جایگزین هویت نشوند |
| compact_behavior/store.py، Store.publish | جدول/ایندکس و dirty مبتنی بر session_id؛ cursor و pending و انتشار اتمیک | storage جدید؛ حفظ تضمین تراکنش و اصلاح با قرارداد UserID |
| compact_ad/engine.py و patterns/forest/seasonality | تجمیع actor بر سشن و مراجع نسخه‌دار | ممیزی و سازگارسازی در WP03؛ baseline تازه |
| compact_ad/store.py، commit_analysis | fence منبع/مرجع، نتیجه/ACK و تاریخچهٔ بازخورد | بازطراحی مستقل با همان تضمین علّی و اتمیک |
| compact_ad/longitudinal.py و long_store | ادامهٔ نسخه‌دار چندروزه و زمان تهران | واحد UserID و مراجع جدید، با کنترل تاریخچه و شکاف |
| compact_product/cases.py و review_groups | شناسهٔ پرونده و grouping وابسته به سشن، انتخاب و تازگی | پروندهٔ مستقل و پیوند نسخهٔ شاهد؛ بدون ادغام سشن/کاربر |
| compact_product/web.py | API نشست، فیلتر روز، feedback؛ کنترل تازگی | API کاربر در نصب جدید؛ حالت آرشیوی قدیمی جدا آزموده شود |
| compact_product/runtime.py، Lease و supervise | init و lease در راه‌اندازی وب؛ ناظر سه نقش را زنده می‌کند | runner مستقل و expected roles مختص همان instance |
| compact_product/operations.py و history.py | نام Task و پوشهٔ runtime و بازگشت به نقش‌های پیشین | نصب جدید مستقل؛ rollback نباید Writer قدیمی را روشن کند |
| helperهای viewer_performance در operations | وابستگی ابزار نصب به پوشه‌های قدیمی | پیش از حذف، dependency استخراج یا جایگزین شود |
| compact_product/config.py | پیش‌فرض پورت‌های ۵۰۲۱ و ۵۰۲۲ و schema فعلی | فقط ۵۰۲۲ برای نصب جدید؛ اشغال واقعی پورت بررسی شود |

در بازپخش قبلی پنجرهٔ اول جدید، ۱۷٬۱۴۵ عملیات materialize شد و session_eligible صفر بود؛ service_rate_eligible برابر ۳٬۶۶۱ باقی ماند. این شاهد مصرف‌نشدن UserID در کد فعلی است و به معنی نبود تحلیل سطح خدمت یا عادی‌بودن کاربران نیست.

## اجزای هدف و مالکیت

| مسیر هدف | مالک بسته | مسئولیت |
|---|---|---|
| userid_product/source، identity، extraction | WP01 | دریافت، هویت، اتصال شواهد و محتوای معتبر |
| userid_product/storage، migrations | WP02 | repository، schema، revision، صف و publication |
| userid_product/analysis | WP03 | ویژگی مصرفی، مراجع، نتیجه و چندروزه |
| userid_product/web | WP04 | read API، پرونده، شاهد و feedback |
| userid_product/runtime | WP05 | کنترل lifecycle، نصب، Task، پورت و recovery |
| contracts/userid و docs/userid | WP00 | قرارداد و تصمیم و نسخهٔ مشترک |

این مسیرها طرح هدف‌اند؛ ایجاد scaffold یا implementation آن‌ها جزو WP00 نیست. فایل __init__ ریشهٔ package، dependencyهای مشترک و قراردادها نباید هم‌زمان و بدون هماهنگی در چند بسته تغییر کنند.

## جریان داده و مسئولیت commit

۱. منبع یک پنجرهٔ کامل و پروفایل تأییدشده تحویل می‌دهد؛ لاگ فاقد UserID حذف نمی‌شود. شکست تمامیت یا سقف ورودی، publication و پیشروی checkpoint ایجاد نمی‌کند.

۲. WP01 درخواست‌ها را فقط در قلمرو منبع و RequestID وصل می‌کند؛ هویت و محتوای خدمت جدا استخراج می‌شوند. حالت ناقص قابل ذخیره و اصلاح است. candidateهای هویت با provenance حفظ می‌شوند؛ هیچ سشن ماسک‌شده‌ای کلید actor نمی‌شود.

۳. WP02 در یک تراکنش، revision رفتار/هویت/ویژگی، dirty و cursor انتشار را می‌نویسد. تکرار همان شواهد، رفتار یا revision تازه نمی‌سازد. seen_at یا زمان اجرای ابزار به‌تنهایی content hash را تغییر نمی‌دهد.

۴. WP03 snapshot نسخه‌دار می‌خواند و پیش از ثبت، source_epoch و reference_epoch و revision مؤثر را کنترل می‌کند. نتیجه و ACK دقیق همان نسخه با هم commit می‌شوند. تغییر منبع هنگام محاسبه، نتیجهٔ کهنه را منتشر نمی‌کند.

۵. تغییر شناسه از فقدان به اعتبار یا از اعتبار به تعارض، همان behavior_key را اصلاح می‌کند. سهم actor قبلی باید در پنجره و مرجع و پروندهٔ وابسته بازبینی/پس گرفته شود؛ تاریخچه و نظر انسانی حذف یا به حساب دیگری منتقل نمی‌شود.

۶. WP04 نتیجهٔ دارای منبع/مرجع معتبر را می‌خواند و زمان داده، پوشش و وضعیت آمادگی را نشان می‌دهد. شاهد پرونده به behavior_key و revision وصل است. feedback به finding_key و revision مربوطه متصل و در بازتحلیل حفظ می‌شود.

## دیتابیس و نقش‌های منطقی

نام مبنای پیشنهادی نصب جدید p24_userid_v1 و خانوادهٔ آزمون p24_userid_test_* است. قرارداد RuntimeConfig فقط خانوادهٔ p24_userid_* را می‌پذیرد؛ ایجاد DB، نقش و migration در WP02/WP05 انجام می‌شود. این قاعده مجوز اتصال به دیتابیس‌های قبلی نیست.

| قلمرو منطقی | اطلاعات لازم |
|---|---|
| ingest | پنجره‌ها، checkpoint، fragmentهای pending، deadline و صف dirty |
| behavior | درخواست یکتا، actor با UserID، شاهد هویت، revision و محتوای/ویژگی منتخب |
| analysis | summary، reference، نتیجه و نسخه‌ها، صف بازتحلیل و ادامهٔ چندروزه |
| app | پرونده، بازخورد نسخه‌دار و وضعیت/lease همان instance |

نام SQL نهایی جدول‌ها و ایندکس‌ها با WP02 است؛ مرزهای منطقی و قیود قرارداد ثابت‌اند. ثبت raw-log archive و انتقال تاریخچهٔ سشن به حساب، جزو برنامهٔ پایه نیست. payload/feature منتخب سقف اندازه و وضعیت نقص صریح دارند.

## زمان و دیررسی

event time سند، زمان اولین مشاهدهٔ شاهد، زمان commit انتشار و زمان تحلیل چهار مفهوم جدا هستند. timestamp نانوثانیه در JSON رشتهٔ ده‌دهی است؛ تبدیل از float برای هویت یا زمان دقیق انجام نمی‌شود. نمایش مرورگر می‌تواند زمان خوانا داشته باشد ولی کلید و زمان اصلی حفظ می‌شود.

مهلت pending اولیه شش پنجرهٔ پنج‌دقیقه‌ای و overlap اولیه دو پنجره با lag شصت ثانیه است؛ مقادیر عملیاتی با دادهٔ جدید بررسی و نسخه‌دار می‌شوند. deadline با watermark رویداد تعیین می‌شود، نه صرف عبور ساعت سیستم. دیررسی خارج از سیاست، صریح گزارش می‌شود؛ finality منبع از overlap نتیجه نمی‌شود. بازخوانی تاریخچه خارج از بودجهٔ جاری، کار محدود و مستقل می‌خواهد.

## حفظ نصب قدیمی

وب فعلی با انتخاب role=web خودکار فقط‌خواندنی نمی‌شود: Lease.init و runtime_init می‌نویسند. supervisor نیز می‌تواند ingest/analysis را دوباره شروع کند. WP05 باید وابستگی‌های نوشتن، Task شروع مجدد و فیلتر زمان/تازگی را آزموده و نمایش آرشیوی را حفظ کند.

Taskهای جدید باید از الگوی P24-UserID-<instance_id>-<role> و code/data root مستقل استفاده کنند. controller و rollback فقط همان instance و DB را هدف می‌گیرند. فعال‌سازی مجدد Writer قدیمی، رفتار rollback پیش‌فرض نیست. ۵۰۲۲ پیش از نصب بررسی می‌شود و listener اضافی قدیمی بدون تغییر پورت اصلی ارائه آزاد می‌شود.
