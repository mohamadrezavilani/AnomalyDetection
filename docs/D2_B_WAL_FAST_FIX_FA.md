# D2-B: محافظه‌کارانه‌ترین آزمایش عملی فشار WAL — ۲۰۲۶/۱۰/۲۷

مبنا: `LogManagment_D2_AB_Diagnostics_Candidate_20261027.zip`، نه بازنویسی Core/Collector.

## شواهد بومی جدید

- مالک یک پنجرهٔ ۱۰۰٬۵۶۳ رویدادی از ۰۶:۰۰ تا ۰۶:۰۵ UTC را منتشر کرده: ۳۱۶٫۶۷۲ ثانیه، بالاتر از گیت ۳۰۰؛ checkpoint این پنجره قبلاً جلو رفته است، آن را تکرار نکنیم.
- `viewer_events` COPY پایانی: ۵۹٫۶۴۰s، شامل export فقط ۱٫۲۰۳s و upload/finish برابر ۵۸٫۴۲۲s؛ spool روی دیسک افتاده؛ raw merge ۳۱٫۵۴۷s، links merge ۲۶٫۰۶۲s، request aggregate حدود ۱۳٫۴۸۴s.
- شاهد waits: `IO/WalWrite`=45، `IO/WalInitSync`=19، `LWLock/WALWrite`=7، `IO/DataFileRead`=9، blocking=0 در sampleهای موجود.
- بازهٔ observer، WAL تولیدی در *سطح سرور* حدود ۲٫۸۵GB و full-page-image شمار ۳۷۸٬۸۸۹ را ثبت کرده؛ دادهٔ نمونه تنها **قرینهٔ فشار WAL** است نه اثبات سهم Viewer. مقدار فعلی `wal_compression` هنوز در گزارش دیده نشده است؛ ممکن است از قبل فعال باشد.
- مقدار D2 Fast Smoke قبلی ۱۶۲٫۷s برای *همین تعداد و بازهٔ پنجره* در یک rollback ناقص مشاهده شده بود، ولی قیاس کنترل‌شدهٔ سرعت نیست.

## تغییر کد این کاندید

یک انتخاب **صریح و اختیاری** `--wal-compression pglz` در `live`, `live-once`, `recheck` افزوده شده که بلافاصله بعد از قفل تراکنشی و قبل از هر ingest با `SET LOCAL wal_compression = pglz` فقط برای همان تراکنش فعال است. بنابراین WAL، `full_page_writes`، `fsync`، `synchronous_commit` و دوام داده خاموش نمی‌شوند. پس از commit/rollback تنظیم محلی از بین می‌رود. بدون flag رفتار کاملاً مثل کاندید قبلی است.

`profile_viewer_window.py` نیز همین flag را می‌پذیرد و قبل از هر Capture در اتصال **فقط‌خواندنی** وضعیت فعلی `wal_compression` و مجوز `SET` را می‌سنجد؛ اگر اکنون compression از قبل فعال است، مجوز نیست یا خطای اتصال رخ دهد، **بدون ingest و تغییر checkpoint** با وضعیت `WAL_COMPRESSION_PREFLIGHT_STOPPED` خارج می‌شود. هش/رمز/کلید/SQL-text محرمانه در JSON خروجی نیست.

## چرا این انتخاب

بر اساس مستندات PostgreSQL 17، WAL compression تصاویر کامل صفحات را *بدون اتلاف* فشرده می‌کند و الزامات بازیابی را کم نمی‌کند، ولی CPU بیشتری مصرف می‌کند. فشرده‌سازی ممکن است روی سرور I/O-bound سود دهد، اما تضمین بهبود وجود ندارد. مسیر COPY و تمام PKها و ایندکس‌ها همان قبلی‌اند؛ RequestID، SessionID، تعارض، Late/Cross-window، پرداخت و تصمیم اپراتور تغییر نکرده‌اند.

## معیار

- تست‌های هدفمند محلی: ۹۷ مورد، ۱ Skip؛ مانیتورینگ، live publishing و حفظ rollback بررسی شده‌اند.
- PostgreSQL native/ویندوز: **NOT_RUN در محیط توسعه**، زیرا PostgreSQL server و psycopg نصب نبود؛ باید فقط یک پنجرهٔ بعدی مالک با همین فیلتر preflight و سقف ۶ دقیقه بررسی شود.
- اگر `PUBLISHED_UNDER_BUDGET`، ثبت موقت نتیجه و بررسی وضعیت پس از commit؛ D2 full هنوز به پایلوت نهایی نیاز دارد. اگر `OVER_BUDGET` یا `FAILED`، این روش را به‌عنوان راهکار سریع رد و رفتار قبلی (بدون flag) را حفظ کنیم. اگر preflight رد شد، دیگر هیچ آزمون پنجره‌ای با همین گزینه لازم نیست.
- در صورت ادامهٔ `WalWrite`/`WalInitSync`، bottleneck احتمالاً نیازمند بهبود واقعی زیرساخت نوشتن WAL/دیسک یا ارزیابی معماری indexing با دادهٔ بومی است؛ هیچ ادعای رفع قطعی مطرح نیست.

## محدودیت‌ها و موارد ثابت

- تغییر تنظیمات عمومی PostgreSQL، حذف ایندکس، Unlogged، خاموش‌کردن WAL یا بالا بردن timeout، ممنوع.
- فقط `p24_design_viewer` مجاز؛ اجرای preflight قبل از Capture این نام را کنترل می‌کند. خصوصی‌ها و `LIVE_START_UTC` بازنویسی نمی‌شوند.
- D1 single window PASS؛ D2 full/D3–D6 هنوز PENDING. سرعت ۸۰۰هزار RequestID/h NOT_PROVEN. گزارش وضعیت و تغییرات برای ارزیاب از همین ZIP قابل بازیابی است.
