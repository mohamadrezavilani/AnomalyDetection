# LogManagment — D0/D1؛ بستهٔ تشخیص/اصلاح مشروط، ۲۰۲۶-۱۰-۲۷

## خط مبنا و نتیجهٔ بومی باز

مبنای توسعه منحصراً `source/P24_Viewer_Online_Final.zip` از Handoff ۲۰۲۶-۱۰-۲۷ است:
`5c2e9432024ec08af70f186b4232e83d58905ab8c7f25934452b6bf7d1e684b8`.
اثر انگشت runtime مبنا: `7eb96aac884f3fd9a02643e65f3ff69c8064bfbc3f0c99c437bb03c1636a4fdb`.
آخرین اجرا در `2026-10-27T05:20:00Z` (۷۱٬۲۲۱ رویداد)، پس از merge تقریباً ۹۰ ثانیه‌ای، در
`rebuild_requests_aggregate` با `SQLSTATE 57014` و بودجهٔ ۳۶۰٫۱۲۵ ثانیه لغو شد.
اجرای بومی آخر **قبول نیست**. نسل ۲۹ و next_ns ساعت ۰۵:۲۰ *پیش از خطا* ثبت شده‌اند، نه بعد از آن.
فاصلهٔ تاریخی ۲۳۰ پنجره حفظ شده؛ live-recent/کلید/config/دیتابیس دیگری تغییر نمی‌کنند.

## D0: مشاهدهٔ فقط‌خواندنی

`tools/diagnose_d0_d1_readonly.py` روی **فقط** `p24_design_viewer` با تراکنش
`REPEATABLE READ, READ ONLY` و timeout دستوری ۸ ثانیه اجرا می‌شود. داده‌های خروجی:
checkpoint واقعی، وجود header پنجره و رسید شکست، نسل، صحت نقش‌های ۸ مسیر مالک،
اثر انگشت sync، حجم تخمینی جدول‌ها، ایندکس رویدادها، آمار تاریخی scan و تنظیمات
محدود Query Planner. تعدادهای تخمینی و counterهای تجمعی آمار زمان این Query نیستند.
رمز، raw log، تنظیمات ES، note دستی یا کلید هیچ‌گاه چاپ نمی‌شود.

D0 فقط پس از اجرای ابزار روی میزبان مالک می‌تواند PASS/FAIL محلیِ مشاهده‌شده بگیرد؛
در محیط توسعهٔ حاضر وضعیت `NOT_RUN_OWNER` است. نبود headerهای منتشرشده به‌تنهایی
برابری همهٔ projectionها را ثابت نمی‌کند؛ نبود انتشار نیمه‌کاره باید با checkpoint
و snapshotهای D3/D4 نیز سنجیده شود.

## D1: تغییر محدود

- کد اصلی `p24_foundation/viewer_data.py`: فقط query اول `rebuild_requests_aggregate`
  در حالت incremental PostgreSQL تغییر کرده است. جدول رویدادهای متأثر حفظ و
  `request_key IN (SELECT viewer_projection_scope)` تکراری روی همان جدول حذف شد.
- برای هر `origin_key`، تعداد versionها در جدول **سراسری** `viewer_events` با subquery
  همبسته سنجیده می‌شود؛ `COUNT(*)=1` دقیقاً معادل نداشتن version رقیب است، چون
  `PRIMARY KEY(origin_key,version_key)` روی جدول اعمال می‌شود. نسخهٔ متعارضِ
  درخواست دیگری نیز از تجمیع حذف می‌شود. مسیر SQLite و full rebuild تغییر نکرده‌اند.
- `tools/profile_viewer_window.py` دو `EXPLAIN (FORMAT JSON)` بدون ANALYZE را فقط
  هنگام probe تک‌پنجره ثبت می‌کند: نسخهٔ قدیمیِ Scope جهانی و نسخهٔ پیشنهادیِ
  index lookup. فقط node/index/rows/cost چاپ می‌شود و نه SQL literal یا مشتری.
  هزینهٔ تخمینی Plan برابر با زمان واقعی نیست. در Worker عادی، EXPLAIN اجرا نمی‌شود.
- پایان query تجمیع با `rebuild_requests_aggregate_complete.seconds` اندازه‌گیری
  می‌شود؛ اگر QueryCanceled باز تکرار شود، مرحلهٔ ثبت plan، دادهٔ بومی برای علت‌یابی
  می‌دهد. budget شش دقیقه‌ای، کنترل تعارض، checkpoint، COPY، نقش Exchangeها،
  پنج سرویس پشتیبان، تصمیم اپراتور و روابط پرداخت حذف یا تغییر نکرده‌اند.

این یک **کاندید فرضیه‌محور برای probe بومی** است، نه رفع قطعیِ اثبات‌شده. برای D1
هنوز باید plan واقعی و زمان چرخهٔ همین runtime به دست آید. اگر Plan به scan
کل جدول یا spill منتهی شد، گام بعد صرفاً بررسی آن سند است؛ افزایش timeout یا
پرش به پنجرهٔ دیگر ممنوع است.

## شواهد و گیت‌ها

آزمون‌های متمرکز SQLite معنای `COUNT(*)=1` را در سناریوی version رقیب خارج از
RequestID جاری با SQL قدیم مقایسه می‌کنند. آزمون‌های کامل Flask/psycopg در محیط
توسعهٔ حاضر به علت نصب‌نبودن وابستگی‌های runtime و نبود سرور PostgreSQL اجرا
نشدند؛ `NOT_RUN` باقی می‌مانند. بازپخش آرشیوی نیز ظرفیت بومی یا صحت ES زنده نیست.
گزارش منبع و جزئیات در `validation/d0_d1_developer_report.json` ثبت می‌شود.

پس از نصب روی میزبان مالک، با Worker متوقف:

1. `python tools/check_viewer_install.py --config viewer_config.local.py --out validation/d1_install_check.json`
2. `python tools/diagnose_d0_d1_readonly.py --config viewer_config.local.py --out validation/d0_d1_readonly.json`
3. *فقط اگر نصب و D0 موفق بودند*: `python tools/profile_viewer_window.py --config viewer_config.local.py --max-minutes 6 --out validation/d1_one_window.json`

هر سه JSON را همراه Runtime SHA برای ارزیاب نگه دارید. ۳) یک ingest واقعی
حداکثر با بودجهٔ ۶ دقیقه است و خواندنی نیست؛ برعکس ۱) و ۲) احتمال انتشار در
صورت موفقیت دارد. حضور هم‌زمان Worker مجاز نیست. اگر ۳) شکست خورد، ابتدا
همان JSON و Query Plan بررسی شود؛ آزمون شش‌پنجره‌ای تکرار نشود.

بعد از D1 موفق بومی، D2 شش forward و دو recheck و حداکثر ۳۰۰ ثانیه در هر چرخه؛
سپس D3 هم‌زمانی/HTTP، D4 recovery/restore، D5 نقش/مرورگر و D6 تحویل نهایی
به ترتیب باقی می‌مانند. ۸۰۰هزار RequestID در ساعت فقط با بار نماینده قابل اثبات است.


## نتیجهٔ تک‌پنجره‌ای بومی پس از نگارش اولیهٔ این سند

بر خلاف عبارت‌های «هنوز probe بومی لازم است» در بخش تاریخی بالا، مالک D0 و D1 را بعداً اجرا کرده است: D0 نشان داد ۰۵:۲۰ منتشر شده (۱ header و ۱ receipt، checkpoint تا ۰۵:۴۵)؛ D1 با همین سورس قبلی در ۰۵:۴۵–۰۵:۵۰، تعداد ۶۵۲۸۴ رویداد و ۱۵۶۸۹ RequestID، تجمیع ۶٫۷۱۹ ثانیه و کل چرخه ۲۴۵٫۳۶ ثانیه موفق بوده است. مشاهدهٔ EXPLAIN بدون ANALYZE است و تعمیم به بار دیگر صحیح نیست. خلاصهٔ شواهد مالک: `validation/d1_native_owner_summary.json`.

برای سرعت توسعه، D2 یک `--smoke` محدود با ۲ forward و بدون recheck می‌گیرد. تست رسمی ۶+۲، پایداری چندپنجره‌ای و ظرفیت هدف همچنان انجام نشده است.
