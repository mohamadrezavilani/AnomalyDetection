# اجرای جاری Viewer و AD

Writer آزمایشی جاری `VIEWER-20261117-C2C3-OBSERVED` است. فقط فرمان `Run_Viewer_Fast.py --trial` آن را فعال می‌کند. اجرای `Run_Viewer_Catchup.py` مسیر قبلی است؛ قبل از اجرای هر کدام، Writer دیگر باید با ابزار کنترل متوقف شده باشد. پاسخ `VIEWER_WORKER_ALREADY_RUNNING` یعنی فرمان دوم شروع نشده است و به‌تنهایی هویت یا سلامت پردازهٔ موجود را ثابت نمی‌کند.

AD جاری از PR35، برچسب `AD-20261116-REFERENCE-CONTRACT` و SHA منبع `a64c001532c76dfa71c40902e0f43e1d0654d5a8b062d2c63ecc1f81870fb98c` دارد. تغییر PR35 کالیبراسیون مؤثر را در هویت immutable مدل pin می‌کند؛ روش، آستانه، کلید پرونده، نظر انسانی و schema تغییر ندارند. صحت همهٔ خانواده‌ها یا precision/recall تولیدی پذیرفته نشده‌اند.

## نصب روی main و ادامه از cursor موجود

فقط نسخهٔ بازبینی‌شده را نصب کنید. اگر pull شامل تغییر AnomalyDetection باشد، AD نیز پیش از آن متوقف و پس از بررسی نسخه راه‌اندازی شود. این بسته فایل‌های اجرایی AD را عوض نمی‌کند. وب و دیتابیس فعلی، محدودهٔ اول آبان و هر دو cursor تاریخی و live حفظ می‌شوند؛ reset یا seek جدید لازم نیست.

```powershell
cd E:\P24\pishkhan24
$adPython = (Resolve-Path .\.venv\Scripts\python.exe).Path
$done = @('VIEWER_WORKER_STOPPED','VIEWER_BACKEND_STOPPED','NO_VIEWER_LOCK_OWNER_OBSERVED')
foreach ($attempt in 1..6) {
    $text = (& $adPython -B viewer_performance/Stop_Viewer_Worker.py --stop | Out-String)
    $text
    $state = ($text | ConvertFrom-Json).status
    if ($state -in $done) { break }
    if ($state -ne 'VIEWER_BACKEND_STOP_PENDING') { throw 'Viewer stop blocked.' }
    Start-Sleep -Seconds 1
}
if ($state -notin $done) { throw 'Viewer stop not confirmed.' }
git pull --ff-only origin main
if ($LASTEXITCODE -ne 0) { throw 'Git pull failed.' }
& $adPython -B AnomalyDetection/run_anomaly.py version
if ($LASTEXITCODE -ne 0) { throw 'AD release verification failed.' }
& $adPython -B AnomalyDetection/run_anomaly.py worker-start
if ($LASTEXITCODE -ne 0) { throw 'AD start failed.' }
& $adPython -B viewer_performance/Run_Viewer_Fast.py --trial
```

Writer فقط پس از گرفتن lease اختصاصی PostgreSQL، رسید پایدارِ هویت کد، PID پایتون، PID و زمان شروع اتصال، nonce اتصال و هویت سرور را ثبت می‌کند. فایل startup قدیمی جای این اثبات نیست. تغییر پردازه، اتصال، کد، منبع یا شکاف رسیدها، مشاهده را ناقص/نامعتبر می‌کند. qualification ایزوله نمی‌تواند رسید فعال محصول را جایگزین کند.

## مشاهدهٔ بدون پیمایش کامل جداول

در پنجرهٔ دیگری اجرا کنید و JSON خروجی را برای بازبینی بفرستید:

```powershell
cd E:\P24\pishkhan24
.\.venv\Scripts\python.exe -B viewer_performance/Observe_Viewer_Fast.py --project . --seconds 3600 --windows 12
```

برای مشاهدهٔ هشت‌ساعته، `--seconds 28800` و بدون `--windows` استفاده شود. این فرمان خودش پذیرش ظرفیت صادر نمی‌کند. فقط انتشارهای تازه با رسید commit معتبر شمرده می‌شوند؛ skip، staging و بازپخش بدون شاهد تازه ظرفیت درج شاهد نیستند. اولین تکمیل ممکن است از قبل آغاز شده باشد و از زمان چرخه حذف می‌شود. دریافت تا commit، زمان commit و COPY/INSERTهای نهایی ثبت می‌شوند. سهم این عملیات تمام هزینهٔ UPDATE/DELETE یا تمام نگهداری ایندکس نیست. آمار cache و دیسک کلاستر به Writer منتسب نمی‌شود.

هویت و heartbeat AD نیز بررسی و پیشرفت شمارنده‌های همان instance گزارش می‌شود. تعداد pending از آمار cacheشدهٔ Worker با timestamp و وضعیت کامل‌بودن گزارش می‌شود؛ پذیرش عقب‌ماندگی AD از این آمار قدیمی نتیجه نمی‌شود. timeout یا خطای AD نیاز به بررسی مستقل دارد و با فعال‌بودن پردازه حل‌شده فرض نمی‌شود.

## صحت، ظرفیت و ذخیره‌سازی مستقل‌اند

`Qualify_Viewer_Fast.py --purpose correctness` در دیتابیس‌های اختصاصی، خروجی کامل هر مرز را مقایسه می‌کند. `--purpose capacity` دیتابیس‌های تازهٔ دیگری می‌سازد و در بین پنجره‌ها oracle کامل اجرا نمی‌کند. مقایسهٔ حالت correctness معیار ظرفیت نیست. بارگذاری fixture، initialization، کنترل‌های صحت و cleanup در رسید کامل از زمان ستون انتشار تفکیک شده‌اند و ناپدید نمی‌شوند. هیچ‌یک نمایندهٔ قطعی working set خارج از cache یا دریافت زندهٔ Elasticsearch نیستند.

C2/C3 بهبود میانی‌اند. C1 و C4 در Worker محصول فعال نیستند. آزمایش C6 در `history_segments.py` و `Benchmark_History_Segments.py`، heap تازه و ایندکس پس از load، دایرکتوری‌های یکتایی سراسری و انتشار prefix را با هزینهٔ کامل می‌سنجد. این نمونه فقط change-set ذخیره‌سازی را می‌سنجد؛ backend آمادهٔ Viewer، مسیر query پذیرفته‌شده یا migration محصول نیست.

## بازگشت

ابتدا Writer آزمایشی را با همان ابزار stop متوقف و آزادشدن lease را بررسی کنید، سپس `Run_Viewer_Catchup.py --with-anomaly` را اجرا کنید. نیازی به checkout قدیمی، حذف شاهد، تغییر کلید، پاک‌کردن feedback یا تبدیل داده نیست. هدف ۶۰–۱۲۰ انتشار تاریخی تازه در ساعت و آزمون پایدار همراه وب و AD همچنان باز است. تاریخچهٔ راهنماهای قبلی در Git محفوظ است؛ راهنمای جاری همین فایل است.
