# Writer آزمایشی C2/C3

نسخه: `VIEWER-20261117-C2C3-TRIAL`. این مسیر با فرمان صریح فعال می‌شود؛ اجرای معمولی Viewer، وب و AD خودکار به این Writer تغییر نمی‌کنند. هویت مستقل کد در `FAST_WRITER_MANIFEST.json` و خط `VIEWER_FAST_TRIAL_STARTING` ثبت می‌شود. هش canonical Viewer، هویت کد افزونه و وضعیت پذیرش سه مفهوم جدا هستند.

دو تغییر فعال‌اند: خواندن بدنهٔ قرارداد پرداخت همراه بررسی یکتایی آن در یک گذر، و مقایسهٔ کامل کلیدهای TEMP بدون تبدیل باینری تکراری. تمام نسخه‌های سراسری، کلید کامل، بدنهٔ مفقود/چندتایی، بازسازی درخواست متأثر و انتشار تراکنشی حفظ می‌شوند. Bloom filter، حذف شاهد، TTL، کش بین commitها، تغییر افق تاریخچه و خواندن موازی فعال نیستند.

## آزمون ایزوله روی سرور

این ابزار فقط به `postgres` و دیتابیس‌های تازه‌ای با نام اختصاصی qualification وصل می‌شود. تنظیم محلی را بدون اجرای فایل پایتون می‌خواند؛ ZIP قبلی Captureها را با هش و proof بررسی می‌کند. اتصال به دیتابیس محصول، توقف Worker و تغییر checkpoint انجام نمی‌دهد. اجرای طولانی آن با بار مشترک سرور تداخل اندازه‌گیری دارد؛ نتیجه، ظرفیت زنده یا فشار کش را ثابت نمی‌کند.

```powershell
cd E:\P24\pishkhan24
$adPython = (Resolve-Path .\.venv\Scripts\python.exe).Path
$captureZip = (Get-ChildItem AnomalyDetection\reports\Viewer_Capacity_Inputs_*.zip | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
& $adPython -B viewer_performance/Qualify_Viewer_Fast.py --project . --captures-zip $captureZip --pairs 2
```

خروجی مورد انتظار `PASS_FAST_EQUIVALENCE` است. هر مرز انتشار، همراه نسخه‌ها، روابط و انتقال‌های معنایی مقایسه می‌شود. زمان initialization، bootstrap، آماده‌سازی، oracle و cleanup جدا در رسید کامل وجود دارد؛ ستون هدف انتشار جای این هزینه‌ها را نمی‌گیرد. پنجرهٔ skipشده ظرفیت انتشار تازه نیست. رسید خصوصی را به Git اضافه نکنید.

## اجرای آزمایشی روی دادهٔ زنده

پیش از تعویض، نسخه و رسید بررسی شوند و اجرای آزمایشی مشخص تأیید شود. AD را پیش از pull تغییرات AD متوقف و سپس با نسخهٔ تأییدشده راه‌اندازی کنید. برای این Writer، schema یا index تازه و تبدیل داده لازم نیست. تنظیمات جلسه از launcher قبلی گرفته می‌شوند و durability و تنظیمات عمومی PostgreSQL حفظ‌اند.

در PowerShell ریشهٔ پروژه، Writer قبلی را متوقف کنید. اگر پاسخ `VIEWER_BACKEND_STOP_PENDING` بود، همان فرمان stop را دوباره اجرا کنید. فقط پس از `VIEWER_WORKER_STOPPED`، `VIEWER_BACKEND_STOPPED` یا `NO_VIEWER_LOCK_OWNER_OBSERVED` ادامه دهید:

```powershell
& $adPython -B viewer_performance/Stop_Viewer_Worker.py --stop
& $adPython -B viewer_performance/Run_Viewer_Fast.py --trial
```

پنجرهٔ دوم را باز نگه دارید. اجرای جدید از replay cursor موجود ادامه می‌دهد و پس از تکمیل به مسیر live قبلی می‌رسد. تاریخ شروع، مرز اول آبان، محدودهٔ AD و پنجره‌های ثبت‌شده تغییر نمی‌کنند. وب مستقل فعلی نیاز به تعویض ندارد.

در ترمینال دیگر، نخست یک مشاهدهٔ واقعی بگیرید؛ حین replay از هدف history استفاده کنید:

```powershell
& $adPython -B AnomalyDetection/validation/observe_viewer_live.py --project . --seconds 3600 --history-windows 12
& $adPython -B AnomalyDetection/run_anomaly.py worker-status
```

این مشاهدهٔ نخست، آزمون هشت‌ساعته نیست. پذیرش ظرفیت، ترافیک پرتراکم، فعالیت وب، سلامت و عقب‌ماندگی مصرف AD باید جدا بررسی شوند. هیچ نرخ تضمینی یا پایان رفع عقب‌ماندگی از آزمون کوتاه استنتاج نشود.

## بازگشت بدون تبدیل داده

Writer آزمایشی را با همان ابزار stop متوقف کنید و سپس این فرمان را اجرا کنید:

```powershell
& $adPython -B viewer_performance/Run_Viewer_Catchup.py --with-anomaly
```

کد، دیتابیس، کلیدهای خصوصی، مدل‌ها، نظر انسانی، شواهد و cursorها را نگه دارید. نیازی به checkout نسخهٔ قدیمی یا حذف داده نیست. آزمون بومی، قطع واقعی در دو سوی commit و ادامه با factory اصلی را کنترل می‌کند. اگر هش کد حین اجرا تغییر کند، Writer پیش از commit متوقف می‌شود؛ خروجی نیمه‌کاره منتشر و cursor جلو برده نمی‌شود.
