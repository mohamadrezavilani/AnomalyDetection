# اجرای Viewer و AD با قرارداد رفتاری

این راهنما مربوط به کاندید `VIEWER-20261117-BEHAVIOR-SCOPE` و `AD-20261119-BEHAVIOR-RECOVERY` است؛ هویت دقیق را از commit و manifest بخوانید. قابلیت محصول تغییر کرده است: رفتارهای مشاهده‌شده حفظ می‌شوند و روابط مالی ساخته یا تحلیل نمی‌شوند. دیتابیس قدیمی تا انتخاب صریح، full باقی می‌ماند. این کاندید هنوز پذیرش ظرفیتِ تاریخچهٔ بزرگ و اجرای عملیاتی ندارد؛ اکنون روی سرور نصب نشود.

جزئیات دامنه و آزمون‌ها در [BEHAVIOR_SCOPE_HANDOFF_FA.md](BEHAVIOR_SCOPE_HANDOFF_FA.md) آمده است. نصب مستقیم شاخهٔ تحویل اولیه یا pull پیش از توقف سرویس‌ها روش ارتقا نیست.

## ارتقا پس از بازبینی و تعیین زمان آزمون مالک

فایل `viewer_performance/Install_Behavior.ps1` را از commit بازبینی‌شده بیرون از checkout جاری ذخیره کنید. اسکریپت را با `powershell.exe -File` اجرا کنید، نه dot-source در یک shell ناشناخته. مسیر پروژه و SHA کامل چهل‌کاراکتریِ نسخهٔ تأییدشده و مرج‌شده به origin/main الزامی‌اند. نمونهٔ زیر الگو است؛ مقدار `APPROVED_40_HEX_COMMIT` باید با commit واقعیِ تأییدشده جایگزین شود:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\P24_Tools\Install_Behavior.ps1 -Project E:\P24\pishkhan24 -TargetCommit APPROVED_40_HEX_COMMIT -ReviewedPreflight E:\P24\pishkhan24\AnomalyDetection\reports\preflight_to_send.json
```

پیش‌بررسیِ خصوصی باید طرح بازگشت frontend، Task و نقش‌های فعلی را به‌طور مشخص تأیید کند. اسکریپت ابتدا با helperهای نصب‌شدهٔ قدیمی، supervisorها را غیرفعال، AD را متوقف و پایان commit جاری Viewer را fence می‌کند؛ سپس Writer/وب/frontend بازبینی‌شده را می‌بندد و نبود session و پردازش باقیمانده را بررسی می‌کند. کد فقط پس از آن fast-forward می‌شود. کار نیمه‌کاره به معنی اجازهٔ توقف کور یا شروع دستی watchdog نیست.

بررسی Git اکنون `git-precheck.json` را پیش از توقف و `git-frozen-check.json` را پس از توقف ثبت می‌کند؛ نام و وضعیت تمام فایل‌های مانع و خطای فرمان Git در خروجی‌اند. تنها تغییرِ unstaged در گزارش تولیدشدهٔ `validation/viewer_startup.json`، با قرارداد معتبر و یکسان‌بودن blob در HEAD، index و نسخهٔ مقصد، مجاز است. بایت‌های آن با SHA در پوشهٔ خصوصی نصب حفظ می‌شوند و خود فایل بازنشانی نمی‌شود. تغییر کد، تغییر staged، حذف/تغییرنام و هر فایل دیگر همچنان مانع‌اند؛ هشدار عمومی بدون نام فایل یا پاک‌کردن کور تغییرها روش ادامه نیست.

حالت پیش‌فرض benchmark و سپس انتخاب behavior است. PostgreSQL روشن و durability حفظ می‌شوند. از تاریخچهٔ واقعی کپی‌های مجزا و از پنجره‌های مفقود بعدی Capture یکسان تهیه می‌شود. correctness و ظرفیت جدا هستند؛ تنها کپی‌های دارای رسید مالکیت قابل پاک‌سازی‌اند. دادهٔ اصلی، کلیدها و checkpoint جابه‌جا نمی‌شوند. چهار پنجره، نمایندگی تمام بار یا cache سرد را اثبات نمی‌کنند.

`-SkipBenchmark` فقط برای اجرای بعدی با qualification معتبر و منطبق با همین کد/داده است؛ محدودیت آزمون قبلی روی دیتابیس تازه را رفع نمی‌کند. اسکریپت source را فقط در شکست **پیش از شروع تغییر scope و پیش از بازیابی نقش‌ها** با `git reset --keep` برمی‌گرداند؛ ویرایش هم‌زمان و فایل خصوصی نادیده گرفته نمی‌شوند. پس از شروع تغییر scope، checkout قدیمی روش rollback نیست.

## ادامه از وضعیت موجود و بازگشت

شروعِ تاریخ، floor، کلیدها، stream، cursor تاریخی و live تغییر نمی‌کنند. فقط همان نقش‌هایی که پیش از توقف فعال بوده‌اند طبق restore plan بازگردانده می‌شوند. پیام موفقیت نصب باید با scope READY، source identity، سلامت واقعی و بازیابی همان Task/Action همراه باشد.

برای بازگشت مالی، پس از freeze معتبر همان نصب‌کننده با `-RestoreFull` و commit تأییدشده اجرا می‌شود. بازگشت با کد سازگار جدید انجام می‌شود: SQL links از نسخه‌های raw نگه‌داشته‌شده، سپس closureهای دقیق درخواست در batchهای قابل‌ادامه بازسازی می‌شوند. انتشار نهاییِ full فقط پس از اتمام همهٔ batchها انجام می‌شود. این عملیات ممکن است طولانی باشد؛ سقف ثابت ۹۰ ثانیه ندارد. `-MaxSeconds` بودجهٔ صریح آن است، نه زمان تضمین‌شدهٔ تکمیل.

شکست یا قطع بازسازی، `RESTORING_FULL` و رسید پیشرفت را حفظ می‌کند و Worker/Taskها خودکار شروع نمی‌شوند. با همان release.json و کد تأییدشده یکی از اقدام‌های صریح زیر انتخاب می‌شود:

```powershell
# ادامهٔ همان بازسازیِ متوقف‌شده:
.\.venv\Scripts\python.exe -B viewer_performance/Behavior_Release.py --project . --receipt PATH_TO_RELEASE_JSON --action resume-rollback --max-seconds 43200
# یا بازگشت صریح به رفتار و سپس بازیابی نقش‌های قبلی:
.\.venv\Scripts\python.exe -B viewer_performance/Behavior_Release.py --project . --receipt PATH_TO_RELEASE_JSON --action enable-after-repair
```

اگر cleanup کپی متوقف شد، `--action cleanup-copies` با همان release.json فقط OID و tag منطبق با allocations.json را می‌پذیرد. کپی مبهم، session باقیمانده یا تغییر مالکیت پاک نمی‌شود؛ DROP FORCE و کشتن پردازش ناشناس راه بازیابی نیستند. رسید را بفرستید.

## مشاهدهٔ جدا همراه وب و AD

پس از بازیابی نقش‌ها و انتخاب رفتار، آزمون هم‌زمان مستقل لازم است:

```powershell
cd E:\P24\pishkhan24
.\.venv\Scripts\python.exe -B viewer_performance/Observe_Viewer_Fast.py --project . --seconds 28800
.\.venv\Scripts\python.exe -B AnomalyDetection/run_anomaly.py acceptance-report --seconds 60
```

این فرمان‌ها اکنون مجوز اجرای زنده نیستند. گزارش `release.json`، `benchmark.json`، `allocations.json` و `scope-progress.json` به‌همراه JSON مشاهده‌گر و ZIP acceptance برای بررسی لازم‌اند و خصوصی می‌مانند. pendingِ cacheشده با timestamp خودش تفسیر می‌شود؛ از آن به‌تنهایی نبود رشد backlog نتیجه نمی‌گیریم. هویت Worker، صف تازه در ابتدا/انتها، آخرین پنجرهٔ کامل Viewer/AD و خطاها باید منطبق باشند. هشت ساعت پذیرش ظرفیتِ قبولیافته از برنامه استخراج نمی‌شود؛ باید شاهد واقعی آن بررسی شود.
