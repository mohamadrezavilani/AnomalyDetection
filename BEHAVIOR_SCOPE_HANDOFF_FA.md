# تحویل توسعهٔ نسخهٔ رفتاری — ۱۷ نوامبر ۲۰۲۶

**وضعیت: WIP؛ برای نصب، مرج به main یا ادعای سرعت آماده نیست.** مالک خواسته توسعه در این نقطه روی شاخه ثبت شود تا ایجنت مدیر ادامه دهد. هیچ تغییری روی اجرای زنده اعمال نشده است. تمام اطلاعات سرور و رسیدهای واقعی خصوصی مانده‌اند؛ داخل مخزن نیستند.

## مبنا و تصمیم جدید مالک

- مبنای remote main: `008008aa4fa86951af6d888fd625d67c19364e31`، tree برابر `85de0c6909eb1728ccc044ad111fae217ea810b9`.
- شاخهٔ تحویل: `wip/behavior-scope-handoff-20261117`؛ main برای این تحویل تغییر نمی‌کند.
- Git محلی محیط قبلی commitهای متفاوت از API داشت، ولی tree مبنا دقیقاً برابر بود. برای بررسی تغییرات، با main فوق مقایسه کنید.
- نیاز نسخهٔ جدید: آنومالی بر اساس رفتار مشاهده‌شده کافی است. بازسازی روابط استعلام/فاکتور/پرداخت/خدمت و تحلیل وابسته حذف شود؛ خود لاگ پرداخت مثل سایر لاگ‌ها بماند.
- حفظ RequestID، Session معتبر، خدمت/عمل/زمان/نتیجهٔ مشاهده‌شده، شواهد خام، تکرار/نسخه/تعارض، دیررس، اصلاح سابقه و بازخورد انسانی الزامی است. TTL حدسی، حذف شواهد، reset کل AD و seek تاریخ جدید مجاز نیست.
- رفرش خودکار سایت باید خاموش باشد. قالب اصلی داشبورد آنومالی حفظ شود.
- غربال قبلی روی Capture واقعی در دیتابیس تازه کامل شده بود؛ برای پذیرش سرعت روی تاریخچهٔ بزرگ کافی نیست. نتایج خام نزد مالک است. هیچ سرعتی از آن به محصول تعمیم داده نشود.

## تغییرات موجود در این snapshot

### Viewer

`p24_foundation/viewer_product_scope.py` قرارداد پایدار `viewer-full-relations-1` و `viewer-behavior-1` را اضافه می‌کند. دیتابیس قدیمی به‌صورت پیش‌فرض full باقی می‌ماند. انتخاب رفتار باید صریح، زیر lease و با Workerهای متوقف انجام شود. جدول‌های scope، تاریخچهٔ تغییر scope و قرارداد هر generation افزوده شده‌اند؛ cursor یا شواهد پاک نمی‌شوند.

در حالت رفتاری:

- `affected_closure` فقط درخواست‌های مستقیم واقعاً متأثر را برمی‌گرداند؛ شامل صاحبان قبلی origin متعارض که خود ingest ثبت می‌کند. گسترش گروه پرداخت حذف می‌شود.
- SQL linkهای مالی تازه نوشته نمی‌شوند؛ `access_session` برای صحت هویت و `query_parameters_hash` برای موضوع مستقیم ورودی حفظ می‌شوند. این دو وابستگی رفتاری‌اند و نباید همراه روابط مالی حذف شوند.
- raw/event/capture و بررسی تمام نسخه‌های origin همان مسیر قبلی را دارند.
- `_rebuild_requests` هویت، root، تعارض، نقش، action و نتیجهٔ مشاهده‌شده را حفظ می‌کند؛ payment index، workflow و نتیجهٔ حاصل از اتصال پرداخت ساخته نمی‌شوند. تاریخچهٔ قدیمی actionهای مالی در این حالت بازنویسی نمی‌شود.
- `rebuild_payment_contract` در حالت رفتار از استخراج و ساخت روابط مالی عبور می‌کند، ولی `reconcile_service_dispatches` را نگه می‌دارد.
- نکتهٔ مهم کشف‌شده: **service dispatch و OTP به محورهای `service_dispatch.*` در جدول تاریخی `viewer_contract_observations` وابسته‌اند**. اسم جدول مالی است، اما این بخش برای تشخیص خدمت واقعی InvoiceRegister لازم است. این facts از همان نسخهٔ raw تازه، هنگام ingest و فقط برای callpathهای مشخص استخراج می‌شوند. از invoice برای اتصال درخواست‌ها استفاده نمی‌شود.
- جزئیات Viewer از خواندن materialization مالی قدیمی عبور می‌کنند و «خارج از دامنه» نشان می‌دهند. بخش ثبت مراحل همان درخواست باقی می‌ماند.
- هر دو polling خودکار ۵ و ۳۰ ثانیه از `review_ui/static/viewer_live.js` حذف شده‌اند. متن banner دستی شده است.

### AD

`AnomalyDetection/anomaly_detection/behavior_scope.py` قرارداد ورودی، سازگاری سابقه، projection روی facts قدیمی و انتقال scope را تعریف می‌کند.

سه خانوادهٔ حذف‌شده:

| family | علت |
|---|---|
| `payment_result_change` | بر نتیجهٔ پرداخت‌های متصل به زنجیره متکی است |
| `typed_target_diversity` | از typed identifierهای روابط، مانند فاکتور و آیتم، استفاده می‌کند |
| `journey_profile_change` | شکل سفر بازسازی‌شدهٔ مرتبط را مصرف می‌کند |

این موارد `OUT_OF_SCOPE` هستند؛ نه `NO_DEVIATION_OBSERVED`، شکست پرداخت یا کمبود تصادفی داده. خواندن journey/مالی در lane مربوط AD خاموش شده است. Snapshot مالی/identifier/edge دریافت نمی‌کند؛ فقط observations مشترک service dispatch باقی می‌مانند. facts قدیمی هنگام مصرف projection می‌شوند، نه اینکه از تاریخچه حذف شوند.

خانواده‌های مستقل حفظ شده‌اند: نرخ ۵ دقیقه/یک ساعت، نرخ مرجع خدمت و نرخ پیوسته، ترکیب خدمات، Isolation Forest، توالی و ریتم زمانی، نتیجهٔ تجاری گزارش‌شده، فاصلهٔ شواهد درخواست، نتیجهٔ OTP؛ سناریوهای تکرار موضوع/تنوع موضوع ورودی، تغییر IP، تغییر مسیر مشاهده‌شدهٔ همان درخواست، ساختار/محتوای پاسخ، سلامت خدمت، حجم/جمعیت خدمت و سناریوهای بلندمدت مبتنی بر پروفایل مستقیم. این فهرست باید در بازبینی نهایی dependencyها دوباره تأیید شود؛ کیفیت و آستانه‌های روش‌ها تغییر نکرده‌اند و دقت کامل محصول ادعا نشده است.

- namespace و کلید پرونده/RequestID عوض نمی‌شوند. state مربوط به input contract و epoch افزوده شده است.
- مدل‌های رفتاری قرارداد feature مشترک دارند؛ receipt جدید مدل با پیشوند `bm1:` از مدل قبلی جدا می‌شود و سازگاری سابقهٔ full/behavior صریح است.
- یافته‌های مالی فعال به خارج از دامنه می‌روند؛ نسخهٔ قبلی، مدل و نظر انسانی نگه داشته می‌شوند. `case_summary` برای جلوگیری از نمایش آنها به‌عنوان عادی یا بازبینی ناقص bucket جدا دارد.
- قرارداد جدید Viewer در `source_profiles.py` با `R311_RUNTIME` و شمار فایل دقیق پین می‌شود؛ pin قبلی R310 نیز حفظ شده است.
- buildهای درحال‌توسعه: `AD-20261117-BEHAVIOR-SCOPE` و `VIEWER-20261117-BEHAVIOR-SCOPE`. صرف وجود این نام‌ها، پذیرش نسخه نیست.

### ابزار ارتقا و benchmark — هنوز نمونهٔ اولیه

- `Behavior_Control.py`: enable صریح و بازسازی data-preserving برای restore-full. rollback مالی از rawهای نگه‌داشته‌شده links و projections را دوباره می‌سازد؛ ارزان و صرفاً git checkout نیست. شکست repair باید `RESTORING_FULL` باقی بگذارد. ادامهٔ behavior پس از repair ناقص نیز نیازمند بازبینی است.
- `Behavior_Release.py` و `Install_Behavior.ps1`: طرح توقف با ابزار قدیمی **پیش از pull**، دریافت main، انتخاب scope و بازگرداندن نقش‌ها/Taskهای قبلاً فعال. controller مرحلهٔ prepare می‌تواند از stdin با `--project` صریح اجرا شود. این مسیر هنوز native Windows اجرا نشده است.
- `behavior_benchmark.py`: طرح مقایسه روی `CREATE DATABASE ... TEMPLATE ... STRATEGY FILE_COPY` از دیتابیس واقعیِ متوقف. cloneها UUIDدار و تنها ساخته‌های همین اجرا قابل DROP هستند؛ محصول هدف انتشار یا DDL نیست. PG روشن و durability حفظ می‌شود.
- ورودی آزمون از پنجره‌های مفقود بعدی، یک بار از ES گرفته می‌شود. پنجرهٔ قبلاً منتشرشده، Capture قبلاً imported و انتشار بدون شاهد جدید برای ورودی غیرخالی رد می‌شوند.
- correctness و capacity cloneهای جدا دارند؛ دو ترتیب full/behavior و behavior/full در ظرفیت. oracle روی همهٔ ردیف‌های scope متأثر و نسخه‌های origin در هر مرز است؛ پیمایش oracle داخل capacity نیست. این oracle فعلاً دامنهٔ متأثر را می‌سنجد، نه preservation کامل کل کپی را.
- هزینهٔ capture، کپی، setup/run/drop، commit، final COPY/INSERT، شمارنده‌های همان backend، انتظارها و منابع جدا گزارش می‌شوند. cache سرد و کارکرد همزمان وب/AD با این آزمون تأیید نمی‌شود.
- `financial_screen.experiment.run_lane` برای clone موجود و oracle مرزی اختیاری توسعه یافته است؛ `Sampler` سقف اندازهٔ configurable برای دیتابیس بزرگ دارد.

## آزمون‌های واقعاً اجراشده

این نتایج مربوط به revisionهای میانی این WIP هستند، **نه تأیید نهایی تمام bytes این snapshot**:

1. سه آزمون SQLite رفتار/دیررس/تعارض، rollback قبل از commit و رفرش دستی: PASS.
2. مجموعهٔ native Viewer/dispatch/financial-screen/maintenance: ۶۸ آزمون، PASS، شش مورد اختصاصی Windows skipped.
3. آزمون native رفتار، استخراج service dispatch، kill واقعی قبل از commit و retry و بازگشت مالی: PASS. بعداً حالت kill بعد از commit به همان تست افزوده شد و این افزوده هنوز اجرا نشده است.
4. مجموعهٔ AD: ۳۵۷ آزمون اجرا شد، یک خطا در adapter قدیمیِ تست که `Store.state` نداشت. compatibility در cases اصلاح شد؛ suite کامل پس از آن دوباره اجرا نشده است.
5. اجرای هدفمند AD پس از اصلاح: شش آزمون PASS؛ شامل انتقال scope روی PostgreSQL، وضعیت OUT_OF_SCOPE پرونده/یافته، حفظ مدل/بازخورد/cursor و oracle روش‌های باقی‌مانده.
6. چند تغییر آخر (کاهش SQL داخل حلقهٔ details، محدودکردن extraction به callpathهای لازم، publication-contract ledger و افزودهٔ crash پس از commit) فقط compile شده‌اند؛ native regression نهایی لازم است.
7. Windows controller/PowerShell installer، benchmark واقعی دیتابیس بزرگ، آزمون وب/AD همزمان و پذیرش ظرفیت: **NOT_RUN**.

## موانع و قدم بعدی؛ پیش از هر نصب رفع شوند

1. ابتدا کل diff را به‌عنوان WIP بازبینی کنید، سپس suiteهای بالا را روی bytes ثابت اجرا کنید. تنها یک benchmark/cluster آزمایشی همزمان فعال باشد. هیچ oracle ضعیف یا detector threshold برای سبزشدن تست تغییر نکند.
2. مسیر upgrade هنوز lifecycle کامل و آزمودهٔ `financial_screen.host.maintenance` را به‌طور کامل reuse نکرده است. بررسی برگشت process/Task پس از disable، باقی‌ماندن sessionهای PostgreSQL و صحت همان Action/sourceهای supervisor باید با gateهای همان کد یکسان و تست شود؛ خاموش‌کردن کنترل‌ها راه‌حل نیست.
3. **rollback طولانی نباید از `host.command` با timeout ثابت ۹۰ ثانیه اجرا شود.** `Behavior_Release` فعلی این مشکل را دارد؛ کنترلر باید فرمان طولانی را با log/progress پایدار و کنترل cancellation اجرا کند. بعد از شکست، فعال‌سازی Worker روی RESTORING_FULL نباید ظاهراً موفق اعلام شود.
4. مسیر نصب از FETCH_HEAD به main نوشته شده بود. اکنون این کد فقط روی WIP است؛ تا تأیید و merge مدیر، فرمان نصب فعلی را به مالک ندهید. منطق upgrade از نسخهٔ قدیمی و بازیابی شکست وسط pull باید روی Windows واقعاً آزموده شود.
5. benchmark بزرگ هنوز اجرا نشده و خودش تست یکپارچه ندارد. ابتدا clone/setup/cleanup، نبود session روی template، ثبت مالکیت allocation، خرابی یا قطع هنگام COPY/CREATE و cleanup بعد از آن را روی DBهای کاملاً ایزوله qualify کنید.
6. بودجهٔ زمانی CREATE DATABASE/cleanup و capture/key-extraction پیش از Sampler هنوز به اندازهٔ laneها پوشش ندارد. SQL copy و آماده‌سازی کلاینت ممکن است از بودجه بگذرند؛ حدود حافظه، فضا، timeout و رسید allocation ناقص باید تکمیل شوند. cache پس از کپی کنترل‌شده فرض نشود.
7. oracle بزرگ و مجموعهٔ scope RequestIDهای قبلی/تازه را بازبینی کنید؛ actions و session heads/بازخورد انسانیِ حفظ‌شده و تغییرهای خارج scope باید reconciliation روشن داشته باشند. حتماً پنجره‌های تازه را با همان ورودی و initial state مقایسه کنید، نه replay تکراری را با fresh publication.
8. در AD، نمایش نسخهٔ قرارداد برای evaluation/model/case قدیمی و جدید، غیرفعال‌بودن تمام مصرف‌های مالی (از جمله drilldown و export) و مسیر full-after-behavior را کامل بررسی کنید. مدل‌های مالی و jobs آنها در بازگشت نباید به‌اشتباه current اعلام شوند؛ مدل/feedback قدیمی پاک نشود.
9. صفحات درخواست/نشست قدیمی را از نظر outcome/target مالی cacheشده بازبینی کنید. پوشش OUT_OF_SCOPE نباید به «پرداخت نشده» یا «داده ناقص» تبدیل شود. UI اصلی آنومالی را بازطراحی نکنید.
10. پس از عبور از qualification، آزمون بزرگ در بازهٔ اختصاصی مالک، با توقف و بازیابی supervisorهای قبلاً بازبینی‌شده اجرا شود. سپس آزمون جدا همراه Viewer، AD و وب، اندازه‌گیری تازگی AD و رشد/کاهش صف لازم است. اگر ذخیره‌سازی همچنان غالب بود، تغییر بعدی از همان سهم هزینه انتخاب شود.

## ادامهٔ کار و manifestها

راهنماهای جاری `VIEWER_README_FA.md`، `AnomalyDetection/PROJECT_MAP_FA.md` و `FINANCIAL_SCOPE_FA.md` هنوز به‌طور کامل برای محصول جدید بازنویسی نشده‌اند؛ بعد از تثبیت کد هماهنگ شوند. بخش مالی قدیمی Roadmap سند تاریخی است، نه نیاز جدید مالک.

`viewer_performance/Refresh_Behavior_Manifests.py` نسخهٔ قابل‌دسترسی helper این WIP است؛ از مسیر خودش root را پیدا می‌کند و دیتابیس باز نمی‌کند. بعد از پایان تغییر source و پیش از تست نسخه اجرا شود. digest canonical runtime، R311/count دقیق، pin ابزارهای capacity، inventory/digest دقیق AD، سپس Fast/Capacity و root manifest را تازه می‌کند. آن را بازبینی کنید؛ helper اثبات صحت یا مجوز انتشار نیست و root release_status را WIP می‌گذارد. هنگام آزمون source را دوباره تغییر ندهید.

فرمان‌های پایه برای محیط دارای PostgreSQL 18 آزمایشی (متغیرهای `P24_DELTA_PG_HOST/PORT/USER` فقط به همان cluster ایزوله اشاره کنند):

```bash
python -B viewer_performance/Refresh_Behavior_Manifests.py
python -B -m unittest -v tests.test_viewer_behavior_scope tests.test_viewer_behavior_pg tests.test_viewer_service_dispatch tests.test_viewer_financial_screen tests.test_financial_maintenance
cd AnomalyDetection
python -B -m unittest discover -s tests -q
```

برای سرور مالک اکنون دستور تازه‌ای لازم نیست. سرویس‌های او طبق آخرین رسید خصوصی بازیابی شده بودند. این شاخه را روی سرور نصب نکنید؛ مدیر باید پس از رفع موانع، نسخه و دستور دقیق نصب/بازیابی و نتایج واقعی را تحویل بدهد.
