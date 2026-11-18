# تحویل نسخهٔ تحلیل رفتار بدون روابط مالی

این سند با تصمیم جاری مالک به‌روز شده است. مبنا، تحویل WIP روی `wip/behavior-scope-handoff-20261117` در `9fc0da43`، بر پایهٔ main برابر `008008aa4fa86951af6d888fd625d67c19364e31` بود. ادامه روی `finish/behavior-scope-20261117` انجام شده است. این کار، PR37 یا ادعای رفع همهٔ مشکلات AD نیست. روی سرور مالک فرمانی اجرا نشده است.

**وضعیت: کاندید بازبینی؛ ظرفیت تاریخچهٔ بزرگ و اجرای عملیاتی هنوز پذیرش ندارند.** buildها `VIEWER-20261117-BEHAVIOR-SCOPE` و `AD-20261117-BEHAVIOR-SCOPE` هستند؛ نام یکسان، جای commit و SHA دقیق manifest را نمی‌گیرد. نصب اولیهٔ WIP مجاز نشده است. راهنمای ادامه/بازگشت [VIEWER_README_FA.md](VIEWER_README_FA.md) و نقشهٔ جاری [Pishkhan24_Project_Roadmap.md](Pishkhan24_Project_Roadmap.md) است.

## قرارداد محصول

- `viewer-full-relations-1` برای دیتابیس قدیمی، تا انتخاب صریح باقی می‌ماند.
- `viewer-behavior-1` روابط مالی تازه نمی‌سازد و closure گروه پرداخت را گسترش نمی‌دهد. خود لاگ پرداخت و مراحل همان RequestID باقی می‌مانند.
- هویت RequestID، پیوستگی معتبر Session، زمان، خدمت، عمل، نتیجهٔ مستقیم API/خدمت، تمام نسخه‌ها و تعارض، شاهد دیررس، Capture قابل‌بازپخش و نظر انسانی حفظ می‌شوند. reset، seek تاریخ جدید، TTL یا حذف raw انجام نمی‌شود.
- `access_session` و `query_parameters_hash` و محورهای همان‌درخواستی `service_dispatch.*` حفظ می‌شوند. service dispatch و OTP، وابستگی رفتاری‌اند؛ نام مالی جدول تاریخی دلیل حذفشان نیست.
- صفحه‌های Request/Action/Session به materialization مالی قدیمی متکی نمی‌مانند. OUT_OF_SCOPE با «پرداخت نشده»، نبود شاهد، رفتار سالم یا نتیجهٔ ناموفق یکسان نیست. نتیجه‌های مستقیم کسب‌وکار و OTP با پاسخ عمومی HTTP جایگزین نمی‌شوند.
- هر دو polling خودکار Viewer حذف شده‌اند. قالب اصلی داشبورد AD بازطراحی نشده است.

## فهرست دقیق ۳۰ خانواده

این فهرست از familyهای Worker و UI استخراج شده است؛ «حفظ» یعنی در دامنه باقی‌مانده، نه اینکه accuracy تولیدی آن پذیرفته شده باشد.

| خانواده | وضعیت | دادهٔ لازم |
|---|---|---|
| `rate_5m` | حفظ | اجرای معنادار و پوشش زمانی |
| `rate_60m` | حفظ | شمارش و پوشش پیوستهٔ یک ساعت |
| `peer_service_rate_5m` | حفظ | اجرای یکتای همان خدمت و مرجع نشست‌های دیگر |
| `continuous_rate` | حفظ | زمان رخداد و عضویت دقیق درخواست |
| `service_mix` | حفظ | ترکیب خدمات مشاهده‌شده |
| `isolation_forest` | حفظ | ویژگی‌های رفتاری؛ محدودیت حساسیت قبلی جداست |
| `service_sequence` | حفظ | ترتیب معتبر خدمات همان Session |
| `timing_regularization` | حفظ | فاصلهٔ زمان رخدادها |
| `business_result_change` | حفظ | نتیجهٔ صریح همان خدمت/درخواست |
| `request_latency` | حفظ | فاصلهٔ اولین تا آخرین شاهد؛ زمان قطعی HTTP نیست |
| `otp_result_change` | حفظ | کد صریح OTP همان RequestID |
| `input_subject_burst` | حفظ | موضوع مستقیم ورودی با شاهد معتبر |
| `repeated_target` | حفظ | تکرار موضوع مستقیم یا اثر ورودی |
| `subject_enumeration` | حفظ | تنوع موضوع مستقیم ورودی |
| `client_ip_rotation` | حفظ | IP سمت مشتری زیر همان Session |
| `service_traversal` | حفظ | خدمات مشاهده‌شدهٔ همان نشست |
| `workflow_change` | حفظ | مراحل واقعی همان RequestID، بدون اتصال مالی |
| `service_workflow_change` | حفظ | مراحل همان درخواست در نمونهٔ مستقل خدمت |
| `response_schema_change` | حفظ | ساختار پاسخ مشاهده‌شده |
| `response_content_change` | حفظ | محتوای پاسخ مشاهده‌شده |
| `service_volume` | حفظ | census حجم خدمت و پوشش منبع |
| `multi_session_service` | حفظ | حجم و نشست‌های همان خدمت |
| `multi_session_target` | حفظ | موضوع مستقیم مشترک؛ هویت اشخاص استنتاج نمی‌شود |
| `service_population` | حفظ | الگوی جمعی حجم/نشست در خدمت و سامانه |
| `service_health` | حفظ | نتیجهٔ ناموفق صریح و هم‌دامنه |
| `long_subject_enumeration` | حفظ | تجمیع موضوع مستقیم در ساعت‌ها و روزها |
| `long_client_ip_rotation` | حفظ | IPهای مشتری در بازهٔ بلند همان نشست |
| `payment_result_change` | OUT_OF_SCOPE | نتیجهٔ پرداختِ متصل به زنجیره |
| `typed_target_diversity` | OUT_OF_SCOPE | تنوع مراجع وابسته مثل فاکتور/آیتم؛ موضوع مستقیم نیست |
| `journey_profile_change` | OUT_OF_SCOPE | شکل سفر مرتبط و بازسازی‌شده |

روش، baseline و آستانهٔ ۲۷ خانواده برای سبزشدن آزمون تغییر نکرده‌اند. باقی‌ماندن در دامنه، کامل‌بودن داده/آموزش، نتیجهٔ مثبت یا پذیرش precision/recall را ثابت نمی‌کند.

## اصلاحات پس از تحویل اولیه

1. مسیر import کنترلر، `sys.path` را دائمی تغییر نمی‌دهد؛ دو شکست واقعی multiprocessing ناشی از تداخل `tests` ریشه و AD رفع شدند. دسترسی موقت تعمیر نیز در finally برمی‌گردد.
2. هویت و **تمام ارجاع‌های والد/فرزند** مدل رفتاری به namespace پایدار `bm1:` می‌روند. مدل موضوع ورودی دیگر به شناسهٔ fullِ حذف‌نشده اما نامتناسب یا به receipt ناموجود اشاره نمی‌کند. مدل اصلی از تاریخچه حذف نمی‌شود.
3. تغییر قرارداد در epoch یکسان و عقب‌رفتن epoch رد می‌شوند. هنگام بازگشت به full، ارزیابی مالی قبلی خودکار current نمی‌شود. requalification با cursor پایدار و صفحهٔ محدود انجام می‌شود؛ facts و journeys مالی قدیمی تا ممیزی epoch تازه، مرجع جاری نیستند. مدل، بازخورد و cursor منبع محفوظ‌اند.
4. drilldown، خروجی ممیزی و پوشش، قرارداد جاری/تاریخی و OUT_OF_SCOPE را تفکیک می‌کنند. export رفتاری، روابط/journey مالی را به‌عنوان خروجی جاری صادر نمی‌کند؛ receiptهای تاریخی با توضیح قرارداد محفوظ‌اند.
5. آماده‌سازی نصب، gateهای فرایند/Task پس از disable، پایان commit، sessionهای PG و Action/source بازگشت را اجرا می‌کند. prepare پیش از تغییر tracked source و با helper نصب‌شدهٔ قدیمی است. فقط commit کاملِ تأییدشده و موجود در origin/main قابل انتخاب است.
6. کنترلر طولانی از timeout ثابت ۹۰ثانیه استفاده نمی‌کند. فایل پیشرفت و لغو پایدار دارد؛ لغو SQL روی اتصال خود و هویت handle فرزند واقعی Windows بررسی می‌شود. بازگشت مالی، rawها و closureهای درخواست را در batchهای قابل‌ادامه بازسازی می‌کند. قطع واقعی وسط repair، READY منتشر نمی‌کند. در RESTORING_FULL، Worker/Taskها شروع نمی‌شوند.
7. نام کپی پیش از CREATE در رسید ثبت می‌شود؛ OID و tag مالکیت پس از موفقیت پین می‌شوند. بازیابی فقط همان کپی را حذف می‌کند. قطع در فاصلهٔ نامعلوم CREATE/ثبت مالکیت، عمداً نیازمند بررسی می‌ماند؛ کپی احتمالی با حدس DROP نمی‌شود. نبود session، مهلت CREATE/cleanup، حافظه و فضای capture/copy/oracle نیز کنترل می‌شوند.
8. benchmark جدید تمام ردیف‌های رفتار، actions با نتیجهٔ مستقیم، session heads، provenance و تمام جدول‌های AD را برای correctness reconcile می‌کند؛ صرفاً scope متأثر را نمونه‌برداری نمی‌کند. archives مالی/انسانیِ رفتار باید بدون تغییر بمانند. زمان درج نقش خودکار و import از زمان رخداد تفکیک می‌شود؛ زمان و سابقهٔ بازبینی انسانی حذف نمی‌شوند.
9. ظرفیت، چهار کپی جدا با ترتیب full/behavior/behavior/full دارد؛ oracle داخل آن نیست. در تاریخچهٔ در حال replay، همان HistoryReplay.advance پیش از commit انتشار اجرا و prefix پس از commit بررسی می‌شود؛ این هزینه از زمان ظرفیت حذف نشده است. ورودی قبلاً منتشرشده یا Capture واردشده و انتشار بدون شاهد تازه رد می‌شوند. codec WAL از قابلیت واقعی همان PostgreSQL انتخاب و در هر دو مسیر یکسان ثبت می‌شود؛ تنظیم عمومی/دوام تغییر نمی‌کند.
10. helper manifest فقط ورودی‌های عمومیِ صریحاً tracked/staged را می‌پذیرد؛ فایل محلیِ untracked، گزارش و دادهٔ خصوصی خودکار وارد inventory نمی‌شوند.

## آزمون و مرز ادعا

پیش از اصلاح، مجموعهٔ پایهٔ AD: ۳۵۸ تست موفق. مجموعهٔ پایهٔ Viewer/maintenance: ۸۶ تست، سه شکست و شش مورد Windows اجرا‌نشده. دو شکست مربوط به import و دیگری codec ناموجود zstd در PostgreSQL آزمایشی بود؛ هیچ آستانه یا oracle برای عبور تغییر نکرد.

آزمون نهایی محلی روی PostgreSQL 18.6: مجموعهٔ Viewer/maintenance شامل ۱۰۱ تست، ۹۳ PASS و ۸ مورد Windows اجرا‌نشده بود. مجموعهٔ کامل AD، هر ۳۶۱ تست را با موفقیت اجرا کرد. qualification کپی فیزیکی و بازیابی نیز ۶ تست موفق داشت؛ شامل جلو رفتن Checkpoint بازپخش داخل همان تراکنش انتشار در تمام کپی‌ها و ثابت ماندن منبع. مجموعهٔ رگرسیون بدون PG، ۱۶۱ تست با ۴۵ skipِ محیطی موفق داشت؛ skip به معنی native PASS نیست. نتیجهٔ Windows و Linux CI باید از checks همان commit خوانده شود؛ اعداد جمع زده نمی‌شوند چون بعضی fixtureها/مجموعه‌ها هم‌پوشانی دارند.

آزمون کپیِ واقعیِ دیتابیس **مصنوعی** شامل برابری کل تاریخچهٔ حفظ‌شده، چهار lane ظرفیت، نبود تغییر دیتابیس template، قطع فرایند پس از tag و recovery، session فعال و cancellation واقعی SQL موفق بوده است. این qualification ابزار است؛ زمان آن به دیتابیس بزرگ مالک تعمیم داده نمی‌شود. در CI دارای PostgreSQL داخل Docker، مسیر فضای دیسکِ کلاینت فقط برای template آزمایشی و با برچسب صریح استفاده می‌شود؛ فضای واقعی volume سرور را تأیید نمی‌کند. مسیر محصول همیشه باید data_directory واقعی و قابل‌دسترسیِ همان سرور محلی باشد.

Windows CI شامل parser واقعی PowerShell، process handle واقعی و ارتقا/شکست/بازیابی با Git و PowerShell واقعی و کنترلر مصنوعی است. این مورد، PostgreSQL بومی Windows یا توقف/بازیابی سرویس‌های واقعی مالک نیست. نتیجهٔ CI اجرا‌نشده NOT_RUN می‌ماند.

**باز هستند:** برابری روی کپی تاریخچهٔ بزرگ مالک و ورودی تازهٔ واقعی، پذیرش سرعت و سهم ذخیره‌سازی آن، PostgreSQL بومی Windows، آزمون هم‌زمان با AD/وب و تازگی/رشد backlog، و دقت مستقل تمام خانواده‌ها. دادهٔ کافی، نبود آنومالی و علت خطاهای قبلی از تست مصنوعی نتیجه نمی‌شوند. برای این gateها ابتدا باید نسخه و برنامهٔ دقیق زمان توقف بازبینی و تأیید شوند؛ اکنون دستور زنده‌ای لازم نیست.

فرمان بازتولید در PostgreSQL 18 کاملاً آزمایشی:

```bash
python -B -m unittest -v tests.test_viewer_behavior_scope tests.test_viewer_behavior_pg tests.test_viewer_service_dispatch tests.test_viewer_financial_screen tests.test_financial_maintenance tests.test_behavior_release tests.test_behavior_benchmark_pg
cd AnomalyDetection
python -B -m unittest discover -s tests -q
```

`P24_DELTA_PG_HOST/PORT/USER` فقط باید به cluster آزمایشی اشاره کنند. source حین آزمون تغییر نکند. بعد از تثبیت source، `Refresh_Behavior_Manifests.py` پین‌ها را تازه می‌کند؛ این helper پذیرش محصول نیست. گزارش‌های خصوصی مالک و رمز/Session خام داخل مخزن قرار نگرفته‌اند.
