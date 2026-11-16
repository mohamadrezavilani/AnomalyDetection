# قرارداد ابزار qualification ظرفیت Viewer

## C4: پیش‌خوانی محدود قبل از درج و سنجش مستقل

`index_prefetch_1/2/4` فقط در subclass دیتابیس تازهٔ qualification فعال‌اند و مبنا C3 است. هر reader یک اتصال READ ONLY با timeout سه‌ثانیه‌ای دارد؛ حداکثر چهار task با ۱۲۸ جفت کلید و مهلت بیست‌ثانیه‌ای برای هر جدول وجود دارد. نتیجهٔ probe فقط EXPLAIN/BUFFERS همان اتصال است و در تصمیم داده استفاده نمی‌شود. Origin/Version، COPY/INSERT اصلی، مالک تراکنش، ترتیب پنج‌دقیقه‌ای و بازسازی عادی/دیررس عوض نمی‌شوند. خطای hint یا پایان مهلت از خواندن معتبر مسیر اصلی جلوگیری نمی‌کند. تمام زمان helper و انتظارش داخل مرحلهٔ درج و زمان تا قرارداد ثبت می‌شود؛ مجموع زمان readerهای هم‌زمان با wall time یا هزینهٔ Writer یکی نیست.

برای هر تعداد reader، `python -B -m viewer_performance.capacity.baseline --backend postgresql --counts 32 256 2048 --pairs 2 --experiment index_prefetch_2 --wal-compression zstd --out qualification/index-prefetch-2.json` اجرا شود. مقدار experiment به ۱ و ۴ هم تغییر کند. مبنا و نامزد روی همان ورودی و ترتیب A/B و B/A مقایسه می‌شوند. این آزمایش مصنوعی کوچک، فشار کش مؤثر را ثابت نمی‌کند و نتیجهٔ سریع‌تر یا کندتر آن به سرور تعمیم داده نمی‌شود. نامزد گرم کندتر، مجوز عرضه ندارد؛ بهبود در خواندن منفرد نیز پذیرش ظرفیت نیست.

تصمیم آزمون مصنوعی بومی در `validation/viewer_index_prefetch_synthetic.json` ثبت است: هر ۳۰ تطبیق مرزی برابر بود، ولی مجموع زمان با یک reader حدود ۲۴٫۹٪ بیشتر، با دو reader حدود ۰٫۶٪ بیشتر و با چهار reader حدود ۱۴٫۳٪ بیشتر شد. helperها در این ورودی کوچک، shared read نداشتند؛ این آزمایش، مسئلهٔ cache مؤثر را بازتولید نکرد. وضعیت هر سه نامزد `DO_NOT_PROMOTE_ON_SMALL_WARM_CORPUS` است. ۷۴ تست بومی بدون skip، از جمله قطع واقعی در prefetch/قبل/بعد commit، snapshot، خطای hint، پایان بودجه، READ ONLY و ردشدن هویت AD نامعتبر، موفق‌اند. این نتیجهٔ محلی است؛ Windows و head نهایی در checks PR سنجیده می‌شوند.

`Observe_Viewer_Index_Parallel.py` کالیبراسیون مستقل READ ONLY روی همان ایندکس‌های ثبت‌شده است. این ابزار قبل از اتصال، AD جاری با هویت/نسخه و heartbeat معتبر را لازم دارد؛ در ابتدا و انتها lease Viewer و هویت AD را ثبت می‌کند. ترتیب ۱،۲،۴ و سپس ۴،۲،۱ برای هر جدول، با کلیدهای تصادفی تازه است. حداکثر پنج اتصال هم‌زمان، ۵۱۲ جفت مصنوعی در هر cell و مجموع ثابت ۱۲ cell دارد. بودجهٔ کلی و هر statement محدودند؛ incomplete cell یا تغییر پردازه، نتیجهٔ PARTIAL می‌دهد. پیش‌خوانی C4 در Worker فعال نمی‌شود. دیسک فیزیکی، کش سرد، شمارندهٔ کل کلاستر، پردازش واقعی AD و throughput از این probe نتیجه نمی‌شوند.

این سند قرارداد کد را شرح می‌دهد؛ ورودی‌ها و رسیدهای خصوصی در این تغییر منتشر نمی‌شوند. گزارش پیشینِ همین مسیر در commit مبنا `93da6a7` و رسیدهای پیش‌تر منتشرشده در تاریخچهٔ Git باقی‌اند.

## C3: کلید دقیق در cache تراکنشی

`LocalProjectionKeysDB` فقط نام دیتابیس تازهٔ `p24_design_capacity_*_qualification` را می‌پذیرد و از C2 ارث می‌برد. مقایسهٔ کامل متن روی indexهای TEMP حفظ می‌شود و تبدیل باینریِ زائد روی همان مقایسه حذف می‌شود. probe روی جدول دائمی و ساخت cache اعتبار Origin همچنان همان مسیر اصلی‌اند. برابری، version رقیب خارج RequestID، نبود مرجع و NULL تغییر نمی‌کنند. هیچ TTL یا cache بین commitها اضافه نشده است.

schema تازهٔ qualification از collation استاندارد deterministic استفاده می‌کند. [مستند PostgreSQL 18](https://www.postgresql.org/docs/18/collation.html#COLLATION-NONDETERMINISTIC) هم‌ارزی متن deterministic را به بایت یکسان محدود می‌کند. ترتیب، collation و normalization در این ابزار عوض نمی‌شوند. runtime pin و کنترل شکل query، تغییر source ناشناخته را رد می‌کنند.

برای بازتولید مصنوعی روی PostgreSQL آزمایش مستقل:

```text
python -B -m viewer_performance.capacity.baseline --backend postgresql --counts 32 256 2048 --pairs 2 --experiment local_projection_keys --wal-compression zstd --out qualification/capacity-local-keys.json
```

متغیرهای اتصال آزمایش `P24_DELTA_PG_HOST/PORT/USER` و در صورت نیاز `PGPASSWORD` هستند. خط مبنا در این مقایسه C2 است. زمان bootstrap، setup، oracle و کنترل خوانایی جدا ثبت می‌شود؛ حذف آن‌ها از یک ستون، پنهان‌کردن آن‌ها از کل رسید نیست. پنجرهٔ skip یا staging انتشار تازه شمرده نمی‌شود. دادهٔ محلی از scope واقعی خروجی قابل تشخیص است؛ ابزار نتیجه را خودکار به ظرفیت Production تبدیل نمی‌کند.

## مشاهدهٔ محدود ایندکس واقعی

`Observe_Viewer_Index_Cost.py --project . --seconds 20` از ابتدا READ ONLY، timeout محدود و کلید تصادفی دارد. هیچ سطر، schema، تنظیم عمومی، Worker یا cursor تغییر نمی‌کند. plan فقط ساختار و شمارنده دارد؛ شرط‌ها، literalها، SQL متن، بدنه و کلیدها صادر نمی‌شوند. برآورد کاتالوگ count دقیق نیست؛ متریک SELECT همین اتصال، مصرف اختصاصی Writer نیست؛ buffer read می‌تواند از OS cache پاسخ بگیرد. دیدن lease به‌تنهایی سلامت Worker را ثابت نمی‌کند.

این probe بر خلاف runner qualification فقط‌خواندنی به دیتابیس واقعی وصل می‌شود؛ callbackهای آن هرگز برای انتشار داده استفاده نمی‌شوند. خروجی باید خصوصی بازبینی شود و به Git افزوده نشود. نتیجه، فشار کش یا سود cache را به‌تنهایی ثابت نمی‌کند؛ حذف lookup می‌تواند هزینه را به COPY منتقل کند.

## صحت و ادامهٔ کار

آزمون‌های مصنوعی هویت کامل، Unicode، NULL، شاهد عادی و دیررس، نسخهٔ رقیب، withdrawn، بدنهٔ مفقود/چندتایی، batch خالی، قطع واقعی قبل/بعد commit، restart و snapshot RR/RO هم‌زمان را پوشش می‌دهند. تست probe، READ ONLY و حفظ داده و حذف literal را کنترل می‌کند. نتیجهٔ کد نهایی در checks PR است. هیچ detector، threshold، incident، UI، source checkpoint یا محدودهٔ تحلیل تغییر نکرده است.

این بسته ارتقای Worker نیست. عرضهٔ محصول، فشار کش در مقیاس تاریخچه، دریافت ES، مصرف و صف AD، هشت ساعت و نرخ هدف به شواهد جدا و برنامهٔ ارتقای مشخص نیاز دارند. داده‌ها و رسیدهای خصوصی در مسیر Git قرار نمی‌گیرند. بازگشت ابزار ایزوله، پایان همان ابزار و حفظ برنامهٔ فعلی است؛ migration محصولی وجود ندارد.
