# قرارداد ابزار qualification ظرفیت Viewer

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
