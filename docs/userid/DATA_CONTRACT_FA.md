# قرارداد داده و یکپارچه‌سازی UserID نسخهٔ ۲

شناسهٔ قرارداد p24-userid-2، هویت userid-identity-2 و ویژگی userid-features-2 است. این قرارداد مرز اجزای جدید را تعریف می‌کند؛ parser، Detector، migration یا نصب اجرایی نیست.

[Schema](../../contracts/userid/v2/schema.json) و [مثال‌های مصنوعی](../../contracts/userid/v2/examples.json) در contracts/userid/v2 ریشهٔ مخزن هستند. اعتبارسنج مرجع در contracts/userid/validate.py فقط ابزار conformance آفلاین است؛ خودبه‌خود به runtime وصل نمی‌شود.

## شناسه و قالب‌های دقیق

UserID نرمال‌شده رشتهٔ ASCII مثبت با نمایش استاندارد و در بازهٔ ۱ تا ۹۲۲۳۳۷۲۰۳۶۸۵۴۷۷۵۸۰۷ است. عدد صحیح دقیق Python/ES می‌تواند طبق همین قرارداد به رشته تبدیل شود؛ float، bool، توان علمی، رقم فارسی، فاصله، علامت جمع، صفر پیشرو، صفر، مقدار منفی و ماسک شناسهٔ معتبر نمی‌سازند. معنای کسب‌وکاری صفر همچنان تأیید نشده و actor صفر ایجاد نمی‌شود.

RequestID این پروفایل از Guid.NewGuid منبع می‌آید و در مرز نرمال‌شده ۳۲ hex کوچک بدون خط تیره است. در هر ۳۰۶٬۹۳۵ سند چهار پنجره، GUID خط‌تیره‌دار واقعی دیده شد. ورودی ۸-۴-۴-۴-۱۲ یا ۳۲ رقم hex فقط پس از بررسی کامل قالب به حروف کوچک و بدون خط تیره تبدیل می‌شود. GUID تهی، فاصله و خط تیره در جای نادرست رد می‌شوند. تابع canonical_request_id همین مرز را آزمون‌پذیر می‌کند. دادهٔ فاقد RequestID یا با قالب نامعتبر به یک درخواست مشترک متصل نمی‌شود؛ در diagnostics محدود و شمارش پوشش باقی می‌ماند. پشتیبانی از RequestID opaque آینده، تغییر قرارداد می‌خواهد.

source_scope صریح، پایدار و مستقل از IP/UA است؛ مانند pishkhan24:production:core. محیط و قلمرو حساب را از نمونهٔ UserID حدس نمی‌زنیم. UserID هم‌نام در payload یا provider، متعلق به این قرارداد هویت نیست.

Nanoseconds نیز رشتهٔ ده‌دهی استاندارد در محدودهٔ Int64 غیرمنفی است. مبنای زمانی UTC، با دقت اصلی و بدون تبدیل float است؛ تاریخ نمایشی تهران از آن مشتق می‌شود.

## تولید کلید

SHA-256 روی UTF-8 از JSON array فشردهٔ سه رشته، با ensure_ascii=False و separators=(',',':') محاسبه می‌شود:

- actor_key: ["userid-actor-1", source_scope, user_id]
- request_key: ["userid-request-1", source_scope, request_id]
- behavior_key: ["userid-behavior-1", source_scope, request_id]

document_key از SHA-256 روی JSON array فشردهٔ ["userid-document-1", source_scope, _index, _id] ساخته می‌شود. منشأ گمشده به یک مقدار مشترک تبدیل نمی‌شود؛ WP01 باید وضعیت آن را در کنترل تمامیت/diagnostics مشخص کند.

behavior_key با رسیدن هویت یا تعارض عوض نمی‌شود؛ revision عوض می‌شود. actor_key فقط برای هویت VALID ساخته می‌شود. این hash قاعدهٔ کلید پایدار است و ادعای ناشناس‌سازی داده نیست. کلید finding/case به تعریف روش، بعد ویژگی و نسخهٔ سیاست وابسته است و جزئیات آن در WP03/WP04 با تغییر نسخه تعیین می‌شود.

## وضعیت و نوع هویت

| status | user_id و actor_key | candidateها و رفتار |
|---|---|---|
| MISSING | null | هیچ مقدار معتبر؛ فقدان/تهی‌بودن، actor مصنوعی نمی‌سازد |
| VALID | یک مقدار و کلید مطابق scope | دقیقاً یک candidate، شاهد معتبر و بدون مشاهدهٔ نامعتبر |
| INVALID | null | مقدار/قالب نامعتبر یا تأییدنشده؛ reason صریح، بدون انتخاب winner |
| CONFLICT | null | دست‌کم دو UserID معتبر متفاوت در یک درخواست؛ candidateها حفظ می‌شوند |

ترتیب تصمیم: CONFLICT بر INVALID، سپس VALID و سپس MISSING تقدم دارد. مشاهدهٔ مفقود کنار یک مقدار معتبر، به‌تنهایی آن مقدار را متعارض نمی‌کند. مقدار معتبر کنار مشاهدهٔ نامعتبر، در این نسخه actor معتبر قطعی نمی‌سازد.

نوع هویت یکی از ACCOUNT، GUEST یا UNDETERMINED است. هر شاهد مثبت یک document_key و request_key متناظر با همان قلمرو و درخواست دارد. شاهد نوع هویت باید مقدار مشاهده‌شدهٔ observed_kind، زمان و نام فیلد صریح source.identity_kind را حمل کند. source.verified به تنهایی نگاشت تأییدشده‌ای ندارد. در صورت تعارض دو شاهد صریح نوع، هر دو شاهد باقی می‌مانند و نوع UNDETERMINED می‌شود. این تعارض با تعارض دو UserID متفاوت است. kind حساب/مهمان به شاهد SOURCE_AUTH_STATE مطابق همان UserID نیاز دارد. پروفایل لاگ فعلی چنین metadata عمومی ندارد؛ WP01 به طور پیش‌فرض UNDETERMINED صادر می‌کند. مسیر موفق Login یا عدد شناسه، شاهد نوع همهٔ رویدادها نیست.

evidence به مکان metadata، document_key و زمان رویداد/مشاهده اشاره دارد و observed_user_id را نگه می‌دارد. candidateهای ادعاشده باید در همین evidence حضور داشته باشند. identity_as_of_ns اولین زمان رویدادِ شاهد UserID منتخب است؛ نبود زمان، جعل timestamp نمی‌کند. kind_evidence مستقل است.

منبع _source.UserID یا metadata تخت، scalar است. fields.UserID تک‌عضوی به عنوان docvalue پذیرفته می‌شود. مقادیر معتبر متفاوت میان این دو مکان CONFLICT‌اند؛ float و آرایهٔ نامعتبر با همسان‌سازی دلخواه پنهان نمی‌شوند. candidateها کران دارند؛ عبور از سقف به خطای صریح/عدم publication منجر می‌شود، نه حذف بی‌صدای تعارض.

## انواع مرزی

| record_type | تولیدکننده و مصرف‌کننده | معنا |
|---|---|---|
| SourceRecord | WP01 transport به extractor | metadata و message خام در حافظه، حتی با UserID نامعتبر؛ خروجی عمومی وب نیست |
| SourceWindow | WP01 به WP02 | پنجرهٔ کامل، aligned پنج‌دقیقه‌ای، شمارش و مبنای تمامیت |
| RequestIdentity | WP01 به WP02/WP03 | هویت نرمال‌شده با provenance و status/kind مستقل |
| FeatureSet | WP01 به WP02/WP03 | نسخه، eligibility مستقل actor/account/service/result و اجزای input/output |
| Behavior | WP01/WP02 به WP03/WP04 | یک اجرای منطقی، هویت، state، revision، خدمت، نتیجه و ویژگی |
| AnalysisResult | WP03 به WP02/WP04 | نتیجه، entity، source/reference fence، مرجع و شاهد نسخه‌دار |
| CaseView | WP04 | پروندهٔ قابل توضیح و نظر انسانی متصل به revision |
| RuntimeConfig | WP05 | instance، DB مستقل، پورت، Task، مسیر و نقش‌های مجاز همان نصب |

SourceRecord شامل origin._index و origin._id است. مصرف‌کننده می‌تواند document_key را دوباره بسازد. WP01 هنگام ساخت شاهد بررسی می‌کند که مقدار و مکان metadata واقعاً از همان سند و RequestID آمده باشند. WP02 و WP06 اتصال به نسخهٔ شاهد را در آزمون جریان کامل بررسی می‌کنند. اعتبارسنج تک‌رکوردی به سند خارجی یا پایگاه داده دسترسی ندارد.

SourceRecord مرز دادهٔ دریافت‌شده است و به معنی معتبر بودن UserID داخل metadata نیست. انواع بعدی باید از هویت نرمال‌شده استفاده کنند. SourceWindow با complete=true قرارداد publication است؛ دریافت ناقص خروجی publishable نمی‌سازد. source_finality در نمونهٔ فعلی NOT_ESTABLISHED است.

## eligibility و نتیجه

actor_eligible به هویت VALID و زمان‌دار، عملیات COMPLETE از نوع business/user_management و شاهد هویت حداکثر در زمان عملیات نیاز دارد. account_eligible افزون بر آن kind=ACCOUNT می‌خواهد. وجود هویت UNDETERMINED می‌تواند تحلیل فعالیت همان شناسه را مجاز کند، ولی ادعای حساب واردشده را مجاز نمی‌کند.

در Behavior هیچ شاهد هویت با seen_at_ns پس از known_at_ns وارد آن revision نمی‌شود. محتوای مشاهده‌شده و زمان عملیات نیز از known_at_ns جلو نمی‌افتند. شاهد دیررس با زمان رویداد قدیمی در revision تازه قابل استفاده است. account_eligible به شاهد صریح حساب با زمان رویداد حداکثر برابر زمان عملیات نیاز دارد. این قاعده مانع انتساب گذشتهٔ مهمان به حساب بعد از ورود می‌شود.

فقدان یا تعارض هویت، الزاماً تحلیل سطح خدمت را حذف نمی‌کند؛ service/result و هر جزء محتوا eligibility مستقل دارند. صحت اتصال محتوا و عملیات باید جدا بررسی شود. stateهای PENDING/EXPIRED/CONFLICT یا roleهای support/system/unknown اجرای تجاری کامل شمرده نمی‌شوند.

اجزای targets/numeric/shape مستقل‌اند. جزء eligible باید زمان و basis معتبر PUBLIC_API، BUSINESS_SQL یا REVIEWED_PROVIDER داشته باشد. UNCONFIRMED و UNAVAILABLE واجد شرایط نیستند. PARTIAL وضعیت نقص را حفظ می‌کند؛ استفادهٔ lower-bound یا هر آمار ناقص، تعریف روش و شاهد مستقل می‌خواهد.

در دادهٔ نرمال‌شده، data.targets نگاشت محور مستند همان خدمت به آرایهٔ اثر انگشت نوع‌دار هدف‌هاست. برای مقدار رشته‌ای، فاصلهٔ ابتدا و انتها حذف و مقدار تهی رد می‌شود. برای عدد، فقط عدد صحیح دقیق پذیرفته می‌شود. SHA-256 روی UTF-8 نمایش JSON همان scalar با ensure_ascii=False محاسبه می‌شود. عدد ۱۲ و رشتهٔ «12» دو مقدار متمایزند. ترتیب آرایه معنای رتبه ندارد، تکرار عضو حفظ می‌شود. در AD هر ترکیب RequestID، محور و هدف فقط یک بار در شمار درخواست وارد می‌شود. شناسهٔ انجام‌دهنده، توکن یا کد برگشتیِ خروجی جانشین هدف ورودی نمی‌شود. برای repeated_target، target_diversity و long_target_enumeration، درخواست با ورودی معتبر مستقل از موفقیت، خطا یا نامعلومی نتیجه در ارزیابی وارد می‌شود.

data.numeric نگاشت مسیر به count/min/max/mean و sum/values_hash اختیاری است. data.shape_hash اثر انگشت SHA-256 شکل است. WP01 و WP03 باید مسیر، قواعد گزینش و هش شکل را با fixture مشترک تثبیت کنند. eligibility هر جزء وجود مقدار سازگار همان جزء را لازم دارد. فقدان محور قابل‌شمارش، مقدار صفر تولید نمی‌کند. دادهٔ PARTIAL دلیل محدودیت را حفظ می‌کند. service_eligible نیز به service_key حل‌شده نیاز دارد. کلید درخواست و actor و behavior طبق الگوریتم قبلی است.

REPORTED_SUCCESS برای پایان API به کد دقیق G00000 و واژهٔ ASCII successful با تطبیق مستقل از بزرگی حروف وابسته است. api_name املای اصلی را حفظ می‌کند. هر ۶۳٬۱۳۵ پیام پایان HTTP با این کد در چهار پنجره، واژهٔ successful با حروف کوچک داشتند. کد یا نام نامطمئن می‌تواند UNKNOWN بماند. business_state مستقل است و نتیجهٔ مالی در برنامهٔ پایه OUT_OF_SCOPE می‌ماند. پاسخ موفق provider جانبی، نتیجهٔ نهایی را عوض نمی‌کند.

## تحلیل، مرجع و پرونده

AnalysisResult، source_epoch و source_window_revision و reference_epoch و نسخهٔ مدل/ویژگی/هویت را دارد. نتیجه/ACK باید علیه همین نسخه‌ها بررسی و اتمیک commit شوند. cutoff مرجع از شروع پنجرهٔ مورد تحلیل جلوتر نیست.

entity از نوع ACTOR، SERVICE یا NETWORK است. actor_key در نتیجهٔ شبکه/خدمت null است؛ اثر انگشت شبکه به حساب تعبیر نمی‌شود. نتیجهٔ NORMAL/ANOMALY برای روش actor بدون actor معتبر مجاز نیست؛ نبود هویت INVALID_INPUT یا INSUFFICIENT_DATA است.

NORMAL و ANOMALY به پنجرهٔ پایان‌یافته، مقدار مشاهده، آستانه و مرجع معتبر وابسته‌اند. برای PAST_DATA شمار پنجره و نمونه مثبت و fingerprint مرجع لازم است. حداقل آماری کافی و اینکه snapshot واقعی فقط دادهٔ قابل‌دانستن پیش از cutoff را دارد، با روش نسخه‌دار WP03 و بازپخش WP06 سنجیده می‌شود. صفرِ مشاهده‌شدهٔ معتبر می‌تواند NORMAL باشد. warmup همچنان INSUFFICIENT_DATA است. ANOMALY شاهد نسخه‌دار نیز می‌خواهد. ENGINEERING_FLOOR در نسخهٔ پایه فقط برای دو روش access_denied_attempts و invalid_session_attempts تعریف شده است؛ افزودن آن به روش دیگر، تصمیم نسخه‌دار می‌خواهد. مرجع unavailable به ناهنجاری تبدیل نمی‌شود.

پروندهٔ ACTIVE دست‌کم یک یافتهٔ ANOMALY معتبر دارد. شاهدها behavior_key/revision دارند. بازخورد به finding_key/revision اصلی خود متصل می‌ماند؛ تغییر نتیجه، نظر قدیمی را حذف یا به revision تازه منتسب نمی‌کند.

CaseView دقیقاً یک موجودیت دارد. چند خدمت یک actor می‌توانند در یک پرونده بیایند. آخرین revision هر finding_key وضعیت جاری را تعیین می‌کند. بازخورد باید به کلید در همان پرونده و revision حداکثر برابر آخرین نسخهٔ آن اشاره کند. وجود دقیق revision تاریخی در ذخیره‌ساز با WP02 است. RuntimeConfig دو مسیر مطلق و مجزا می‌خواهد که هیچ‌کدام زیرمسیر دیگری نباشد. WP05 مسیر واقعی را پس از حل پیوندها و junction روی سرور کنترل می‌کند.

## نسخه‌بندی و تغییر

consumer باید نسخهٔ ناشناخته را رد یا به مسیر ناسازگار مشخص هدایت کند؛ fallback به Session یا قرارداد Compact انجام نمی‌شود. تغییر breaking در schema، enum، الگوریتم کلید یا eligibility، نسخه و CR لازم دارد. افزودن فیلد مجاز فقط با به‌روزشدن schema/مثال/آزمون و مصرف‌کنندگان انجام می‌شود.

فرمان‌های بررسی توسعه:

```text
python -m pip install jsonschema==4.25.1
python -B -m unittest -v tests.test_userid_contracts
python -B -m contracts.userid.validate
```

این وابستگی در محیط تست قرارداد نصب می‌شود و requirements نصب قدیمی تغییر نکرده است. ابزار از Draft202012Validator همراه FormatChecker استفاده می‌کند؛ format به تنهایی enforcement نیست. مرجع API: https://python-jsonschema.readthedocs.io/en/v4.25.1/validate/ .
