# قرارداد داده و یکپارچه‌سازی UserID نسخهٔ ۱٫۱

شناسهٔ جاری قرارداد p24-userid-1.1، هویت userid-identity-1 و ویژگی userid-features-1 است. CR-001 به Behavior زمینه و attempt نسخه‌دار اضافه کرده است. مسیر v1 خانوادهٔ اصلی قرارداد است. WP01، parser و producer مستقل این مرزها را پیاده‌سازی کرده؛ Detector، migration و نصب متعلق به بسته‌های بعدند.

[Schema](../../contracts/userid/v1/schema.json) و [مثال‌های مصنوعی](../../contracts/userid/v1/examples.json) در contracts/userid/v1 ریشهٔ مخزن هستند. اعتبارسنج مرجع در contracts/userid/validate.py فقط ابزار conformance آفلاین است؛ خودبه‌خود به runtime وصل نمی‌شود.

## شناسه و قالب‌های دقیق

UserID نرمال‌شده رشتهٔ ASCII مثبت با نمایش استاندارد و در بازهٔ ۱ تا ۹۲۲۳۳۷۲۰۳۶۸۵۴۷۷۵۸۰۷ است. عدد صحیح دقیق Python/ES می‌تواند طبق همین قرارداد به رشته تبدیل شود؛ float، bool، توان علمی، رقم فارسی، فاصله، علامت جمع، صفر پیشرو، صفر، مقدار منفی و ماسک شناسهٔ معتبر نمی‌سازند. معنای کسب‌وکاری صفر همچنان تأیید نشده و actor صفر ایجاد نمی‌شود.

RequestID این پروفایل از Guid.NewGuid منبع می‌آید و در مرز نرمال‌شده ۳۲ hex کوچک بدون خط تیره است. پذیرش قالب GUID خط‌تیره‌دار در adapter، پس از تأیید قالب و بدون تغییر مقدار انجام می‌شود. دادهٔ فاقد RequestID یا با قالب نامعتبر به یک درخواست مشترک متصل نمی‌شود؛ در diagnostics محدود و شمارش پوشش باقی می‌ماند. پشتیبانی از RequestID opaque آینده، تغییر قرارداد می‌خواهد.

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

kind جدا و یکی از ACCOUNT، GUEST یا UNDETERMINED است. kind حساب/مهمان به شاهد SOURCE_AUTH_STATE مطابق همان UserID نیاز دارد. پروفایل لاگ فعلی چنین metadata عمومی ندارد؛ WP01 به طور پیش‌فرض UNDETERMINED صادر می‌کند. مسیر موفق Login یا عدد شناسه، شاهد نوع همهٔ رویدادها نیست.

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

SourceRecord مرز دادهٔ دریافت‌شده است و به معنی معتبر بودن UserID داخل metadata نیست. انواع بعدی باید از هویت نرمال‌شده استفاده کنند. SourceWindow با complete=true قرارداد publication است؛ دریافت ناقص خروجی publishable نمی‌سازد. source_finality در نمونهٔ فعلی NOT_ESTABLISHED است.

## eligibility و نتیجه

actor_eligible به هویت VALID و زمان‌دار، عملیات COMPLETE از نوع business/user_management و شاهد هویت حداکثر در زمان عملیات نیاز دارد. account_eligible افزون بر آن kind=ACCOUNT می‌خواهد. وجود هویت UNDETERMINED می‌تواند تحلیل فعالیت همان شناسه را مجاز کند، ولی ادعای حساب واردشده را مجاز نمی‌کند.

فقدان یا تعارض هویت، الزاماً تحلیل سطح خدمت را حذف نمی‌کند؛ service/result و هر جزء محتوا eligibility مستقل دارند. صحت اتصال محتوا و عملیات باید جدا بررسی شود. stateهای PENDING/EXPIRED/CONFLICT یا roleهای support/system/unknown اجرای تجاری کامل شمرده نمی‌شوند.

اجزای targets/numeric/shape مستقل‌اند. جزء eligible باید زمان و basis معتبر PUBLIC_API، BUSINESS_SQL یا REVIEWED_PROVIDER داشته باشد. UNCONFIRMED و UNAVAILABLE واجد شرایط نیستند. PARTIAL وضعیت نقص را حفظ می‌کند؛ استفادهٔ lower-bound یا هر آمار ناقص، تعریف روش و شاهد مستقل می‌خواهد.

REPORTED_SUCCESS برای پایان API به جفت دقیق G00000/Successful وابسته است. business_state مستقل است و نتیجهٔ مالی در برنامهٔ پایه OUT_OF_SCOPE می‌ماند. پاسخ موفق provider جانبی، نتیجهٔ نهایی را عوض نمی‌کند.

## observations و CR-001

Behavior اکنون observations با version=userid-observations-1، service_binding، request_context و attempt دارد. زمینه با userid-request-context-1، مقادیر کراندار و منشأ و زمان رشته‌ای نگهداری می‌شود. دادهٔ بدنه جای header احراز‌شده نیست؛ missing/limited/چندمقداری باید توسط مصرف‌کننده حفظ شود. IP و UA actor یا نوع حساب تعیین نمی‌کنند.

attempt تنها با پایان عمومی هم‌زمان و جفت دقیق کد/نام نسخه‌دار قابل ادعاست: ACCESS_DENIED، INVALID_SESSION، VALIDATION_REJECTED یا RATE_LIMIT. requested_service مقصد درخواست‌شده است، نه اجرای آن. در attempt، actor/account/service/result و همهٔ eligibilityهای محتوا برای اجرای عادی خاموش‌اند. WP03 برای تحلیل اقدام ردشده، هویت و تاریخ و منشأ مناسب همان روش را جدا بررسی می‌کند. هم‌زمانی dispatch قطعی و رد پیش از اجرا، تعارض شواهد است.

نسخهٔ قبلی p24-userid-1 توسط validator جاری پذیرفته نمی‌شود. هیچ دادهٔ نسخهٔ جدید هنوز در تولید ذخیره نشده است؛ تولیدکننده و fixtureها با CR-001 یکجا ارتقا یافتند. معنای UID، namespace کلید، سیاست identity و نسخهٔ features تغییر نکرده‌اند.

## تحلیل، مرجع و پرونده

AnalysisResult، source_epoch و source_window_revision و reference_epoch و نسخهٔ مدل/ویژگی/هویت را دارد. نتیجه/ACK باید علیه همین نسخه‌ها بررسی و اتمیک commit شوند. cutoff مرجع از شروع پنجرهٔ مورد تحلیل جلوتر نیست.

entity از نوع ACTOR، SERVICE یا NETWORK است. actor_key در نتیجهٔ شبکه/خدمت null است؛ اثر انگشت شبکه به حساب تعبیر نمی‌شود. نتیجهٔ NORMAL/ANOMALY برای روش actor بدون actor معتبر مجاز نیست؛ نبود هویت INVALID_INPUT یا INSUFFICIENT_DATA است.

ANOMALY مقدار، threshold، شاهد و basis مرجع دارد. ENGINEERING_FLOOR در نسخهٔ پایه فقط برای دو روش access_denied_attempts و invalid_session_attempts تعریف شده است؛ افزودن آن به روش دیگر، تصمیم نسخه‌دار می‌خواهد. مرجع unavailable به ناهنجاری تبدیل نمی‌شود.

پروندهٔ ACTIVE دست‌کم یک یافتهٔ ANOMALY معتبر دارد. شاهدها behavior_key/revision دارند. بازخورد به finding_key/revision اصلی خود متصل می‌ماند؛ تغییر نتیجه، نظر قدیمی را حذف یا به revision تازه منتسب نمی‌کند.

## نسخه‌بندی و تغییر

consumer باید نسخهٔ ناشناخته را رد یا به مسیر ناسازگار مشخص هدایت کند؛ fallback به Session یا قرارداد Compact انجام نمی‌شود. تغییر breaking در schema، enum، الگوریتم کلید یا eligibility، نسخه و CR لازم دارد. افزودن فیلد مجاز فقط با به‌روزشدن schema/مثال/آزمون و مصرف‌کنندگان انجام می‌شود.

فرمان‌های بررسی توسعه:

```text
python -m pip install -r requirements-userid.txt
python -B -m unittest -v tests.test_userid_contracts tests.test_userid_extraction
python -B -m contracts.userid.validate
```

این وابستگی در محیط تست قرارداد نصب می‌شود و requirements نصب قدیمی تغییر نکرده است. ابزار از Draft202012Validator همراه FormatChecker استفاده می‌کند؛ format به تنهایی enforcement نیست. مرجع API: https://python-jsonschema.readthedocs.io/en/v4.25.1/validate/ .
