# پیاده‌سازی و تحویل WP01

مرجع مشترک ۱٫۴؛ بستهٔ WP01؛ مبنای توسعه ce8ba5c5988c2710a52e452f19d463a6ab5da84d، شاخهٔ codex/userid-wp01. اجازهٔ مالک شامل پیاده‌سازی، آزمون و ادغام main است. این فایل راهنمای جاری استخراج و اتصال به WP02 است؛ رسید PR/CI وضعیت ادغام را مشخص می‌کند.

## نتیجه و مرز تحویل

مسیر مستقل دریافت، هویت UserID، اتصال درخواست، محتوای منتخب و ویژگی در userid_product پیاده‌سازی شده است. فایل یا snapshot ناقص، خروجی قابل انتشار نمی‌سازد. هیچ DB، collector، مدل AD، وب یا Task تولید با import یا فرمان آزمون فعال نمی‌شود. راه‌اندازی ۵۰۲۲، توقف Writer قدیمی و ساخت DB در این بسته انجام نشده‌اند.

| فایل | مسئولیت |
|---|---|
| userid_product/source.py | پروفایل UserID، projection جدید، JSON.gz جریانی و ES صریح، کنترل پنجره/منشأ/تعداد/زمان |
| userid_product/identity.py | UserID و RequestID سخت‌گیرانه، namespace، evidence کراندار و وضعیت هویت |
| userid_product/extraction.py | adapter نسخه‌دار محتوای خالص، fragment، merge اتمیک، Behavior و hashها |
| userid_product/replay.py | بازپخش آفلاین و گزارش شمارشی بدون شناسه و لاگ خام |
| tests/test_userid_extraction.py | ورودی ناسازگار، دیررسی، replay، سقف‌ها، محتوای ناقص، intent و تمامیت |
| requirements-userid.txt | jsonschema==4.25.1؛ بدون تغییر requirements نصب قدیمی |

پاک‌سازی این مرحله شامل اصلاح راهنمای ریشه، مأموریت منقضی‌شدهٔ WP00 و اسناد جاری است. پوشه‌های Compact/Viewer حذف نشده‌اند: نصب ارائه و adapter محتوای جدید هنوز مصرف‌کنندهٔ مشخص آن‌ها هستند. حذف آن‌ها پیش از جایگزین‌کردن وابستگی، cleanup معتبر نیست.

## شناخت هویت برای ایجنت بعدی

منبع Core در CreateScope، RequestID تازه و UserID تهی می‌سازد. HasAccess پیش از Session.Info است و در نمونه‌های آن نبود UserID انتظار می‌رود. Info مقدار ستون نهم ud_prc_userSessionInfo را به context می‌دهد؛ NLog آن را به UserID مستقل می‌نویسد. UserID در payload سرویس یا شمارهٔ موبایل provider، هویت actor نیست.

طبق تأیید مالک، مهمان پیش از OTP هم شناسه دارد و حساب اصلی پس از ورود شناسهٔ پایدار خود را دارد. چون Info قبل از Verify است، خود درخواست Login می‌تواند هنوز UID مهمان داشته باشد. دادهٔ فعلی شاهد عمومی Verified/kind ندارد؛ تمام خروجی واقعی این بسته UNDETERMINED است و account_eligible صفر می‌ماند. دو UID مهمان/حساب با سشن نیمه‌ماسک‌شده، IP یا UA به هم وصل نمی‌شوند.

UserID تنها scalar صحیح مثبت Int64 یا رشتهٔ استاندارد ASCII آن است. float/bool/صفر/منفی/رقم فارسی/فاصله/ماسک/صفر پیشرو رد می‌شوند. docvalue تک‌عضوی fields.UserID مجاز است؛ آرایهٔ نامعتبر پنهان نمی‌شود. تعارض بر نامعتبر، سپس معتبر و سپس مفقود تقدم دارد. مقدار مفقود کنار یک معتبر، آن را حذف نمی‌کند؛ یک نامعتبر کنار معتبر به INVALID می‌رسد. حداکثر چهار candidate و ۱۶ شاهد حفظ می‌شود، از جمله نخستین شاهد زمان‌دار هر candidate و شاهد مقدار نامعتبر در صورت وجود. candidate پنجم خطای صریح است.

## مرز منبع و تمامیت

normalize(hit, source_scope, seen_at_ns) یک SourceRecord می‌سازد. _index و _id معتبر و محدود لازم‌اند؛ document_key از scope و همین منشأ است. metadata خام هویت با مکان _source/fields/log حفظ می‌شود و message جداست. هیچ message خامی وارد RequestState یا گزارش عمومی نمی‌شود. event_time_ns و seen_at_ns رشتهٔ ده‌دهی‌اند؛ زمان نانوثانیه و UID از float عبور نمی‌کنند.

WindowFile فایل JSON یا gzip با logs، count، complete، window_start و window_end را جریانی می‌خواند. property تکراری، حتی در سند داخلی، خطاست. خواندن کل EOF، شمارش صحیح و تمامیت لازم‌اند. wrapper records در هر دو مسیر فایل و ES، منشأ یکتا، زمان معتبر داخل بازه و پنجرهٔ aligned پنج‌دقیقه‌ای را بررسی می‌کند. سند بی‌زمان/خارج بازه یا منشأ تکراری، کل آماده‌سازی پنجره را رد می‌کند. فقدان UserID پنجره را رد نمی‌کند.

ElasticWindow از کنترل PIT/scroll نسخهٔ ثابت استفاده می‌کند؛ projection آن UserID دارد و Session ندارد. PIT تعداد دقیق و cursor صعودی، و scroll تعداد دقیق/منشأ یکتا/صفحهٔ پایانی تهی می‌خواهد. شکست shard، timeout، سقف یا خواندن ناقص، certificate نمی‌سازد و handle بسته می‌شود. اعتبارسنجی منشأ wrapper روی PIT هم اعمال می‌شود. source.window تا پایان موفق records قابل دریافت نیست. source_finality همچنان NOT_ESTABLISHED است.

وجود فیلد مستقل Session در پروفایل قدیمی، SOURCE_PROFILE_LEGACY_SESSION می‌دهد؛ دادهٔ قدیمی به actor جدید بازتعبیر نمی‌شود. Session داخل payload نیز کلید هویت نیست و از payload منتخب checkpoint حذف می‌شود.

records خروجی provisional می‌دهد؛ مصرف‌کننده باید در هر استثنا تمام آن آماده‌سازی را دور بریزد. مسیر توصیه‌شده برای WP02، extract_window است که فقط پس از پایان موفق، certificate و stateهای کراندار را برمی‌گرداند. این تابع خودش cursor یا DB نمی‌نویسد.

## اتصال عملی به WP02

```python
from userid_product.source import WindowFile
from userid_product.extraction import (
    extract_window, merge, materialize, state_hash, behavior_hash,
)

certificate, batch = extract_window(
    WindowFile(private_path), source_scope, seen_at_ns,
)
# پس از موفقیت کامل منبع؛ بارگذاری و commit با repository بستهٔ WP02:
for request_id, incoming in batch.states.items():
    previous = repository.load_request_state(source_scope, request_id)
    updated = merge(previous, incoming)
    behavior = materialize(updated, revision=repository.next_revision(...))
    # حفظ state/hash، اصلاح Behavior، dirty/retraction و certificate/cursor
    # باید در تراکنش fenced متعلق به WP02 انجام شود.
```

این قطعه، قرارداد اتصال است؛ repository و next_revision هنوز پیاده‌سازی نشده‌اند و علامت ... ورودی placeholder است. اجرای مستقیم آن دستور نصب یا فرمان سرور نیست.

| رابط | تضمین و مسئولیت مصرف‌کننده |
|---|---|
| fragment(SourceRecord) | یک RequestState نسخه‌دار؛ RequestID GUID استاندارد لازم است |
| Extractor.add(record) | قبول یک fragment یا شمارش quarantine فاقد RequestID؛ شکست سقف، state پذیرفته‌شده را تغییر نمی‌دهد |
| merge(previous, incoming, limits) | merge خالص همان scope/RequestID؛ ورودی‌ها تغییر نمی‌کنند؛ نسخه/هویت ناسازگار خطا می‌دهد |
| materialize(state, revision=...) | یک Behavior، حتی برای PENDING بدون API؛ شمارهٔ revision پایدار با WP02 است |
| state_hash(state) | تغییر شواهد نرمال‌شده؛ مستقل از ساعت اجرای مجدد و seen_at provenance |
| behavior_hash(behavior) | امضای مؤثر مصرف تحلیل؛ مستقل از revision/known_at و تغییر صرف نمونهٔ provenance |

state.version برابر userid-request-state-1 و extractor_version برابر userid-extraction-1 است. checkpoint یک شیء خصوصی Python با facts منتخب است و DTO عمومی وب نیست. facts میراث parser، timestamp صحیح Python دارد؛ اگر WP02 آن را JSON ذخیره کند باید صحیح دقیق حفظ شود، فقط در Python/ذخیرهٔ عددی دقیق خوانده شود و از parser عددی JavaScript نگذرد. DTOهای عمومی Behavior/observations زمان رشته‌ای دارند. state دریافتی از نسخهٔ ناشناخته، upgrade ضمنی نمی‌شود.

یک RequestID در چند پنجره همان behavior_key است. دیررسی می‌تواند MISSING را VALID یا VALID را CONFLICT کند؛ WP02 علاوه بر revision، سهم actor قدیمی و dirty پنجره/مرجع وابسته را اصلاح می‌کند. replay با ساعت جدید به‌تنهایی known_at یا امضای رفتار تازه نمی‌سازد. تغییر صرف provenance می‌تواند نیازمند نگهداری state باشد، بدون اجرای دوبارهٔ همهٔ روش‌های AD. feedback قبلی به revision اصلی‌اش متصل می‌ماند.

pending deadline، expiry، watermark، retention و retry محدود ذخیره با WP02/WP05 هستند؛ این extractor حلقهٔ recheck یا جست‌وجوی نامحدود RequestID ندارد. publication/cursor/dirty، fence، crash و recovery هنوز پیاده‌سازی/آزمون بومی نشده‌اند.

## محتوا، زمینه و عملیات ردشده

بازاستفادهٔ D04 به parser، تطبیق خدمت و feature خالص محدود است. بستهٔ frozen محتوای COMPACT-BEHAVIOR-20261124-25 با SHA256 برابر 1eeea74603931361c41a39679bb654cd164497cae549854f46f6739b1103a752 و hash مبدأ کاتالوگ 05ebff4db5829cc2f72a73e2813dce3002f7afd26793c9efd61947d246005d92 در شروع بررسی می‌شود. store/runtime/AD قدیمی وارد این مسیر نمی‌شوند. UserID هرگز در session_id قرار نمی‌گیرد و eligibility قدیمیِ Session صادر نمی‌شود.

PUBLIC_API، BUSINESS_SQL و REVIEWED_PROVIDER basisهای قابل استنادند؛ provider ناشناخته UNCONFIRMED باقی می‌ماند. input/output و targets/numeric/shape eligibility مستقل دارند؛ یک جزء ناقص، نرخ خدمت سالم را حذف نمی‌کند. snapshot بزرگ سقف دارد و دلیل ARRAY_LIMIT، FEATURE_STORAGE_LIMIT و موارد مشابه همراه داده می‌ماند. محتوای انتخابی برای وب آینده، feature snapshot و شواهد policy منتخب است، نه آرشیو لاگ خام.

actor_eligible به VALID و شاهد زمان‌دار تا زمان پایان عملیات و نقش business/user_management نیاز دارد؛ نبود/تعارض UID می‌تواند service/content سالم را قابل استفاده نگه دارد. support/system/unknown اجرای تجاری حدس زده نمی‌شوند. G00000/Successful فقط موفقیت گزارش‌شدهٔ API است؛ business_state=UNKNOWN و financial_state=OUT_OF_SCOPE می‌مانند.

observations در CR-001 به Behavior افزوده شده است. request_context مقدار IP/UA و زمینهٔ محدود را با منشأ و first_ns نگه می‌دارد. N/A/NULL و IP نامعتبر حذف می‌شوند؛ IPv4-mapped IPv6 نرمال می‌شود. IP بدنهٔ payload، metadata معتبر header فرض نمی‌شود. WP03 باید منشأ، ابهام، limited و تاریخ را پیش از ساخت entity شبکه بررسی کند؛ هیچ contextای هویت حساب نمی‌سازد.

جفت‌های دقیق ردشده: G00010/UserAccessObjectsDoesNotContainAccessObject، G00002/SessionIsNotValid، G00003/NullCheckError و GR0004/RequestRateLimiting. attempt تنها intent پیش از اجرای تأییدشده است؛ requested_service خدمت اجراشده نیست. eligibility اجرای تجاری و محتوای این موارد خاموش است. شاهد هم‌زمان dispatch قطعی و رد پیش از اجرا، EXECUTION_REFUSAL_CONFLICT است و برای بررسی جدا کنار گذاشته می‌شود.

## بودجه و آزمون

حدود پیش‌فرض هر پنجره: ۶۰هزار درخواست، ۲۰MiB state هر درخواست، ۱۲۸MiB مجموع state کدشده، چهار variant، ۳۲ سطح محتوا. سقف source wrapper یک میلیون سند است؛ مبدأ تا ۴KiB برای هر جزء و message تا ۶۷٬۱۰۸٬۸۶۴ نویسه کران دارد. حدود اندازهٔ JSON معادل RSS فرآیند نیستند. عبور از سقف، خطای صریح و عدم publication می‌خواهد، نه حذف candidate یا پیشروی cursor.

```text
python -m pip install -r requirements-userid.txt
python -B -m unittest -v tests.test_userid_contracts tests.test_userid_extraction
python -B -m contracts.userid.validate
python -B -m unittest -v tests.test_compact_extract tests.test_compact_features_v2 tests.test_compact_context tests.test_compact_request_context
python -B -m compact_product version
```

فرمان بازپخش توسعه، با مسیرهای واقعی خصوصی جایگزین شود:

```text
python -B -m userid_product.replay capture1.json.gz capture2.json.gz --scope pishkhan24:production:core --max-requests 100000 --max-total-state-mib 512 --report replay-report.json
```

این بودجهٔ بزرگ‌تر برای نگهداری تجمعی چند فایل در ابزار آفلاین است؛ پیشنهاد افزایش RAM سرور یا تنظیم ظرفیت تولید نیست. در محصول نهایی state پایدار بین پنجره‌ها در WP02 است. فایل گزارش فقط آمار/نسخه/hash دارد؛ captureها و شناسه‌ها commit نمی‌شوند.

آزمون‌ها شامل ۳۴ conformance قرارداد و ۳۹ آزمون استخراج/منبع/بازپخش جدید، به‌علاوهٔ ۹۶ رگرسیون Compact هستند. CI همین مجموعه را روی Ubuntu و Windows اجرا می‌کند؛ رسید نهایی workflow نتیجهٔ واقعی هر دو را نشان می‌دهد. manifestهای قدیمی باید همان ۸۸ فایل و SHA256 محصول 527978ec05cabc4ce3aaff20ae97f81d72c0bc5e6edf2f78467d418fbac3f6b0 را تأیید کنند.

## بازپخش نمونهٔ واقعی و حدود نتیجه

چهار فایل ۲۸ نوامبر ساعت ۱۳:۲۰ تا ۱۳:۴۰ تهران، به ترتیب UTC 09:50/09:55/10:00/10:05، با پروفایل جدید بررسی شدند. شمارش فایل‌ها ۷۸٬۳۵۵، ۷۸٬۴۳۵، ۷۵٬۰۰۶ و ۷۵٬۱۳۹ است. هر Behavior نهایی از schema و validator معنایی عبور می‌کند؛ این آزمون استخراج است، نه تشخیص ناهنجاری.

| شاخص | نتیجه |
|---|---:|
| سند ورودی | ۳۰۶٬۹۳۵ |
| درخواست منطقی یکتا | ۶۷٬۰۹۵ |
| UID معتبر / مفقود | ۶۱٬۶۴۲ / ۵٬۴۵۳ |
| UID نامعتبر / متعارض در این نمونه | ۰ / ۰ |
| شناسهٔ actor متمایز، شامل مهمان/حساب | ۵٬۰۱۶ |
| quarantine RequestID | ۰ |
| عضویت تکراری درخواست بین پنجره‌ها | ۶۰؛ همه merge شدند |
| kind قابل اثبات حساب | ۰؛ همه UNDETERMINED |
| state کامل / pending | ۶۷٬۰۲۹ / ۶۶ |
| actor_eligible / service_eligible | ۱۴٬۶۸۴ / ۱۴٬۶۸۷ |
| attempt سشن نامعتبر / محدودیت نرخ / عدم دسترسی | ۱۲۷ / ۸۶ / ۳۰ |

نوع COMPLETE پایان عمومی درخواست است و به‌تنهایی به معنی اجرای تجاری، حساب احرازشده یا خروجی موفق نیست. نقش‌های support/system/unknown و attempt eligibility جدا دارند. digest نرمال‌شدهٔ بازپخش d32b9d28c4af81ef12247863847b3298a55ac3dad9eb7be9796b2cd6ac6ce8e7 است؛ پارامترهای replay شامل scope نمونه و seen_at رشته‌ای ثابت بوده‌اند. digest به ساعت اجرای دوباره وابسته نیست. حدود ۱۶۲ ثانیه برای چهار capture همراه بررسی تمام DTOها در محیط توسعه ثبت شد؛ آزمون ظرفیت تولید محسوب نمی‌شود.

این ۵٬۰۱۶ شناسه، تعداد حساب واردشده نیستند. missing UID، unknown kind و فقدان anomaly سه موضوع متفاوت‌اند. نمونهٔ ۲۰دقیقه‌ای برای ظرفیت/تاریخچهٔ مدل نمایندهٔ کافی نیست. گزارش ماشین خصوصی بازپخش، شمارش state/role/attempt و eligibility و اندازهٔ state و زمان محاسبه را جدا دارد؛ زمان آن همراه validation توسعه است و latency زنده محسوب نمی‌شود.

NOT_RUN: اتصال ES زنده، PostgreSQL بومی، cursor/ACK/recovery، صحت Detector، مرورگر، پایداری/ظرفیت تولید، پایلوت هشت‌ساعته و نصب. نصب یا دستور تغییری روی سرور برای این تحویل لازم نیست. Q01 SQL Info/Verify/LogOut، Q02 metadata نوع هویت، Q03 mapping/rollout، Q04 Task/پورت واقعی، Q05 نگاشت تاریخی و Q06 تاریخچه/دقت روش‌ها باز هستند. WP02 می‌تواند با قرارداد حاضر شروع شود؛ نوع حساب تا دریافت شاهد، ناشناخته می‌ماند.
