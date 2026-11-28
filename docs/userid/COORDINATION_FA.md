# تصمیم‌های معماری و برنامهٔ ادغام

نسخهٔ مرجع مشترک ۱٫۳؛ این تصمیم‌ها در دامنهٔ WP00 تثبیت شده‌اند. تصمیم جدید مالک و CR پذیرفته‌شده می‌توانند آن‌ها را نسخه‌دار اصلاح کنند. وجود این فایل، مأموریت اجرایی تازه‌ای برای بسته‌های تخصیص‌نیافته ایجاد نمی‌کند.

## تصمیم‌ها

| شناسه | تصمیم و دلیل | اثر |
|---|---|---|
| D01 | نصب جدید در DB مستقل؛ جلوگیری از آمیختن هویت و baseline سشن با UserID | WP02/WP05؛ فقط خانوادهٔ p24_userid_* و کنترل expected DB/instance |
| D02 | کد Compact فعلی در این فاز دست‌نخورده می‌ماند؛ نصب ارائه از نسخهٔ ثابت اجرا شود | همه؛ هیچ activation از طریق import یا تغییر manifest قدیمی |
| D03 | مرزهای کد جدید در userid_product و مالکیت مسیرها مشخص است | WP01-WP05؛ root/shared modules صاحب تغییر واحد دارند |
| D04 | بازاستفادهٔ parser/feature خالص فقط از adapter صریح و با آزمون و نسخهٔ معلوم | WP01/WP03؛ Session store/runtime قدیمی وارد محصول جدید نمی‌شود |
| D05 | UserID در session_id قرار نمی‌گیرد؛ قرارداد جدید نام و نسخهٔ جدا دارد | همه؛ schema فیلد session_id را در DTO نرمال‌شده نمی‌پذیرد |
| D06 | هویت، نوع هویت، محتوا و eligibility مستقل‌اند؛ نبود UID سرویس سالم را حذف نمی‌کند | WP01/WP03/WP04؛ پوشش و Unknown صریح |
| D07 | کلید رفتار مستقل از actor است؛ تغییر هویت همان رفتار را revision می‌کند | WP01/WP02/WP03؛ اصلاح و retraction سهم قبلی و مرجع وابسته |
| D08 | publication/cursor/dirty و نتیجه/ACK، fence و commit مشخص دارند | WP02/WP03؛ crash و source/reference change باید آزموده شوند |
| D09 | پورت جدید فقط ۵۰۲۲؛ Task و controller محدود به instance هستند | WP05؛ rollback، Writer قدیمی را روشن نمی‌کند |
| D10 | schema و semantic validator و مثال با هم قراردادند | همه؛ صرف JSON Schema format بدون checker، دقت Int64 را تضمین نمی‌کند |
| D11 | اسناد جاری مخزن canonical و Page نمای هم‌نسخهٔ قابل ارسال است | WP00؛ اصلاح در Git و انتقال نسخه/commit به Page |
| D12 | بدهی cleanup بعد از dependency audit بسته می‌شود | همه؛ فایل قدیمیِ مصرف‌شده با حدس حذف نمی‌شود |

نام p24_userid_v1 گزینهٔ مبنا برای نصب جدید است؛ موجودبودن/مالکیت آن در زمان نصب بررسی و در config ثبت می‌شود. نمونهٔ تست از p24_userid_test_contracts استفاده می‌کند. هیچ DB در WP00 ساخته نشده است.

## بودجه‌های اولیه و تصمیم‌های باز

سقف‌های ورودی، حافظه، candidate و provenance باید پیش از publication اعمال شوند. schema v1 برای هر درخواست حداکثر چهار UserID متمایز و ۱۶ شاهد هویت نمونه‌برداری‌شده دارد. محدودکردن نمونهٔ provenance، مجوز حذف candidate متعارض یا نادیده‌گرفتن خطا نیست. عبور از حد نمایش candidate، خطای صریح و عدم پیشروی cursor می‌خواهد.

مقادیر اولیهٔ عملیاتی از قرارداد پذیرفته‌شدهٔ قبلی گرفته می‌شوند: pending شش پنجره، overlap دو پنجره، lag شصت ثانیه. این‌ها تضمین finality یا زمان قطعی ورود همهٔ لاگ‌ها نیستند. تنظیم نهایی سقف‌ها و بودجهٔ history با ۱۲ پنجرهٔ جدید و پایلوت نماینده سنجیده می‌شود.

Q01 تا Q06 در MASTER_PLAN_FA ثبت‌اند. نبود metadata نوع هویت مانع پیاده‌سازی identity_status نیست؛ kind تا دریافت شاهد UNDETERMINED می‌ماند. دقت Detector و پایداری هشت‌ساعته خروجی WP00 نیستند.

## ترتیب ادغام و نقاط اتصال

۱. WP00: قرارداد v1، مثال‌ها و CI مشترک به main برسند.
۲. WP01 و WP02: adapter/identity/extraction و storage interface علیه همین fixtureها جدا ساخته شوند؛ کلید و revision و خطا قبل از اتصال نهایی یکسان باشند.
۳. WP03: ابتدا FeatureSet و snapshot/reference interface، سپس روش‌ها و ادامهٔ چندروزه؛ تا schema/feature مشخص نشده، مدل فرضی کامل اعلام نشود.
۴. WP04: می‌تواند با مثال‌های CaseView/API شروع کند؛ اتصال به DB و نتیجه پس از تثبیت read API انجام شود.
۵. WP05: طرح جداسازی و نمایش آرشیوی موازی آماده شود؛ عملیات سرور پس از پیش‌شرط‌ها و مأموریت اجرایی انجام می‌شود.
۶. WP06: از همان قراردادهای مشترک، آزمون مستقل می‌سازد؛ پیش از ادغام نهایی، اتصال واقعی و recovery و مرورگر را بررسی می‌کند.

هر PR باید WP، نسخهٔ قرارداد، commit مبنا، اثر بر نصب قدیمی، migration لازم یا NONE، آزمون واقعی و NOT_RUN را بیان کند. ادغام main طبق اجازهٔ مالک پس از بررسی تغییر و موفقیت بررسی‌های مرتبط انجام می‌شود. main جدید به معنی نصب روی سرور نیست.

## مرز مالکیت و پیشگیری از تداخل

| فایل یا قلمرو مشترک | هماهنگ‌کنندهٔ تغییر |
|---|---|
| contracts/userid، نسخهٔ DTO، الگوریتم کلید و enum | WP00 با تولیدکننده و مصرف‌کنندهٔ قرارداد |
| root package/dependency/config مشترک userid_product | WP00 با WP05 و بستهٔ متأثر |
| migration و قیود تراکنش و repository | WP02؛ تغییر قرارداد مرزی با WP00 |
| تعریف feature و model/reference نسخه‌دار | WP01 و WP03 با WP00 |
| read API، CaseView و feedback | WP04 با WP02/WP03 |
| Task/launcher/پورت/آرشیو قدیمی | WP05؛ سایر بسته‌ها درجا تغییر نمی‌دهند |
| dataset و fixture مشترک و acceptance | WP06 با WP00؛ دادهٔ واقعی خصوصی می‌ماند |

هر ایجنت شاخه/worktree مستقل دارد. ادغام نباید تغییر دیگران را reset، overwrite یا force-push کند. اگر main جلو رفته، ابتدا تفاوت و وابستگی بررسی و سپس شاخه به‌روز و آزمون لازم تکرار می‌شود. شاخهٔ فعال دیگران محل حل تعارض نیست.

## تغییر قرارداد

CR شامل شناسه، علت و شاهد، نسخهٔ فعلی/جدید، بسته‌های متأثر، اثر بر داده و rollback، راه سازگاری و آزمون است. یک پیشنهاد، تصمیم پذیرفته‌شده یا کار انجام‌شده محسوب نمی‌شود. تغییر enum/meaning/key/eligibility بدون به‌روزرسانی schema، مثال و تست مصرف‌کننده ادغام نمی‌شود.

## قالب گزارش

```yaml
document: P24-USERID-REBUILD-MASTER
document_version: "1.3"
work_package: WPxx
agent: assigned-by-owner
base_commit: exact-sha
result_commit: exact-sha-or-NOT_CREATED
contract_versions: p24-userid-1 / userid-identity-1 / userid-features-1
status: READY | IN_PROGRESS | BLOCKED | REVIEW | VERIFIED | INTEGRATED
files_changed: paths
contract_changes: NONE-or-CR-id
tests_run: commands-and-environment-and-results
tests_not_run: NOT_RUN-with-reason
legacy_effect: exact-effect-or-NONE
dependencies: exact-WP-or-Q
handoff: PR-or-commit-or-delivered-file
next_action: next-independent-or-dependent-action
```

مسئول هر بسته و اختیار پیام‌رسانی جدا تعیین می‌شوند. دسترسی خودکار به چت یا فایل ایجنت دیگر فرض نمی‌شود؛ مالک می‌تواند همین گزارش و commit واقعی را منتقل کند. انتشار این سند، پیامی برای ایجنت‌های دیگر ارسال نکرده است.

## پایان WP00 و کارهای بعدی

معیار پایان این تحویل: معماری و قرارداد v1 قابل دریافت، schema/مثال/semantic conformance بررسی‌شده، مرز بسته‌ها و نقاط ادغام مشخص و تغییر روی main ادغام شود. اجرای WP01 تا WP06، نصب، migration، توقف Writer قدیمی، آزمون بومی DB/مرورگر، پایلوت و حذف DB در این تحویل انجام نمی‌شوند.

راهنماهای عملیاتی DETECTORS، OPERATIONS و TESTING همراه پیاده‌سازی اجزای مربوط کامل می‌شوند. این اسناد جایگزین روش و کد واقعی آن اجزا نیستند.
