"""Explicit readiness contract. No financial inference or unverified durations."""

METHODS = {
    'access_denied_attempts': dict(label='تکرار تلاش بدون مجوز دسترسی',unit='نشست و خدمت درخواستی / پنج دقیقه',features='G00010 و نام دقیق رد دسترسی در پایان همان درخواست',minimum='۲۰ رد معتبر در دست‌کم ۳۰ ثانیه؛ مقایسه با سابقهٔ همان نشست در صورت وجود ۱۲ پنجره'),
    'invalid_session_attempts': dict(label='تلاش پرتکرار با نشست نامعتبر',unit='IP مشاهده‌شده / پنج دقیقه',features='G00002 | SessionIsNotValid و IP بدون تعارض در همان درخواست',minimum='۳۰ رد و دست‌کم ۵ توکن متفاوت یا ۱۰۰ رد؛ دست‌کم ۳۰ ثانیه؛ IP هویت یک نفر نیست'),
    'rate_limit_rejections': dict(label='تکرار درخواست ردشده با محدودیت نرخ',unit='نشست و خدمت درخواستی / پنج دقیقه',features='GR0004 و مقصد درخواستی معتبر؛ مستقل از اجرای خدمت',minimum='۱۲ پنجرهٔ مرجع؛ اجرای موفق یا پرداخت فرض نمی‌شود'),
    'service_latency': dict(label='افزایش زمان اجرای خدمت',unit='صدک ۹۵ ExecutionTime خدمت / پنج دقیقه',features='زمان پایان درخواست با انتساب معتبر',minimum='۱۲ پنجرهٔ مرجع و ۱۰ زمان معتبر در هر پنجره؛ مقایسهٔ نسبی'),
    'isolation_forest': dict(label='الگوی چندمتغیرهٔ نشست',unit='نشست / پنج دقیقه',features='حجم، تنوع خدمات، سهم خدمت غالب و آنتروپی',minimum='۱۶۰ بردار گذشته و ۱۰ رفتار فعلی؛ آموزش و کالیبراسیون جدا'),
    'service_sequence': dict(label='توالی کم‌سابقهٔ خدمات',unit='نشست / پنج دقیقه',features='ترتیب درخواست‌ها با اتصال به پنجرهٔ قبلی',minimum='۳۶ پنجره و ۵۰۰ انتقال گذشته؛ ۱۲ پنجرهٔ کالیبراسیون و تکرار انتقال کم‌سابقه'),
    'timing_regularization': dict(label='نظم زمانی غیرمعمول',unit='نشست / پنج دقیقه',features='فاصلهٔ زمانی درخواست‌ها',minimum='۲۰ فاصله در حداقل ۶۰ ثانیه و ۳۰ نمونهٔ مرجع در ۱۲ پنجره'),
    "service_rate": dict(
        label="نرخ درخواست خدمت",
        unit="خدمت / پنج دقیقه",
        features="service_rate_eligible + service_key",
        minimum="۱۲ پنجرهٔ گذشته و ۳۰ رفتار مرجع",
    ),
    "actor_rate": dict(
        label="نرخ درخواست نشست",
        unit="نشست و خدمت / پنج دقیقه",
        features="Session معتبر + session_eligible",
        minimum="۱۲ پنجره و ۳۰ رفتار؛ مرجع صدک ۹۵ نرخ نشست‌های گذشته",
    ),
    "service_mix": dict(
        label="ترکیب خدمت‌های نشست",
        unit="نشست / پنج دقیقه",
        features="Session معتبر + service_key",
        minimum="۱۲ پنجره و ۱۰۰ رفتار مرجع؛ حداقل ۱۰ رفتار نشست",
    ),
    "reported_result": dict(
        label="تغییر نتیجهٔ گزارش‌شده",
        unit="خدمت / پنج دقیقه",
        features="result_eligible + result_code",
        minimum="۱۲ پنجره و ۳۰ نتیجهٔ مرجع؛ ۱۰ نتیجهٔ فعلی",
    ),
    "repeated_target": dict(
        label="تکرار هدف ورودی",
        unit="نشست و خدمت / پنج دقیقه",
        features="input_feature_eligibility.targets",
        minimum="۱۲ پنجره و ۳۰ ورودی معتبر مرجع",
    ),
    "target_diversity": dict(
        label="تنوع هدف ورودی",
        unit="نشست و خدمت / پنج دقیقه",
        features="input_feature_eligibility.targets",
        minimum="۱۲ پنجره و ۳۰ ورودی معتبر مرجع",
    ),
    "response_shape": dict(
        label="تغییر ساختار پاسخ",
        unit="خدمت / پنج دقیقه",
        features="output_feature_eligibility.shape",
        minimum="۱۲ پنجره و ۳۰ پاسخ معتبر مرجع؛ حداقل ۱۰ پاسخ فعلی",
    ),
    "response_numeric": dict(
        label="تغییر مقادیر پاسخ",
        unit="خدمت و مسیر ویژگی / پنج دقیقه",
        features="output_feature_eligibility.numeric",
        minimum="۱۲ پنجره و ۳۰ پاسخ عددی مرجع؛ ۱۰ مقدار فعلی",
    ),
}
OUT_OF_SCOPE = {
    "financial_chain": "روابط مالی خارج از دامنه است",
}
STATUSES = ("NORMAL", "ANOMALY", "INSUFFICIENT_DATA", "INVALID_INPUT")
