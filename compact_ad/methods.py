"""Explicit readiness contract. No financial inference or unverified durations."""

METHODS = {
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
    "execution_duration": "واحد ExecutionTime تأیید نشده است",
}
STATUSES = ("NORMAL", "ANOMALY", "INSUFFICIENT_DATA", "INVALID_INPUT")
