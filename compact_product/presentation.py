"""Operator language for evidence limitations; does not change AD eligibility."""

ROLES = {
    "business": "خدمت", "user_management": "مدیریت حساب",
    "support": "پشتیبان", "system": "سیستمی", "unknown": "نقش مشخص نشده",
}
NOTES = {
    "output_binding_unconfirmed": "خروجی ثبت شده، اما ارتباط آن با خدمت این درخواست تأیید نشده است؛ برای تحلیل محتوای خروجی معتبر نیست.",
    "input_binding_unconfirmed": "ورودی ثبت شده، اما ارتباط آن با خدمت این درخواست تأیید نشده است؛ برای تحلیل محتوای ورودی معتبر نیست.",
    "conflicting_dispatch": "شواهد خدمت مقصد همین درخواست با یکدیگر تعارض دارند؛ انتساب قطعی ممکن نیست.",
    "unresolved_dispatch": "فراخوانی InvoiceRegister دیده شده، اما خدمت مقصد از شواهد همین درخواست مشخص نشده است.",
    "postal_cache_result_unconfirmed": "کد پستی برگشتی کش مبهم است یا شاهد زمان معتبر ندارد.",
    "input_unavailable": "ورودی قابل استفاده در شواهد این درخواست موجود نیست.",
    "output_unavailable": "خروجی قابل استفاده در شواهد این درخواست موجود نیست.",
    "input_conflict": "بیش از یک ورودی متفاوت ثبت شده و انتخاب یک ورودی قطعی ممکن نیست.",
    "output_conflict": "بیش از یک خروجی متفاوت ثبت شده و انتخاب یک خروجی قطعی ممکن نیست.",
    "operation_conflict": "بیش از یک API برای این درخواست ثبت شده است.",
    "operation_field_conflict": "فیلدهای نام عملیات با یکدیگر سازگار نیستند.",
    "session_conflict": "بیش از یک شناسهٔ نشست برای این درخواست ثبت شده است.",
    "session_field_conflict": "فیلدهای شناسهٔ نشست با یکدیگر سازگار نیستند.",
    "session_unavailable": "شناسهٔ نشست قابل اتکا موجود نیست.",
    "timestamp_unavailable": "زمان معتبر برای بخشی از شواهد موجود نیست.",
    "operation_completion_unavailable": "شاهد معتبر پایان عملیات موجود نیست.",
    "multiple_completion_variants": "چند روایت از پایان عملیات ثبت شده است.",
    "result_conflict": "کدهای نتیجهٔ متفاوتی برای پایان همین درخواست ثبت شده است.",
    "message_field_conflict": "فیلدهای متن لاگ با یکدیگر سازگار نیستند.",
    "prior_fragments_expired": "مهلت تکمیل بخشی از شواهد قبلی پایان یافته؛ کامل‌بودن محتوا تأیید نشده است.",
    "auxiliary_content_out_of_scope": "این API پشتیبان یا سیستمی است؛ محتوای آن طبق دامنهٔ محصول ذخیره و تحلیل نمی‌شود. این وضعیت خطا نیست.",
    "input_value_replaced_by_features": "ورودی حجیم بوده؛ ویژگی‌ها، اندازه و اثر انگشت به‌جای متن کامل نگهداری شده‌اند.",
    "output_value_replaced_by_features": "خروجی حجیم بوده؛ ویژگی‌ها، اندازه و اثر انگشت به‌جای متن کامل نگهداری شده‌اند.",
}
for direction, label in (("inputs", "ورودی"), ("outputs", "خروجی")):
    NOTES[direction + "_parse_error"] = f"بخشی از محتوای {label} قابل خواندن به‌صورت JSON نبوده است."
    NOTES[direction + "_content_limit"] = f"بخشی از محتوای {label} از سقف پردازش عبور کرده است."


def data_note(code):
    return NOTES.get(code, "برای بخشی از شواهد، محدودیت یا ابهام ثبت شده است؛ کد فنی در زیر آمده است.")
