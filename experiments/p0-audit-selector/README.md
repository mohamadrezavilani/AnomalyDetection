# کاندیدای P0

Patch و فایل `audit_scope_candidate.py` همراه Shadow و NativePG هستند. این پوشه جدا از سورس عملیاتی است. نتیجهٔ آخرین NativePG با Fixture مصنوعی `PASS_SYNTHETIC_NATIVE_PG_PRELIMINARY` است.

- `shadow/` شامل diff، تست محلی انتخاب‌گر و Harness خواندنی است.
- `native-pg/` شامل Fixtureهای PostgreSQL و آزمون‌های پیش‌پرواز است.
- در این نسخه، اجرای ابزارها به پروژهٔ مرجع مهرشده و `--reference-db-oid` از محیط آزمایشی مجاز نیاز دارد. تست‌های unittest از fixture و اتصال شبیه‌سازی‌شده استفاده می‌کنند.

[وضعیت، محدودیت‌ها و گیت پذیرش](../../docs/p0/STATUS_FA.md)
