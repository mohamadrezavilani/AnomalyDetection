# AnomalyDetection پیشخوان۲۴

سورس توسعه و تحویل ایجنت برای تشخیص ناهنجاری رفتاری پیشخوان۲۴. Viewer رویدادهای Elasticsearch را به اجرای منطقی و شاهد رفتار تبدیل می‌کند. AD شواهد را می‌خواند، ارزیابی را در PostgreSQL نگه می‌دارد و سیگنال‌ها را برای بازبینی اپراتور به پرونده تبدیل می‌کند.

## شروع ایجنت جدید

1. دامنهٔ کار و قواعد پذیرش را بخوان. [AGENTS.md](AGENTS.md)
2. معماری، مسیر داده، هویت و دستور آزمون را مرور کن. [راهنمای ورود](docs/AGENT_ONBOARDING_FA.md)
3. وضعیت کاندیدا و گیت‌های پیش از انتشار را بخوان. [وضعیت P0](docs/p0/STATUS_FA.md)
4. وضعیت هر خانواده را از ماتریس دنبال کن. [ماتریس ۳۰ معیار](docs/criteria/ALL_30_CRITERIA_STATUS.csv)

| بخش | وضعیت تحویل |
|---|---|
| `AnomalyDetection/` | سورس مرجع WinStart و Fixtureهای توسعه. ۶۱ ماژول runtime با Release اصلی مطابق‌اند. |
| `experiments/p0-audit-selector/` | Patch و کاندیدای P0 در مسیر مستقل. ۱۰ سناریوی NativePG قبلی با دادهٔ مصنوعی پاس شده‌اند. وضعیت `PRELIMINARY / NOT_DEPLOYED` است. |
| پذیرش مدل | ۰ از ۳۰ معیار پذیرش نهایی دارند. |
| اولویت | رقابت، Crash/Restart و بازپخش همسان در PostgreSQL ایزوله، پیش از نصب P0. |

## آزمون آفلاین

از ریشهٔ مخزن با Python 3.10 یا جدیدتر اجرا کن.

```bash
python -B scripts/verify_source.py
python -B -m unittest discover -s AnomalyDetection/tests -t AnomalyDetection
python -B AnomalyDetection/validation/check_install_release.py
python -B -m unittest discover -s experiments/p0-audit-selector/shadow
python -B -m unittest discover -s experiments/p0-audit-selector/native-pg
```

برای نصب یا بازپخش منبع واقعی، Release مهرشده، Runtime Viewer R3 و شواهد مجاز را از مالک بگیر. `run_anomaly.py` و `Install_Update.py` در این مخزن برای مطالعهٔ قرارداد نسخه و نصب‌اند. فایل‌های عملیاتی و راه‌اندازهای محیط واقعی در بستهٔ تحویل مجاز قرار دارند. [فایل‌های مرجع](docs/SOURCE_ARTIFACTS_FA.md)
