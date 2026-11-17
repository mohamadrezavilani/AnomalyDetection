# گزارش تشخیصی محدود AD

`focused_diagnostics.py` اطلاعات jobهای مرتبط با پرونده‌ها را بدون window_body و source_proof حجیم، با lookup دقیق کلید اصلی در batchهای ۱۶تایی می‌خواند. همان READ ONLY / REPEATABLE READ و نقش محدود نصب‌شده لازم‌اند. سقف ۱۰۲۴ scope، هشت MiB ردیف، ۴۵ ثانیه بودجهٔ اسمی و timeout اختصاصی ۱۲۰۰ میلی‌ثانیه‌ایِ اتصال مشاهده‌گر دارد. statement جاری/اتصال می‌تواند اندکی بعد از مهلت تمام شود؛ موعد، تضمین hard real-time نیست. هیچ تنظیم عمومی PostgreSQL عوض نمی‌شود.

حداکثر سه درخواست با کیفیت WAITING_FOR_BOUNDED_READMODEL در adp_journeys بر اساس next_read_ns جدیدتر، از read-model موجود Viewer خوانده می‌شوند؛ این نمونه شامل همهٔ targetهای خطا نیست. ابزار، سفر را ذخیره نمی‌کند، مدل یا Worker را اجرا/متوقف نمی‌کند و به جدول محصول چیزی نمی‌نویسد. فقط JSON تازه زیر reports ایجاد می‌شود. هیچ initialization، prepare، grant، DDL، reset یا recheck اجرا نمی‌شود. خطا، فقط نوع و محل کدِ داخل پکیج‌های شناخته‌شده را دارد؛ پیام exception، SQL، پارامتر، locals و payload صادر نمی‌شوند. کلیدهای داخلی و وضعیت jobها خصوصی‌اند؛ گزارش را در Git عمومی قرار ندهید. این ابزار jobهای feature/population را صادر نمی‌کند و فقط scopeهای actor با job_session موجود را پوشش می‌دهد.

یک خواندن موفقِ سفر، موفق‌بودن مرحلهٔ ذخیرهٔ آن در AD یا رفع خطای قبلی را ثابت نمی‌کند. مرحلهٔ Worker فعلی هر دو را read_viewer_journey می‌نامد؛ siteهای خواندن به تشخیص این دو کمک می‌کنند. نبود درخواست معوق یا تمام‌شدن مهلت، NOT_RUN است و موفقیت تشخیص محسوب نمی‌شود. کامل‌بودن این خروجی، پذیرش دقت هیچ معیار نیست.

از پوشهٔ پروژه یا یک checkout ابزار اجرا کنید و project را به نصب اصلی اشاره دهید:

```powershell
& E:\P24\pishkhan24\.venv\Scripts\python.exe -B .\AnomalyDetection\validation\focused_diagnostics.py --project E:\P24\pishkhan24
```

اگر فایل ابزار را جدا دانلود کردید، فقط مسیر قبل از `--project` را به همان فایل عوض کنید. کد نصب‌شده پیش از import با manifest خودش تأیید می‌شود. فایل ابزار جزو inventory عملیاتی AD نیست؛ دو manifest و هویت runtimeها تغییر نکرده‌اند. دانلود این ابزار به معنی نصب یا توقف کارگر نیست. تست‌های ابزار در validation/test_focused_diagnostics.py هستند و جدا با unittest اجرا می‌شوند.

JSON تازهٔ `AD_Focused_Diagnostics_*.json` که مسیرش مقابل output چاپ می‌شود را ارسال کنید؛ PARTIAL یا BLOCKED را با دادهٔ کامل یا صفر کار تفسیر نکنید. این داده، مکمل acceptance-report است و زمان/نسخهٔ خودش را دارد؛ snapshot قدیمی را جای آن بازنویسی نمی‌کنیم.
