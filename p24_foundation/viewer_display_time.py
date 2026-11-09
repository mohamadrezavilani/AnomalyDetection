"""Human-readable Tehran time; original evidence and UTC API fields stay intact."""
from datetime import datetime
from zoneinfo import ZoneInfo


def tehran_time(value):
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
    if value is None or value == '':
        return '—'
    try:
        parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            return 'زمان بدون منطقهٔ زمانی'
        return parsed.astimezone(ZoneInfo('Asia/Tehran')).strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError, OverflowError):
        return 'زمان نامشخص'
