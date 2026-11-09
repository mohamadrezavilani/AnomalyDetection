"""Exact offset-bearing source times; no float conversion or rounding.

Promoted from the reviewed Phase 1 evidence_sample_contracts helper.
Source clocks and representational precision are separate concerns.
"""
from __future__ import annotations

import calendar
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .errors import FoundationError

ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$")
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

@dataclass(frozen=True)
class SourceTime:
    epoch_ns: int
    fraction_digits: int
    original: str

    @property
    def floor(self):
        seconds, ns = divmod(self.epoch_ns, 1_000_000_000)
        return EPOCH + timedelta(seconds=seconds, microseconds=ns // 1000)

    @property
    def precision(self):
        if self.fraction_digits > 6:
            return "submicrosecond"
        if self.fraction_digits > 3:
            return "microsecond"
        if self.fraction_digits:
            return "millisecond"
        return "second"

    @property
    def resolution_ns(self):
        return 10 ** (9 - self.fraction_digits)

    def public(self):
        return dict(epoch_ns=str(self.epoch_ns), fraction_digits=self.fraction_digits,
                    precision=self.precision, floor_utc=self.floor.isoformat().replace("+00:00", "Z"))

def parse_time(value):
    if not isinstance(value, str):
        raise FoundationError("source_time_requires_offset")
    match = ISO.fullmatch(value)
    if not match:
        raise FoundationError("source_time_requires_offset")
    wall, fraction, offset = match.groups()
    fraction = fraction or ""
    try:
        offset_seconds = 0
        if offset != "Z":
            hours, minutes = map(int, offset[1:].split(":"))
            if hours > 23 or minutes > 59:
                raise ValueError
            offset_seconds = (hours * 3600 + minutes * 60) * (1 if offset[0] == "+" else -1)
        date = datetime.fromisoformat(wall)
        seconds = calendar.timegm(date.timetuple()) - offset_seconds
    except (ValueError, OverflowError):
        raise FoundationError("invalid_source_time") from None
    return SourceTime(seconds * 1_000_000_000 + int(fraction.ljust(9, "0") or "0"), len(fraction), value)

def microsecond_cutoff(value):
    parsed = parse_time(value)
    if parsed.epoch_ns % 1000:
        raise FoundationError("projection_cutoff_requires_microseconds")
    return parsed

def compatible_times(a, b):
    if a is None or b is None:
        return a is b
    coarse, fine = sorted((a, b), key=lambda t: t.fraction_digits)
    return fine.epoch_ns // coarse.resolution_ns == coarse.epoch_ns // coarse.resolution_ns

