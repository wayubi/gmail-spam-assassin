"""Retention ages for the quarantine list: 14d, 3m, 1y.

Days are exact 24-hour periods. Months and years are calendar arithmetic,
clamped to the last valid day, so three months before 31 May is 28 or 29
February rather than 30 August. Every comparison is in UTC.

A future timestamp cannot keep a message alive forever: it is treated as
"now", so the clock starts when it is first seen.
"""

import calendar
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

_UNITS = {
    "d": "d",
    "day": "d",
    "days": "d",
    "m": "m",
    "month": "m",
    "months": "m",
    "y": "y",
    "year": "y",
    "years": "y",
}

_NAMES = {"d": ("day", "days"), "m": ("month", "months"), "y": ("year", "years")}

_PATTERN = re.compile(r"^\s*(\d+)\s*([a-z]+)?\s*$", re.IGNORECASE)


@dataclass(frozen=True)
class Age:
    count: int
    unit: str  # "d", "m" or "y"

    @classmethod
    def parse(cls, spec):
        match = _PATTERN.match(spec or "")
        if not match:
            raise ValueError("use a number with an optional unit: 14d, 3m, 1y")
        count = int(match.group(1))
        if count < 1:
            raise ValueError("must be at least 1")
        if count > 1000:
            raise ValueError("must be 1000 or less")
        raw = (match.group(2) or "d").lower()
        if raw not in _UNITS:
            raise ValueError("unknown unit %r; use d, m or y" % match.group(2))
        return cls(count, _UNITS[raw])

    @property
    def text(self):
        singular, plural = _NAMES[self.unit]
        return "%d %s" % (self.count, singular if self.count == 1 else plural)

    def cutoff(self, now=None):
        """The instant before which a message counts as expired."""
        now = _utc(now)
        if self.unit == "d":
            return now - timedelta(days=self.count)
        months = self.count if self.unit == "m" else self.count * 12
        return _shift_months(now, -months)

    def expired(self, stamp, now=None):
        """True/False, or None when the timestamp cannot be read."""
        when = parse_iso(stamp)
        if when is None:
            return None
        now = _utc(now)
        if when > now:
            when = now
        return when <= self.cutoff(now)


def parse_iso(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return _utc(parsed)


def _utc(value):
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _shift_months(value, months):
    index = value.year * 12 + (value.month - 1) + months
    year, month = divmod(index, 12)
    month += 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)
