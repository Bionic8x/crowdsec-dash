"""Normalise the many timestamp formats we meet into 'YYYY-MM-DDTHH:MM:SSZ' (UTC)."""
import re
from datetime import datetime, timedelta, timezone

from .db import iso

_TS = re.compile(
    r"(?P<d>\d{4}-\d{2}-\d{2})[T ](?P<t>\d{2}:\d{2}:\d{2})(?P<frac>\.\d+)?\s*(?P<tz>Z|UTC|[+-]\d{2}:?\d{2})?"
)


def norm_ts(value: str | None) -> str | None:
    """'2026-10-10T18:16:09.123456Z', '2026-10-10 18:16:09 +0000 UTC', ... -> '2026-10-10T18:16:09Z'"""
    if not value:
        return None
    m = _TS.search(value)
    if not m:
        return None
    dt = datetime.strptime(f"{m['d']} {m['t']}", "%Y-%m-%d %H:%M:%S")
    tz = m["tz"]
    if tz and tz not in ("Z", "UTC"):
        sign = 1 if tz[0] == "+" else -1
        hh, mm = int(tz[1:3]), int(tz[-2:])
        dt = dt - sign * timedelta(hours=hh, minutes=mm)
    return iso(dt.replace(tzinfo=timezone.utc))


_DUR = re.compile(r"(-?\d+(?:\.\d+)?)(h|ms|m|s)")


def parse_go_duration(value: str | None) -> timedelta | None:
    """Go-style durations as LAPI returns them: '3h59m12.5s', '-1m', '4h'."""
    if not value:
        return None
    total = 0.0
    found = False
    for num, unit in _DUR.findall(value):
        found = True
        n = float(num)
        total += {"h": 3600, "m": 60, "s": 1, "ms": 0.001}[unit] * n
    return timedelta(seconds=total) if found else None


def parse_nginx_time(value: str) -> str:
    """'10/Oct/2026:14:16:09 -0400' -> '2026-10-10T18:16:09Z'"""
    return iso(datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z"))
