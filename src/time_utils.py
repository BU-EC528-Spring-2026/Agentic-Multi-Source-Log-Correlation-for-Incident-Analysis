from __future__ import annotations
from datetime import datetime, timezone

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

def parse_mac_timestamp(month: str, day: str, time_hms: str, *, year: int) -> float:
    """mac_system_logs.csv has Month/Date/Time but NO year.
    We make the year explicit for reproducibility.

    Returns epoch seconds (UTC).
    """
    m = MONTHS.get(str(month).strip())
    if m is None:
        raise ValueError(f"Unknown month token: {month!r}")
    d = int(str(day).strip())

    t = str(time_hms).strip()
    # allow milliseconds (HH:MM:SS.mmm)
    if "." in t:
        t = t.split(".", 1)[0]
    hh, mm, ss = [int(x) for x in t.split(":")]
    dt = datetime(year, m, d, hh, mm, ss, tzinfo=timezone.utc)
    return dt.timestamp()

def iso_utc(epoch_s: float) -> str:
    return datetime.fromtimestamp(epoch_s, tz=timezone.utc).isoformat().replace("+00:00","Z")
