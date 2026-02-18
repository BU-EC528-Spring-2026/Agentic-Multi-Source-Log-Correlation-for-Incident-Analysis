from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Iterable, List, Dict, Optional

from .events import Event
from .time_utils import parse_mac_timestamp

# ----------------------------
# Omar: ingestion is boring, but if it's wrong everything downstream is wrong.
# So keep it strict, keep it testable, keep it readable.
# ----------------------------

REQUIRED_MAC_COLS = {"Month", "Date", "Time", "Component", "Content"}

def ingest_mac_system_logs(csv_path: str | Path, *, year: int, source: str = "host") -> list[Event]:
    """Ingest the FULL mac_system_logs.csv (Tahira dataset).
    Expected columns: Month, Date, Time, User, Component, Content
    """
    p = Path(csv_path)
    if not p.exists():
        raise FileNotFoundError(f"mac_system_logs.csv not found: {p}")

    events: list[Event] = []
    with p.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        headers = set(reader.fieldnames or [])
        missing = REQUIRED_MAC_COLS - headers
        if missing:
            raise ValueError(f"CSV missing columns: {sorted(missing)}. Found: {sorted(headers)}")

        for row in reader:
            ts = parse_mac_timestamp(row["Month"], row["Date"], row["Time"], year=year)
            msg = str(row.get("Content") or "")
            events.append(Event(
                ts=ts,
                source=source,
                message=msg,
                level=None,
                fields={
                    "user": row.get("User"),
                    "component": row.get("Component"),
                    "month": row.get("Month"),
                    "date": row.get("Date"),
                    "time": row.get("Time"),
                },
            ))

    return events

def load_jsonl(path: str | Path) -> list[dict[str, Any]]:
    p = Path(path)
    rows: list[dict[str, Any]] = []
    with p.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON on line {i} in {p}: {e}") from e
    return rows

def ingest_auth_jsonl(path: str | Path, *, source: str = "auth") -> list[Event]:
    """Optional second source ingestion (JSONL).
    Minimal schema:
      - timestamp (ISO string) OR ts (epoch seconds)
      - message (or msg/event)
      - optional level/severity
    """
    from dateutil import parser as dtparser
    from datetime import timezone

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"auth jsonl not found: {p}")

    rows = load_jsonl(p)
    events: list[Event] = []
    for r in rows:
        msg = r.get("message") or r.get("msg") or r.get("event") or ""
        level = r.get("level") or r.get("severity")
        if r.get("ts") is not None:
            ts = float(r["ts"])
        else:
            dt = dtparser.parse(r["timestamp"])
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            ts = dt.timestamp()

        fields = {k: v for k, v in r.items() if k not in {"message","msg","event","level","severity","ts","timestamp"}}
        events.append(Event(ts=ts, source=source, message=str(msg), level=level, fields=fields))
    return events
