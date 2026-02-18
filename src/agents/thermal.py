from __future__ import annotations
from typing import List, Dict, Any
from collections import Counter

from ..events import Event

THERMAL_TOKEN = "Thermal pressure state"
HIGH_TOKEN = "Thermal pressure state: 1"
LOW_TOKEN = "Thermal pressure state: 0"

def extract(events: list[Event]) -> list[dict[str, Any]]:
    """Extract thermal events from host logs.
    This matches Tahira's focus for Demo 1: high vs low thermal pressure.
    """
    out = []
    for e in events:
        if THERMAL_TOKEN in e.message:
            out.append({
                "ts": e.ts,
                "component": (e.fields or {}).get("component"),
                "message": e.message,
                "pressure": "high" if HIGH_TOKEN in e.message else "low",
            })
    return out

def summarize(thermal_events: list[dict[str, Any]]) -> dict[str, Any]:
    c = Counter(t["pressure"] for t in thermal_events)
    high = c.get("high", 0)
    low = c.get("low", 0)

    # Keep a small sample for the demo report (not for computation).
    sample_high = [
        {
            "ts": t["ts"],
            "component": t.get("component"),
            "message": (t.get("message") or "")[:220],
        }
        for t in thermal_events if t["pressure"] == "high"
    ][:10]

    return {
        "agent": "thermal",
        "total_events": len(thermal_events),
        "high_pressure_count": high,
        "low_pressure_count": low,
        "sample_high_pressure_events": sample_high,
    }

def segments(thermal_events: list[dict[str, Any]], *, gap_s: float = 15*60) -> list[dict[str, Any]]:
    """Group thermal events into segments so we can say: 'between X and Y, thermal pressure was high-ish'.
    We split a segment if time gap > gap_s.
    """
    if not thermal_events:
        return []

    evs = sorted(thermal_events, key=lambda x: x["ts"])
    segs = []
    cur = {"start_ts": evs[0]["ts"], "end_ts": evs[0]["ts"], "count": 0, "high": 0, "low": 0}
    for t in evs:
        if t["ts"] - cur["end_ts"] > gap_s:
            segs.append(cur)
            cur = {"start_ts": t["ts"], "end_ts": t["ts"], "count": 0, "high": 0, "low": 0}
        cur["end_ts"] = t["ts"]
        cur["count"] += 1
        if t["pressure"] == "high":
            cur["high"] += 1
        else:
            cur["low"] += 1
    segs.append(cur)
    return segs
