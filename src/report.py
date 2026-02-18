from __future__ import annotations
from typing import Any
from collections import Counter
from .events import Event
from .time_utils import iso_utc

def timeline(events: list[Event], *, limit: int = 200) -> list[dict[str, Any]]:
    """Timeline preview (capped for readability)."""
    out = []
    for e in sorted(events, key=lambda x: x.ts)[:limit]:
        out.append({
            "time": iso_utc(e.ts),
            "ts": e.ts,
            "source": e.source,
            "component": (e.fields or {}).get("component"),
            "message": e.message[:220],
        })
    return out

def source_counts(events: list[Event]) -> dict[str, int]:
    c = Counter(e.source for e in events)
    return dict(sorted(c.items(), key=lambda kv: (-kv[1], kv[0])))

def component_counts(host_events: list[Event], *, top_k: int = 10) -> list[dict[str, Any]]:
    c = Counter((e.fields or {}).get("component") for e in host_events)
    items = [(k, v) for k, v in c.items() if k]
    items.sort(key=lambda kv: kv[1], reverse=True)
    return [{"component": k, "count": v} for k, v in items[:top_k]]

def build_report(*, all_events: list[Event], window_events: list[Event], thermal_summary: dict[str, Any], thermal_segments: list[dict[str, Any]]) -> dict[str, Any]:
    start_ts = min((e.ts for e in window_events), default=None)
    end_ts = max((e.ts for e in window_events), default=None)

    host_events = [e for e in all_events if e.source == "host"]

    return {
        "meta": {
            "sources": sorted({e.source for e in all_events}),
            "all_events_count": len(all_events),
            "window": {
                "start_time": iso_utc(start_ts) if start_ts else None,
                "end_time": iso_utc(end_ts) if end_ts else None,
                "events_in_window": len(window_events),
                "counts_by_source": source_counts(window_events),
            },
            "top_host_components": component_counts(host_events),
        },
        "signals": {
            "thermal": {
                **thermal_summary,
                "segments": [
                    {
                        **s,
                        "start_time": iso_utc(s["start_ts"]),
                        "end_time": iso_utc(s["end_ts"]),
                    }
                    for s in thermal_segments
                ],
            }
        },
        "timeline": timeline(window_events),
        "narrative": {
            "human_summary": (
                f"Thermal pressure events detected in host logs: total={thermal_summary.get('total_events')}, "
                f"high={thermal_summary.get('high_pressure_count')}, "
                f"low={thermal_summary.get('low_pressure_count')}. "
                f"Window contains {len(window_events)} aligned events."
            ),
            "why_this_is_useful": [
                "Everything is normalized onto one time axis (epoch seconds).",
                "Any future agent (auth/network/metrics) can plug into the same Event schema.",
                "Correlation agent later can cite exact timestamps + events from this report.",
            ],
        },
    }
