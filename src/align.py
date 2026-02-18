from __future__ import annotations
from typing import Iterable, List, Optional
from .events import Event

def sort_events(events: list[Event]) -> list[Event]:
    return sorted(events, key=lambda e: e.ts)

def choose_anchor(events: list[Event], *, strategy: str = "median") -> float:
    """Anchor selection.
    - median: robust, works even when you don't know incident time
    - first: first event timestamp
    """
    if not events:
        raise ValueError("No events to choose anchor from")
    s = sort_events(events)
    if strategy == "first":
        return s[0].ts
    if strategy == "median":
        return s[len(s)//2].ts
    raise ValueError(f"Unknown anchor strategy: {strategy}")

def window(events: list[Event], *, anchor_ts: float, delta_s: float) -> list[Event]:
    lo = anchor_ts - delta_s
    hi = anchor_ts + delta_s
    return [e for e in events if lo <= e.ts <= hi]
