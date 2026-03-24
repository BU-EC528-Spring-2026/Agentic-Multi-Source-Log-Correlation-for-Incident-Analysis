from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import math
import re
from difflib import SequenceMatcher


ENTITY_KEYS_DEFAULT = (
    "trace_id",
    "request_id",
    "span_id",
    "host",
    "hostname",
    "node",
    "service",
    "app",
    "pod",
    "container",
    "namespace",
    "cluster",
    "user",
    "ip",
    "src_ip",
    "dst_ip",
)


def _parse_ts(ts: Any) -> datetime:
    """
    Accepts:
      - datetime
      - ISO8601 string (with or without timezone; 'Z' supported)
      - numeric epoch seconds (int/float)
    Returns timezone-aware UTC datetime.
    """
    if isinstance(ts, datetime):
        dt = ts
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(float(ts), tz=timezone.utc)

    if isinstance(ts, str):
        s = ts.strip()
        # Handle Z
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        # If no timezone, assume UTC
        try:
            dt = datetime.fromisoformat(s)
        except ValueError as e:
            raise ValueError(f"Unrecognized timestamp format: {ts}") from e
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    raise TypeError(f"Unsupported timestamp type: {type(ts)}")


def _normalize_message(msg: str) -> str:
    msg = msg.lower()
    msg = re.sub(r"\b[0-9a-f]{8,}\b", "<hex>", msg)  # collapse long hex ids
    msg = re.sub(r"\b\d+\b", "<num>", msg)          # collapse numbers
    msg = re.sub(r"\s+", " ", msg).strip()
    return msg


def _similar(a: str, b: str) -> float:
    # SequenceMatcher is cheap and good enough for demo-scale tests
    return SequenceMatcher(None, a, b).ratio()


@dataclass
class LogEvent:
    """
    Canonical structured event for correlation.
    """
    event_id: str
    timestamp: datetime
    source: str                    # e.g., "app", "infra", "thermal"
    level: str = "INFO"
    message: str = ""
    attributes: Dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def from_dict(d: Dict[str, Any], *, source: Optional[str] = None) -> "LogEvent":
        # minimal required
        event_id = str(d.get("event_id") or d.get("id") or d.get("uuid") or "")
        if not event_id:
            # last-resort deterministic-ish id
            event_id = f"evt_{abs(hash((d.get('timestamp'), d.get('message'), d.get('source'))))}"
        ts = _parse_ts(d.get("timestamp"))
        src = source or str(d.get("source") or "unknown")
        level = str(d.get("level") or "INFO")
        msg = str(d.get("message") or "")
        attrs = dict(d.get("attributes") or {})
        # also merge top-level common fields into attributes if present
        for k, v in d.items():
            if k in ("event_id", "id", "uuid", "timestamp", "source", "level", "message", "attributes"):
                continue
            attrs.setdefault(k, v)
        return LogEvent(event_id=event_id, timestamp=ts, source=src, level=level, message=msg, attributes=attrs)


@dataclass
class CorrelationGroup:
    group_id: str
    events: List[LogEvent] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)

    @property
    def start_time(self) -> datetime:
        return min(e.timestamp for e in self.events)

    @property
    def end_time(self) -> datetime:
        return max(e.timestamp for e in self.events)


class CorrelationAgent:
    """
    Simple correlation agent:
      - groups events if they match on entity keys within a time window
      - optionally uses message similarity as a fallback when no entity key match exists
    """

    def __init__(
        self,
        *,
        time_window_seconds: int = 30,
        entity_keys: Tuple[str, ...] = ENTITY_KEYS_DEFAULT,
        min_shared_entities: int = 1,
        use_message_similarity_fallback: bool = True,
        min_message_similarity: float = 0.78,
        require_distinct_sources: bool = False,
    ) -> None:
        self.time_window_seconds = int(time_window_seconds)
        self.entity_keys = entity_keys
        self.min_shared_entities = int(min_shared_entities)
        self.use_message_similarity_fallback = bool(use_message_similarity_fallback)
        self.min_message_similarity = float(min_message_similarity)
        self.require_distinct_sources = bool(require_distinct_sources)

    def correlate(self, events: List[LogEvent]) -> List[CorrelationGroup]:
        """
        Returns a list of correlation groups.
        """
        if not events:
            return []

        # sort by time
        events_sorted = sorted(events, key=lambda e: e.timestamp)

        groups: List[CorrelationGroup] = []
        group_counter = 0

        # Track which group an event has been assigned to
        assigned: Dict[str, int] = {}

        # Precompute entity maps + normalized messages
        entities_map: Dict[str, Dict[str, Any]] = {}
        norm_msg: Dict[str, str] = {}
        for e in events_sorted:
            entities_map[e.event_id] = self._extract_entities(e)
            norm_msg[e.event_id] = _normalize_message(e.message)

        # Sliding window candidate search (O(n^2) worst case but fine for demo)
        for i, e in enumerate(events_sorted):
            if e.event_id in assigned:
                continue

            group_counter += 1
            g = CorrelationGroup(group_id=f"corr_{group_counter}", events=[e], reasons=[])
            assigned[e.event_id] = len(groups)

            # expand group by scanning forward within time window
            for j in range(i + 1, len(events_sorted)):
                cand = events_sorted[j]
                if cand.event_id in assigned:
                    continue

                dt = (cand.timestamp - e.timestamp).total_seconds()
                if dt > self.time_window_seconds:
                    break  # past window (since sorted)

                should_join, reason = self._should_join_group(
                    base=e,
                    candidate=cand,
                    base_entities=entities_map[e.event_id],
                    cand_entities=entities_map[cand.event_id],
                    base_norm_msg=norm_msg[e.event_id],
                    cand_norm_msg=norm_msg[cand.event_id],
                    current_group=g,
                )
                if should_join:
                    g.events.append(cand)
                    g.reasons.append(reason)
                    assigned[cand.event_id] = len(groups)

            # If require distinct sources, enforce it here (drop single-source groups)
            if self.require_distinct_sources:
                sources = {ev.source for ev in g.events}
                if len(sources) < 2:
                    # unassign
                    for ev in g.events:
                        assigned.pop(ev.event_id, None)
                    continue

            groups.append(g)

        # sort events inside each group + deduplicate reasons
        for g in groups:
            g.events.sort(key=lambda e: e.timestamp)
            g.reasons = list(dict.fromkeys(g.reasons))  # preserve order

        return groups

    def _extract_entities(self, e: LogEvent) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k in self.entity_keys:
            if k in e.attributes and e.attributes[k] not in (None, "", "null"):
                out[k] = e.attributes[k]
        return out

    def _shared_entities(self, a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
        shared: Dict[str, Any] = {}
        for k, v in a.items():
            if k in b and b[k] == v:
                shared[k] = v
        return shared

    def _should_join_group(
        self,
        *,
        base: LogEvent,
        candidate: LogEvent,
        base_entities: Dict[str, Any],
        cand_entities: Dict[str, Any],
        base_norm_msg: str,
        cand_norm_msg: str,
        current_group: CorrelationGroup,
    ) -> Tuple[bool, str]:
        # 1) entity match
        shared = self._shared_entities(base_entities, cand_entities)
        if len(shared) >= self.min_shared_entities:
            keys = ", ".join(f"{k}={shared[k]}" for k in sorted(shared.keys()))
            return True, f"entity_match({keys})"

        # 2) message similarity fallback (still within time window because caller enforces)
        if self.use_message_similarity_fallback:
            sim = _similar(base_norm_msg, cand_norm_msg)
            if sim >= self.min_message_similarity:
                return True, f"msg_sim({sim:.2f})"

        return False, "no_match"