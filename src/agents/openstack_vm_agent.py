#!/usr/bin/env python3
# Pipeline step 3b: OpenStack VM agent — detect VM lifecycle anomalies from unified logs.

"""
OpenStack VM agent: analyze compute lifecycle evidence and output structured anomalies.

Loads unified_logs.jsonl, filters nova.compute.manager VM lifecycle events, groups by
instance id, detects suspicious patterns, writes normalized/openstack_vm_agent_output.json.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from src.common import load_logs, setup_logging

# Paths relative to repo root
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
NORMALIZED_DIR = REPO_ROOT / "normalized"
UNIFIED_LOGS = NORMALIZED_DIR / "unified_logs.jsonl"
OUTPUT_PATH = NORMALIZED_DIR / "openstack_vm_agent_output.json"

COMPONENT_SUBSTRING = "nova.compute.manager"

# Message/template patterns for VM lifecycle (case-insensitive)
VM_LIFECYCLE_PATTERNS: tuple[str, ...] = (
    "vm started",
    "vm stopped",
    "vm paused",
    "vm resumed",
    "lifecycle event",
)
# Also treat "Terminating instance" as a stop-like event
TERMINATING_PATTERN = "terminating instance"

# Instance UUID in message: [instance: <uuid>]
INSTANCE_ID_RE = re.compile(r"\[instance:\s*([a-f0-9-]{36})\]", re.IGNORECASE)

# Churn: require EITHER > 5 events in 5 min OR multiple transition types (and enough events)
CHURN_EVENT_COUNT_MIN = 6  # more than 5 in window
CHURN_WINDOW_MS = 5 * 60 * 1000  # 5 minutes
CHURN_DISTINCT_TYPES_MIN = 2  # at least 2 of: started, stopped, paused, resumed, terminating
CHURN_EVENT_COUNT_IF_MULTI_TYPE = 4  # and at least this many events when using distinct-types rule

# Repeated restart: at least this many (started -> stopped/terminating) cycles in order
MIN_RESTART_CYCLES = 2

# Canonical field order for agent JSON output
VM_ANOMALY_KEYS = (
    "agent", "event_category", "severity", "confidence", "instance_id",
    "start_timestamp", "end_timestamp", "evidence_ids", "summary",
)


# -----------------------------------------------------------------------------
# Load and filter
# -----------------------------------------------------------------------------


def is_vm_lifecycle_record(record: dict[str, Any]) -> bool:
    """True if openstack, nova.compute.manager component, and message matches VM lifecycle."""
    if (record.get("dataset") or "").strip().lower() != "openstack":
        return False
    comp = (record.get("component") or "").lower()
    if COMPONENT_SUBSTRING.lower() not in comp:
        return False
    msg = (record.get("message") or "").lower()
    template = (record.get("event_template") or "").lower()
    text = msg + " " + template
    if any(p in text for p in VM_LIFECYCLE_PATTERNS):
        return True
    if TERMINATING_PATTERN in text:
        return True
    return False


def extract_instance_id(record: dict[str, Any]) -> str | None:
    """Extract instance UUID from message or event_template. Returns None if not found."""
    for field in ("message", "event_template"):
        raw = record.get(field) or ""
        m = INSTANCE_ID_RE.search(raw)
        if m:
            return m.group(1)
    return None


def select_candidates(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filter to OpenStack nova.compute.manager VM lifecycle records, sorted by timestamp."""
    log = logging.getLogger(__name__)
    candidates = [r for r in logs if is_vm_lifecycle_record(r)]
    candidates.sort(key=lambda r: r.get("timestamp_epoch") or 0)
    log.info("Selected %d VM lifecycle candidate records", len(candidates))
    return candidates


# -----------------------------------------------------------------------------
# Group by instance and classify event type
# -----------------------------------------------------------------------------


def event_type(record: dict[str, Any]) -> str | None:
    """
    Classify single record as: started | stopped | paused | resumed | terminating | other.
    Returns None for non-lifecycle (other).
    """
    msg = (record.get("message") or "").lower()
    if "vm started" in msg or "started (lifecycle" in msg:
        return "started"
    if "vm stopped" in msg or "stopped (lifecycle" in msg:
        return "stopped"
    if "vm paused" in msg or "paused (lifecycle" in msg:
        return "paused"
    if "vm resumed" in msg or "resumed (lifecycle" in msg:
        return "resumed"
    if "terminating instance" in msg:
        return "terminating"
    return "other"


def group_by_instance(
    candidates: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Group records by instance_id. Records without instance_id go under key 'unknown'."""
    by_instance: dict[str, list[dict[str, Any]]] = {}
    for r in candidates:
        iid = extract_instance_id(r) or "unknown"
        by_instance.setdefault(iid, []).append(r)
    for key in by_instance:
        by_instance[key].sort(key=lambda x: x.get("timestamp_epoch") or 0)
    logging.getLogger(__name__).info("Grouped into %d instances", len(by_instance))
    return by_instance


# -----------------------------------------------------------------------------
# Detect suspicious patterns per instance
# -----------------------------------------------------------------------------


def count_restart_cycles(records: list[dict[str, Any]]) -> int:
    """
    Count (started followed by stopped/terminating) cycles in timeline order.
    Walk events in time order; each started -> stopped/terminating counts as one cycle.
    """
    cycles = 0
    seen_start = False
    for r in records:
        t = event_type(r)
        if t == "started":
            seen_start = True
        elif t in ("stopped", "terminating") and seen_start:
            cycles += 1
            seen_start = False
    return cycles


def has_stop_without_prior_start(records: list[dict[str, Any]]) -> bool:
    """True if the first lifecycle event (started|stopped|paused|resumed|terminating) is a stop/terminating/pause with no prior start."""
    for r in records:
        t = event_type(r)
        if t == "other":
            continue
        if t in ("stopped", "terminating", "paused"):
            return True
        if t in ("started", "resumed"):
            return False
    return False


def has_lifecycle_churn(records: list[dict[str, Any]]) -> bool:
    """
    True if (a) > 5 events in some 5-min window, OR
    (b) multiple transition types (started/stopped/paused/resumed/terminating) and >= CHURN_EVENT_COUNT_IF_MULTI_TYPE events.
    """
    if len(records) < CHURN_EVENT_COUNT_IF_MULTI_TYPE:
        return False
    epochs = [r.get("timestamp_epoch") or 0 for r in records]
    # (a) More than 5 events in 5 minutes
    for i in range(len(epochs)):
        window_start = epochs[i]
        count = sum(1 for t in epochs if window_start <= t <= window_start + CHURN_WINDOW_MS)
        if count >= CHURN_EVENT_COUNT_MIN:
            return True
    # (b) Multiple transition types and enough events
    types_present = {event_type(r) for r in records}
    types_present.discard("other")
    if len(types_present) >= CHURN_DISTINCT_TYPES_MIN and len(records) >= CHURN_EVENT_COUNT_IF_MULTI_TYPE:
        return True
    return False


def confidence_anomaly(
    event_category: str,
    records: list[dict[str, Any]],
    cycles: int = 0,
    stop_without_start: bool = False,
) -> float:
    """Rule-based confidence in [0.0, 1.0] for the anomaly."""
    n = len(records)
    if event_category == "repeated_vm_restart_cycle":
        return min(1.0, 0.6 + 0.15 * min(cycles, 3))
    if event_category == "unexpected_vm_stop":
        return 0.75
    if event_category == "lifecycle_churn":
        types_set = {event_type(r) for r in records}
        types_set.discard("other")
        types_set.discard(None)
        types_present = len(types_set)
        return min(1.0, 0.5 + 0.05 * min(n, 10) + 0.1 * min(types_present, 3))
    return 0.5


def detect_anomalies(
    instance_id: str,
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    For one instance, detect which anomaly categories apply and return a list of
    output records (one per detected category) with confidence.
    """
    results: list[dict[str, Any]] = []
    if not records:
        return results

    start_ts = min(r.get("timestamp_epoch") or 0 for r in records)
    end_ts = max(r.get("timestamp_epoch") or 0 for r in records)
    start_iso = next((r.get("timestamp_iso") for r in records if (r.get("timestamp_epoch") or 0) == start_ts), "")
    end_iso = next((r.get("timestamp_iso") for r in records if (r.get("timestamp_epoch") or 0) == end_ts), "")
    evidence_ids = [r.get("line_id") for r in records if r.get("line_id")]

    if instance_id == "unknown":
        return results

    cycles = count_restart_cycles(records)
    stop_without_start = has_stop_without_prior_start(records)
    churn = has_lifecycle_churn(records)

    def _record(category: str, severity: str, conf: float, summary_text: str) -> dict[str, Any]:
        out = {
            "agent": "openstack_vm_agent",
            "event_category": category,
            "severity": severity,
            "confidence": round(conf, 2),
            "instance_id": instance_id,
            "start_timestamp": start_iso,
            "end_timestamp": end_iso,
            "evidence_ids": evidence_ids,
            "summary": summary_text,
        }
        return {k: out[k] for k in VM_ANOMALY_KEYS}

    if cycles >= MIN_RESTART_CYCLES:
        conf = confidence_anomaly("repeated_vm_restart_cycle", records, cycles=cycles)
        results.append(_record(
            "repeated_vm_restart_cycle", "high", conf,
            f"repeated_vm_restart_cycle: {cycles} start/stop cycle(s) for instance {instance_id}",
        ))

    if stop_without_start:
        conf = confidence_anomaly("unexpected_vm_stop", records, stop_without_start=True)
        results.append(_record(
            "unexpected_vm_stop", "medium", conf,
            f"unexpected_vm_stop: stop/terminate/pause without prior start in window for instance {instance_id}",
        ))

    if churn:
        conf = confidence_anomaly("lifecycle_churn", records)
        results.append(_record(
            "lifecycle_churn", "high", conf,
            f"lifecycle_churn: {len(records)} lifecycle events for instance {instance_id}",
        ))

    return results


# -----------------------------------------------------------------------------
# Run agent and write output
# -----------------------------------------------------------------------------


def run_agent(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Run the OpenStack VM agent: filter candidates, group by instance,
    detect anomalies per instance, return flat list of anomaly records.
    """
    candidates = select_candidates(logs)
    by_instance = group_by_instance(candidates)
    results: list[dict[str, Any]] = []
    for iid, recs in by_instance.items():
        results.extend(detect_anomalies(iid, recs))
    return results


def main() -> None:
    """Load logs, run OpenStack VM agent, write structured output."""
    setup_logging()
    log = logging.getLogger(__name__)

    if not UNIFIED_LOGS.exists():
        raise FileNotFoundError(f"Logs not found: {UNIFIED_LOGS}")

    logs = load_logs(UNIFIED_LOGS)
    anomalies = run_agent(logs)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(anomalies, f, indent=2, ensure_ascii=False)

    log.info("Wrote %d anomaly records to %s", len(anomalies), OUTPUT_PATH)

    by_category: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for a in anomalies:
        by_category[a["event_category"]] = by_category.get(a["event_category"], 0) + 1
        by_severity[a["severity"]] = by_severity.get(a["severity"], 0) + 1
    print()
    print("--- OpenStack VM agent output statistics ---")
    print(f"Total anomalies: {len(anomalies)}")
    print("By category:", json.dumps(by_category, sort_keys=True))
    print("By severity:", json.dumps(by_severity, sort_keys=True))
    print()
    log.info("By category: %s", by_category)
    log.info("By severity: %s", by_severity)


if __name__ == "__main__":
    main()
