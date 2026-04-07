#!/usr/bin/env python3
# Pipeline step 3a: Auth agent — detect auth-related incidents from unified logs.

"""
Auth agent: analyze authentication-related evidence and output structured incidents.

Loads unified_logs.jsonl, filters auth records (linux/openssh), groups by actor + time
window, classifies and assigns severity, writes normalized/auth_agent_output.json.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from src.common import load_logs, setup_logging

# Only emit these categories (no generic authentication_activity)
SUSPICIOUS_CATEGORIES: frozenset[str] = frozenset({
    "repeated_authentication_failure",
    "invalid_user_attempt",
    "successful_auth_after_failures",
    "suspicious_login_burst",
})

# Actor extraction: rhost=..., "from <ip/host>", or IPv4
RHOST_RE = re.compile(r"rhost=(\S+)", re.IGNORECASE)
FROM_RE = re.compile(r"\bfrom\s+(\S+)", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

# Paths relative to repo root
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
NORMALIZED_DIR = REPO_ROOT / "normalized"
UNIFIED_LOGS = NORMALIZED_DIR / "unified_logs.jsonl"
OUTPUT_PATH = NORMALIZED_DIR / "auth_agent_output.json"

# Datasets to include (linux required, openssh optional)
AUTH_DATASETS: tuple[str, ...] = ("linux", "openssh")

# Message substrings (case-insensitive) that indicate auth-related events
MESSAGE_MATCHES: tuple[str, ...] = (
    "authentication failure",
    "failed password",
    "invalid user",
    "accepted password",
)

# Component substrings (case-insensitive)
COMPONENT_MATCHES: tuple[str, ...] = ("sshd", "pam")

# Time window for grouping events into one incident (seconds)
INCIDENT_WINDOW_SEC = 60
INCIDENT_WINDOW_MS = INCIDENT_WINDOW_SEC * 1000

# Threshold for "many" failures (high severity)
HIGH_SEVERITY_FAILURE_COUNT = 3

# Threshold for burst (many events in one incident)
BURST_EVENT_COUNT = 5


# -----------------------------------------------------------------------------
# Load and filter
# -----------------------------------------------------------------------------


def is_auth_candidate(record: dict[str, Any]) -> bool:
    """True if dataset in AUTH_DATASETS and (message or component) matches auth patterns."""
    dataset = (record.get("dataset") or "").strip().lower()
    if dataset not in AUTH_DATASETS:
        return False
    msg = (record.get("message") or "").lower()
    comp = (record.get("component") or "").lower()
    if any(m in msg for m in MESSAGE_MATCHES):
        return True
    if any(c in comp for c in COMPONENT_MATCHES):
        return True
    return False


def select_candidates(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filter to auth-related records and sort by (actor_key, timestamp_epoch)."""
    log = logging.getLogger(__name__)
    candidates = [r for r in logs if is_auth_candidate(r)]
    for r in candidates:
        r["_actor_key"] = extract_actor_key(r)
    candidates.sort(key=lambda r: (r["_actor_key"], r.get("timestamp_epoch") or 0))
    log.info("Selected %d auth-related candidate records", len(candidates))
    return candidates


def extract_actor_key(record: dict[str, Any]) -> str:
    """Prefer host/IP from message, else component. Used for grouping."""
    msg = record.get("message") or ""
    m = RHOST_RE.search(msg)
    if m:
        return (m.group(1) or "").strip().lower() or "unknown"
    m = FROM_RE.search(msg)
    if m:
        return (m.group(1) or "").strip().lower() or "unknown"
    m = IPV4_RE.search(msg)
    if m:
        return m.group(1)
    comp = (record.get("component") or "").strip().lower()
    return comp or "unknown"


# -----------------------------------------------------------------------------
# Group into incidents (by actor + 60s window)
# -----------------------------------------------------------------------------


def group_into_incidents(
    candidates: list[dict[str, Any]],
    window_ms: int = INCIDENT_WINDOW_MS,
) -> list[list[dict[str, Any]]]:
    """
    Group by actor_key then time: events in same actor within window_ms
    of the previous event are merged into the same incident.
    """
    if not candidates:
        return []
    incidents: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = [candidates[0]]
    for rec in candidates[1:]:
        ts = rec.get("timestamp_epoch") or 0
        prev_ts = current[-1].get("timestamp_epoch") or 0
        same_actor = rec.get("_actor_key") == current[0].get("_actor_key")
        if same_actor and ts - prev_ts <= window_ms:
            current.append(rec)
        else:
            incidents.append(current)
            current = [rec]
    incidents.append(current)
    logging.getLogger(__name__).info("Grouped into %d incidents", len(incidents))
    return incidents


# -----------------------------------------------------------------------------
# Classify incident: event_category and severity
# -----------------------------------------------------------------------------


def _count_matches(records: list[dict[str, Any]], *phrases: str) -> int:
    """Count records whose message (lower) contains any of the phrases."""
    total = 0
    for r in records:
        msg = (r.get("message") or "").lower()
        if any(p in msg for p in phrases):
            total += 1
    return total


def classify_incident(records: list[dict[str, Any]]) -> tuple[str, str]:
    """
    Return (event_category, severity). Only returns one of the suspicious categories;
    use is_suspicious() to filter out generic authentication_activity.
    """
    n = len(records)
    fail_count = _count_matches(
        records,
        "authentication failure",
        "failed password",
    )
    invalid_count = _count_matches(records, "invalid user")
    accepted_count = _count_matches(records, "accepted password")

    if accepted_count > 0 and fail_count > 0:
        event_category = "successful_auth_after_failures"
    elif fail_count >= HIGH_SEVERITY_FAILURE_COUNT:
        event_category = "repeated_authentication_failure"
    elif invalid_count > 0:
        event_category = "invalid_user_attempt"
    elif n >= BURST_EVENT_COUNT:
        event_category = "suspicious_login_burst"
    elif fail_count > 0:
        event_category = "repeated_authentication_failure"
    else:
        event_category = "authentication_activity"

    if fail_count >= HIGH_SEVERITY_FAILURE_COUNT or n >= BURST_EVENT_COUNT:
        severity = "high"
    elif fail_count > 0 or invalid_count > 0:
        severity = "medium"
    else:
        severity = "low"

    return event_category, severity


def confidence_incident(
    records: list[dict[str, Any]],
    event_category: str,
) -> float:
    """Rule-based confidence in [0.0, 1.0] for the incident category."""
    n = len(records)
    fail_count = _count_matches(records, "authentication failure", "failed password")
    invalid_count = _count_matches(records, "invalid user")
    accepted_count = _count_matches(records, "accepted password")

    if event_category == "repeated_authentication_failure":
        # Higher with more failures
        return min(1.0, 0.5 + 0.12 * min(fail_count, 5))
    if event_category == "invalid_user_attempt":
        return 0.85
    if event_category == "successful_auth_after_failures":
        return 0.82
    if event_category == "suspicious_login_burst":
        return min(1.0, 0.55 + 0.08 * max(0, n - BURST_EVENT_COUNT))
    return 0.5


def incident_summary(records: list[dict[str, Any]], category: str) -> str:
    """Short human-readable summary for the incident."""
    n = len(records)
    fail_count = _count_matches(records, "authentication failure", "failed password")
    invalid_count = _count_matches(records, "invalid user")
    accepted_count = _count_matches(records, "accepted password")
    parts: list[str] = []
    if fail_count:
        parts.append(f"{fail_count} auth failure(s)")
    if invalid_count:
        parts.append(f"{invalid_count} invalid user(s)")
    if accepted_count:
        parts.append(f"{accepted_count} accepted login(s)")
    if not parts:
        parts.append(f"{n} auth-related event(s)")
    return f"{category}: " + ", ".join(parts) + f" in {n} log(s)"


# -----------------------------------------------------------------------------
# Build structured output
# -----------------------------------------------------------------------------


# Canonical field order for agent JSON output
AUTH_INCIDENT_KEYS = (
    "agent", "event_category", "severity", "confidence", "actor_key",
    "start_timestamp", "end_timestamp", "evidence_ids", "summary",
)


def build_incident_output(
    records: list[dict[str, Any]],
    event_category: str,
    severity: str,
    summary: str,
    confidence: float,
) -> dict[str, Any]:
    """Build one incident dict for JSON output. Keys in canonical order."""
    if not records:
        raise ValueError("Empty incident")
    start_ts = min(r.get("timestamp_epoch") or 0 for r in records)
    end_ts = max(r.get("timestamp_epoch") or 0 for r in records)
    start_iso = next((r.get("timestamp_iso") for r in records if (r.get("timestamp_epoch") or 0) == start_ts), "")
    end_iso = next((r.get("timestamp_iso") for r in records if (r.get("timestamp_epoch") or 0) == end_ts), "")
    evidence_ids = [r.get("line_id") for r in records if r.get("line_id")]
    actor = records[0].get("_actor_key", "")
    out = {
        "agent": "auth_agent",
        "event_category": event_category,
        "severity": severity,
        "confidence": round(confidence, 2),
        "actor_key": actor,
        "start_timestamp": start_iso,
        "end_timestamp": end_iso,
        "evidence_ids": evidence_ids,
        "summary": summary,
    }
    return {k: out[k] for k in AUTH_INCIDENT_KEYS}


def run_agent(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Run the auth agent: filter candidates, group by actor + window, classify each,
    return only suspicious incidents (no authentication_activity).
    """
    candidates = select_candidates(logs)
    incidents = group_into_incidents(candidates)
    results: list[dict[str, Any]] = []
    for recs in incidents:
        event_category, severity = classify_incident(recs)
        if event_category not in SUSPICIOUS_CATEGORIES:
            continue
        summary = incident_summary(recs, event_category)
        confidence = confidence_incident(recs, event_category)
        results.append(
            build_incident_output(recs, event_category, severity, summary, confidence)
        )
    return results


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------


def main() -> None:
    """Load logs, run auth agent, write structured output."""
    setup_logging()
    log = logging.getLogger(__name__)

    if not UNIFIED_LOGS.exists():
        raise FileNotFoundError(f"Logs not found: {UNIFIED_LOGS}")

    logs = load_logs(UNIFIED_LOGS)
    incidents = run_agent(logs)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(incidents, f, indent=2, ensure_ascii=False)

    log.info("Wrote %d incidents to %s", len(incidents), OUTPUT_PATH)

    # Output statistics (print + log)
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for inc in incidents:
        by_severity[inc["severity"]] = by_severity.get(inc["severity"], 0) + 1
        by_category[inc["event_category"]] = by_category.get(inc["event_category"], 0) + 1
    print()
    print("--- Auth agent output statistics ---")
    print(f"Total incidents: {len(incidents)}")
    print("By category:", json.dumps(by_category, sort_keys=True))
    print("By severity:", json.dumps(by_severity, sort_keys=True))
    print()
    log.info("By severity: %s", by_severity)
    log.info("By category: %s", by_category)


if __name__ == "__main__":
    main()
