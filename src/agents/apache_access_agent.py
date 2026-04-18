#!/usr/bin/env python3
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from src.common import load_logs, setup_logging

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
NORMALIZED_DIR = REPO_ROOT / "normalized"
UNIFIED_LOGS = NORMALIZED_DIR / "unified_logs.jsonl"
OUTPUT_PATH = NORMALIZED_DIR / "apache_access_agent_output.json"

HTTP_STATUS_RE = re.compile(r"\b([1-5]\d\d)\b")
IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
SUSPICIOUS_PATH_HINTS: tuple[str, ...] = (
    "/admin",
    "/wp-admin",
    "/phpmyadmin",
    "../",
    "/.env",
    "/etc/passwd",
)

INCIDENT_WINDOW_SEC = 60
INCIDENT_WINDOW_MS = INCIDENT_WINDOW_SEC * 1000
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


def is_apache_candidate(record: dict[str, Any]) -> bool:
    if (record.get("dataset") or "").strip().lower() != "apache":
        return False
    message = (record.get("message") or "").lower()
    level = (record.get("level") or "").lower()
    if level in {"error", "critical", "alert"}:
        return True
    return " 4" in message or " 5" in message or any(
        token in message for token in SUSPICIOUS_PATH_HINTS
    )


def classify_apache_record(record: dict[str, Any]) -> tuple[str, str, float]:
    message = (record.get("message") or "").lower()
    status = 0
    status_match = HTTP_STATUS_RE.search(message)
    if status_match:
        status = int(status_match.group(1))

    if status >= 500:
        return "apache_server_error_spike", "high", 0.87
    if status in {401, 403}:
        return "apache_access_denied_pattern", "medium", 0.79
    if status == 404:
        return "apache_recon_or_missing_resource", "low", 0.66
    if any(token in message for token in SUSPICIOUS_PATH_HINTS):
        return "apache_suspicious_path_probe", "high", 0.85
    return "apache_runtime_signal", "low", 0.55


def extract_client_key(record: dict[str, Any]) -> str:
    msg = record.get("message") or ""
    m = IPV4_RE.search(msg)
    if m:
        return m.group(1)
    return "unknown"


def select_candidates(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for record in logs:
        if not is_apache_candidate(record):
            continue
        category, severity, confidence = classify_apache_record(record)
        record["_apache_category"] = category
        record["_apache_severity"] = severity
        record["_apache_confidence"] = confidence
        record["_apache_client"] = extract_client_key(record)
        candidates.append(record)
    candidates.sort(
        key=lambda r: (
            r["_apache_category"],
            r["_apache_client"],
            r.get("timestamp_epoch") or 0,
        ),
    )
    return candidates


def group_into_incidents(
    candidates: list[dict[str, Any]],
    window_ms: int = INCIDENT_WINDOW_MS,
) -> list[list[dict[str, Any]]]:
    if not candidates:
        return []
    incidents: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = [candidates[0]]
    for rec in candidates[1:]:
        ts = rec.get("timestamp_epoch") or 0
        prev_ts = current[-1].get("timestamp_epoch") or 0
        same_bucket = (
            rec["_apache_category"] == current[0]["_apache_category"]
            and rec["_apache_client"] == current[0]["_apache_client"]
        )
        if same_bucket and ts - prev_ts <= window_ms:
            current.append(rec)
        else:
            incidents.append(current)
            current = [rec]
    incidents.append(current)
    return incidents


def merge_severity(values: list[str]) -> str:
    return max(values, key=lambda s: SEVERITY_RANK.get(s, 0))


def incident_summary(category: str, records: list[dict[str, Any]]) -> str:
    n = len(records)
    sample = (records[0].get("message") or "")[:160]
    if n == 1:
        return f"{category}: {sample}"
    return f"{category}: {n} matching lines in {INCIDENT_WINDOW_SEC}s window (e.g. {sample})"


def run_agent(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    candidates = select_candidates(logs)
    for records in group_into_incidents(candidates):
        category = records[0]["_apache_category"]
        severity = merge_severity([r["_apache_severity"] for r in records])
        confidence = round(max(r["_apache_confidence"] for r in records), 2)
        epochs = [r.get("timestamp_epoch") or 0 for r in records]
        start_ts = min(epochs)
        end_ts = max(epochs)
        start_iso = next(
            (r.get("timestamp_iso") for r in records if (r.get("timestamp_epoch") or 0) == start_ts),
            "",
        )
        end_iso = next(
            (r.get("timestamp_iso") for r in records if (r.get("timestamp_epoch") or 0) == end_ts),
            "",
        )
        evidence_ids = [r.get("line_id") for r in records if r.get("line_id")]
        findings.append(
            {
                "agent": "apache_access_agent",
                "event_category": category,
                "severity": severity,
                "confidence": confidence,
                "service": "apache",
                "start_timestamp": start_iso,
                "end_timestamp": end_iso,
                "evidence_ids": evidence_ids,
                "summary": incident_summary(category, records),
            }
        )
    return findings


def main() -> None:
    setup_logging()
    log = logging.getLogger(__name__)
    if not UNIFIED_LOGS.exists():
        raise FileNotFoundError(f"Logs not found: {UNIFIED_LOGS}")

    logs = load_logs(UNIFIED_LOGS)
    findings = run_agent(logs)
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", encoding="utf-8") as handle:
        json.dump(findings, handle, indent=2, ensure_ascii=False)
    log.info("Wrote %d findings to %s", len(findings), OUTPUT_PATH)


if __name__ == "__main__":
    main()
