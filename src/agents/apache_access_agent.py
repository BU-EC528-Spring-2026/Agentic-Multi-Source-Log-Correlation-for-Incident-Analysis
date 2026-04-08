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
SUSPICIOUS_PATH_HINTS: tuple[str, ...] = (
    "/admin",
    "/wp-admin",
    "/phpmyadmin",
    "../",
    "/.env",
    "/etc/passwd",
)


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


def run_agent(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for record in logs:
        if not is_apache_candidate(record):
            continue
        category, severity, confidence = classify_apache_record(record)
        findings.append(
            {
                "agent": "apache_access_agent",
                "event_category": category,
                "severity": severity,
                "confidence": round(confidence, 2),
                "service": "apache",
                "start_timestamp": record.get("timestamp_iso") or "",
                "end_timestamp": record.get("timestamp_iso") or "",
                "evidence_ids": [record.get("line_id")] if record.get("line_id") else [],
                "summary": f"{category}: {(record.get('message') or '')[:180]}",
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
