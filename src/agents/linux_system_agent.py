#!/usr/bin/env python3
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from src.common import load_logs, setup_logging

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
NORMALIZED_DIR = REPO_ROOT / "normalized"
UNIFIED_LOGS = NORMALIZED_DIR / "unified_logs.jsonl"
OUTPUT_PATH = NORMALIZED_DIR / "linux_system_agent_output.json"

SUSPICIOUS_KEYWORDS: tuple[str, ...] = (
    "oom",
    "out of memory",
    "segfault",
    "panic",
    "i/o error",
    "disk error",
    "connection timed out",
    "denied",
)


def is_linux_candidate(record: dict[str, Any]) -> bool:
    if (record.get("dataset") or "").strip().lower() != "linux":
        return False
    message = (record.get("message") or "").lower()
    level = (record.get("level") or "").lower()
    if level in {"error", "critical", "alert", "emergency"}:
        return True
    return any(token in message for token in SUSPICIOUS_KEYWORDS)


def classify_linux_record(record: dict[str, Any]) -> tuple[str, str, float]:
    message = (record.get("message") or "").lower()
    level = (record.get("level") or "").lower()

    if "oom" in message or "out of memory" in message or "panic" in message:
        return "system_resource_or_kernel_failure", "high", 0.9
    if "i/o error" in message or "disk error" in message:
        return "storage_io_failure", "high", 0.88
    if "denied" in message:
        return "privilege_or_access_violation", "medium", 0.78
    if "segfault" in message:
        return "process_crash", "high", 0.84
    if "connection timed out" in message:
        return "service_connectivity_degradation", "medium", 0.72
    if level in {"error", "critical", "alert", "emergency"}:
        return "linux_runtime_error", "medium", 0.68
    return "linux_runtime_signal", "low", 0.55


def run_agent(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for record in logs:
        if not is_linux_candidate(record):
            continue
        event_category, severity, confidence = classify_linux_record(record)
        findings.append(
            {
                "agent": "linux_system_agent",
                "event_category": event_category,
                "severity": severity,
                "confidence": round(confidence, 2),
                "host_or_component": (record.get("component") or "linux").strip(),
                "start_timestamp": record.get("timestamp_iso") or "",
                "end_timestamp": record.get("timestamp_iso") or "",
                "evidence_ids": [record.get("line_id")] if record.get("line_id") else [],
                "summary": f"{event_category}: {(record.get('message') or '')[:180]}",
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
