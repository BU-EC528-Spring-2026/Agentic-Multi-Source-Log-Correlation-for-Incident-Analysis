from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.core.log_parser import ParsedLog


@dataclass
class LogEvent:
    event_id: str
    timestamp: str
    source: str
    process: str
    category: str
    severity: str
    message: str
    entities: list[dict[str, str]]
    raw_metadata: dict[str, Any]


def build_source_name(log_file: str) -> str:
    path = Path(log_file)
    name = path.parent.name.strip() or path.stem.strip()
    return name or "unknown"


def build_events(entries: list[ParsedLog], source: str) -> list[LogEvent]:
    return [build_event(entry, source=source) for entry in entries]


def build_event(entry: ParsedLog, source: str) -> LogEvent:
    entities = []
    if entry.host:
        entities.append({"name": "host", "value": entry.host})
    if entry.pid:
        entities.append({"name": "pid", "value": entry.pid})

    raw_metadata: dict[str, Any] = {
        "line_no": entry.line_no,
        "raw": entry.raw,
    }
    if entry.host:
        raw_metadata["host"] = entry.host
    if entry.pid:
        raw_metadata["pid"] = entry.pid
    if entry.context:
        raw_metadata["context"] = entry.context

    return LogEvent(
        event_id=f"{source}:{entry.line_no}",
        timestamp=entry.timestamp,
        source=source,
        process=entry.process,
        category="other",
        severity="unknown",
        message=entry.message,
        entities=entities,
        raw_metadata=raw_metadata,
    )
