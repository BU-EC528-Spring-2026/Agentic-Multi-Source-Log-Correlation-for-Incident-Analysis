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

    @classmethod
    def from_dict(cls, item: dict[str, Any]) -> "LogEvent":
        return cls(
            event_id=str(item["event_id"]),
            timestamp=str(item["timestamp"]),
            source=str(item["source"]),
            process=str(item["process"]),
            category=str(item["category"]),
            severity=str(item["severity"]),
            message=str(item["message"]),
            entities=[dict(value) for value in item["entities"]],
            raw_metadata=dict(item["raw_metadata"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "process": self.process,
            "category": self.category,
            "severity": self.severity,
            "message": self.message,
            "entities": [dict(value) for value in self.entities],
            "raw_metadata": dict(self.raw_metadata),
        }


def build_source_name(log_file: str) -> str:
    path = Path(log_file)
    name = path.parent.name.strip() or path.stem.strip()
    return name or "unknown"


def build_events(entries: list[ParsedLog], source: str) -> list[LogEvent]:
    return [build_event(entry, source=source) for entry in entries]


def build_event_from_ingestion_record(item: dict[str, Any]) -> LogEvent:
    event_id, event_id_key = pick_value(item, ["event_id", "id"])
    timestamp, timestamp_key = pick_value(item, ["timestamp", "ts", "@timestamp"])
    source, source_key = pick_value(item, ["source", "dataset", "source_file"])
    category, category_key = pick_value(
        item,
        ["category", "template", "label"],
        default="other",
    )
    severity, severity_key = pick_value(
        item,
        ["severity", "level"],
        default="unknown",
    )
    message, message_key = pick_value(item, ["message", "text", "raw"])
    entities = build_entities(item.get("entities", []))
    used_keys = {
        event_id_key,
        timestamp_key,
        source_key,
        category_key,
        severity_key,
        message_key,
        "process",
        "entities",
    }
    raw_metadata = {key: value for key, value in item.items() if key not in used_keys}
    return LogEvent(
        event_id=event_id,
        timestamp=timestamp,
        source=source,
        process=str(item.get("process", "")),
        category=category,
        severity=normalize_severity(severity),
        message=message,
        entities=entities,
        raw_metadata=raw_metadata,
    )


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


def pick_value(
    item: dict[str, Any],
    keys: list[str],
    default: str | None = None,
) -> tuple[str, str]:
    for key in keys:
        value = item.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text, key
    if default is not None:
        return default, ""
    raise ValueError(f"missing required field from {keys}")


def build_entities(values: Any) -> list[dict[str, str]]:
    if not isinstance(values, list):
        return []

    entities = []
    for item in values:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        value = str(item.get("value", "")).strip()
        if name and value:
            entities.append({"name": name, "value": value})
    return entities


def normalize_severity(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"critical", "fatal", "emergency", "alert"}:
        return "critical"
    if normalized in {"error", "err"}:
        return "error"
    if normalized in {"warning", "warn"}:
        return "warning"
    if normalized in {"info", "informational"}:
        return "info"
    if normalized in {"debug", "trace"}:
        return "debug"
    if not normalized:
        return "unknown"
    return normalized
