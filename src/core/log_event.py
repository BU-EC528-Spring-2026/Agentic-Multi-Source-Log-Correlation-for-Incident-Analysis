import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
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


def load_events_from_ingestion_jsonl(
    path: str | Path,
) -> tuple[list[LogEvent], list[dict[str, Any]]]:
    jsonl_path = Path(path)
    if not jsonl_path.exists():
        raise FileNotFoundError(f"ingestion JSONL not found: {jsonl_path}")

    events: list[LogEvent] = []
    rejected: list[dict[str, Any]] = []

    with jsonl_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                rejected.append(
                    {"line_number": line_number, "reason": f"invalid JSON: {exc.msg}"}
                )
                continue
            if not isinstance(payload, dict):
                rejected.append(
                    {
                        "line_number": line_number,
                        "reason": "ingestion record must be a JSON object",
                    }
                )
                continue
            try:
                events.append(build_event_from_ingestion_record(payload))
            except ValueError as exc:
                rejected.append({"line_number": line_number, "reason": str(exc)})

    return events, rejected


def build_events_from_ingestion_records(
    records: list[dict[str, Any]],
) -> tuple[list[LogEvent], list[dict[str, Any]]]:
    events: list[LogEvent] = []
    rejected: list[dict[str, Any]] = []

    for index, payload in enumerate(records, start=1):
        if not isinstance(payload, dict):
            rejected.append(
                {
                    "record_index": index,
                    "reason": "ingestion record must be a JSON object",
                }
            )
            continue
        try:
            events.append(build_event_from_ingestion_record(payload))
        except ValueError as exc:
            rejected.append({"record_index": index, "reason": str(exc)})

    return events, rejected


def build_event_from_ingestion_record(item: dict[str, Any]) -> LogEvent:
    used: set[str] = set()

    source, sk = pick_value(item, ["source", "dataset", "source_file"])
    used.add(sk)

    event_id, id_keys = ingestion_event_id(item, source=source)
    used.update(id_keys)

    timestamp, ts_keys = ingestion_timestamp(item)
    used.update(ts_keys)

    category, ck = pick_value(
        item,
        ["category", "event_template", "template", "label"],
        default="other",
    )
    if ck:
        used.add(ck)

    severity, sek = pick_value(item, ["severity", "level"], default="unknown")
    if sek:
        used.add(sek)

    message, mk = pick_value(item, ["message", "text", "raw"])
    used.add(mk)

    process, pk = pick_value(item, ["component", "process"], default="")
    if pk:
        used.add(pk)

    entities = build_entities(item.get("entities", []))
    if "entities" in item:
        used.add("entities")

    line_id = item.get("line_id")
    line_no = coerce_line_number(line_id)
    if line_no is not None:
        used.add("line_id")

    raw_metadata = {k: v for k, v in item.items() if k not in used}
    if line_id is not None:
        raw_metadata["line_id"] = line_id
    if line_no is not None:
        raw_metadata["line_no"] = line_no

    return LogEvent(
        event_id=event_id,
        timestamp=timestamp,
        source=source,
        process=process,
        category=category,
        severity=normalize_severity(severity),
        message=message,
        entities=entities,
        raw_metadata=raw_metadata,
    )


def ingestion_event_id(item: dict[str, Any], *, source: str) -> tuple[str, set[str]]:
    for key in ("event_id", "id"):
        value = item.get(key)
        if value is not None and str(value).strip():
            return str(value).strip(), {key}
    line_id = item.get("line_id")
    if line_id is not None and str(line_id).strip():
        return f"{source}:{str(line_id).strip()}", {"line_id"}
    raise ValueError("missing required field from ['event_id', 'line_id']")


def ingestion_timestamp(item: dict[str, Any]) -> tuple[str, set[str]]:
    iso = item.get("timestamp_iso")
    if iso is not None and str(iso).strip():
        return normalize_timestamp(str(iso)), {"timestamp_iso"}

    epoch = item.get("timestamp_epoch")
    if epoch is not None and str(epoch).strip():
        try:
            sec = float(str(epoch).strip())
        except ValueError as exc:
            raise ValueError(f"invalid timestamp_epoch: {epoch!r}") from exc
        if abs(sec) > 1e12:
            sec /= 1000.0
        dt = datetime.fromtimestamp(sec, tz=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z"), {"timestamp_epoch"}

    for key in ("timestamp", "ts", "@timestamp"):
        value = item.get(key)
        if value is not None and str(value).strip():
            return normalize_timestamp(str(value)), {key}

    raise ValueError("missing required field from timestamp")


def normalize_timestamp(text: str) -> str:
    candidate = text.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError(f"invalid timestamp: {text!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)
    return parsed.isoformat().replace("+00:00", "Z")


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


def coerce_line_number(value: Any) -> int | None:
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    if text.isdigit():
        return int(text)

    matches = re.findall(r"\d+", text)
    if not matches:
        return None
    return int(matches[-1])


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
