import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

SYSLOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[^\[:]+?)"
    r"(?:\[(?P<pid>\d+)\])?"
    r"(?:\s+\((?P<context>[^)]*)\))?"
    r":\s*(?P<message>.*)$"
)

WHITESPACE = re.compile(r"\s+")


@dataclass
class ParsedLog:
    line_no: int
    timestamp: str
    host: str
    process: str
    pid: str | None
    context: str | None
    message: str
    raw: str


def clean_text(value: str) -> str:
    return WHITESPACE.sub(" ", value.strip())


def parse_log_lines(raw_lines: list[str]) -> tuple[list[ParsedLog], list[dict[str, str | int]]]:
    """Syslog lines get structured fields; other formats are included
    as raw entries so the LLM can handle them."""
    parsed: list[ParsedLog] = []
    skipped: list[dict[str, str | int]] = []
    for idx, raw in enumerate(raw_lines, start=1):
        line = raw.strip()
        if not line:
            continue

        match = SYSLOG_PATTERN.match(line)
        if match:
            month = match.group("month")
            day = str(int(match.group("day")))
            time_part = match.group("time")
            timestamp = f"{month} {day} {time_part}"

            parsed.append(
                ParsedLog(
                    line_no=idx,
                    timestamp=timestamp,
                    host=match.group("host"),
                    process=clean_text(match.group("process")),
                    pid=match.group("pid"),
                    context=clean_text(match.group("context")) if match.group("context") else None,
                    message=clean_text(match.group("message")),
                    raw=line,
                )
            )
        else:
            parsed.append(
                ParsedLog(
                    line_no=idx,
                    timestamp="",
                    host="",
                    process="",
                    pid=None,
                    context=None,
                    message=line,
                    raw=line,
                )
            )
    return parsed, skipped


parse_logs = parse_log_lines


def chunk_logs(entries: list[Any], chunk_size: int) -> list[list[Any]]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be > 0")
    return [entries[i : i + chunk_size] for i in range(0, len(entries), chunk_size)]


TIME_GAP_SECONDS = 300
HIGH_SEVERITY_CHUNK_SIZE = 100
HIGH_SEVERITY_RATIO = 0.30
HIGH_SEVERITIES = frozenset({"critical", "error", "high"})


def parse_event_ts(event: Any) -> datetime | None:
    ts = getattr(event, "timestamp", None)
    if not ts or not isinstance(ts, str):
        return None
    candidate = ts.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def is_high_severity(event: Any) -> bool:
    sev = getattr(event, "severity", "")
    return isinstance(sev, str) and sev.strip().lower() in HIGH_SEVERITIES


def chunk_logs_adaptive(
    entries: list[Any],
    chunk_size: int,
) -> list[list[Any]]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be > 0")
    if not entries:
        return []

    chunks: list[list[Any]] = []
    current: list[Any] = []
    prev_ts: datetime | None = None

    for event in entries:
        event_ts = parse_event_ts(event)

        # Break on time gap
        if current and prev_ts and event_ts:
            gap = abs((event_ts - prev_ts).total_seconds())
            if gap >= TIME_GAP_SECONDS:
                chunks.append(current)
                current = []

        current.append(event)

        # Break when current chunk hits its size limit
        high_count = sum(1 for e in current if is_high_severity(e))
        high_ratio = high_count / len(current)
        limit = HIGH_SEVERITY_CHUNK_SIZE if high_ratio >= HIGH_SEVERITY_RATIO else chunk_size

        if len(current) >= limit:
            chunks.append(current)
            current = []
            prev_ts = None
            continue

        if event_ts:
            prev_ts = event_ts

    if current:
        chunks.append(current)

    return chunks
