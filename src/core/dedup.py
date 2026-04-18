import re
from dataclasses import replace

from src.core.log_event import LogEvent
from src.core.log_parser import HIGH_SEVERITIES, clean_text, parse_event_ts

ISO_TIMESTAMP = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b"
)
SYSLOG_TIMESTAMP = re.compile(r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b")
IP_ADDRESS = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
BRACKET_PID = re.compile(r"\[(\d+)\]")
KV_PID = re.compile(r"\bpid=(\d+)\b", re.IGNORECASE)
PATH = re.compile(r"(?<!<)(?:/[A-Za-z0-9._-]+)+")
NUMBER = re.compile(r"\b\d+\b")
DECISIVE_EVENT_PATTERNS = [
    re.compile(r"Accepted\s+(?:password|publickey)", re.IGNORECASE),
    re.compile(r"session\s+opened", re.IGNORECASE),
    re.compile(r"FTP\s+connection", re.IGNORECASE),
    re.compile(r"logrotate.*exited?\s+with", re.IGNORECASE),
    re.compile(r"segfault|OOM|out of memory", re.IGNORECASE),
]

SEVERITY_ORDER = {
    "debug": 0,
    "info": 1,
    "notice": 2,
    "warning": 3,
    "medium": 4,
    "high": 5,
    "error": 6,
    "critical": 7,
}


def extract_event_template(message: str) -> str:
    template = clean_text(message)
    template = ISO_TIMESTAMP.sub("<TIMESTAMP>", template)
    template = SYSLOG_TIMESTAMP.sub("<TIMESTAMP>", template)
    template = IP_ADDRESS.sub("<IP>", template)
    template = BRACKET_PID.sub("[<PID>]", template)
    template = KV_PID.sub("pid=<PID>", template)
    template = PATH.sub("<PATH>", template)
    template = NUMBER.sub("<NUM>", template)
    return clean_text(template)


def group_events_by_template(events: list[LogEvent]) -> dict[str, list[LogEvent]]:
    grouped: dict[str, list[LogEvent]] = {}
    for event in events:
        template = extract_event_template(event.message)
        grouped.setdefault(template, []).append(event)
    return grouped


def format_template_summary(
    template: str,
    count: int,
    severity_range: str,
    time_range: str,
) -> str:
    return f"{count} events | severity {severity_range} | time {time_range} | template {template}"


def severity_range_for_events(events: list[LogEvent]) -> str:
    values = [event.severity.strip().lower() or "unknown" for event in events]
    ranked = sorted(values, key=lambda value: (SEVERITY_ORDER.get(value, -1), value))
    if not ranked:
        return "unknown"
    if ranked[0] == ranked[-1]:
        return ranked[0]
    return f"{ranked[0]}->{ranked[-1]}"


def time_range_for_events(events: list[LogEvent]) -> str:
    parsed = [(parse_event_ts(event), event.timestamp) for event in events]
    valid = [(dt, raw) for dt, raw in parsed if dt is not None]
    if not valid:
        if not events:
            return "unknown"
        if len(events) == 1:
            return events[0].timestamp
        return f"{events[0].timestamp} -> {events[-1].timestamp}"
    valid.sort(key=lambda item: item[0])
    start = valid[0][1]
    end = valid[-1][1]
    return start if start == end else f"{start} -> {end}"


def clone_event(
    event: LogEvent,
    *,
    template: str,
    template_summary: str | None = None,
) -> LogEvent:
    raw_metadata = dict(event.raw_metadata)
    raw_metadata["__event_template"] = template
    if template_summary:
        raw_metadata["__template_summary"] = template_summary
    return replace(event, raw_metadata=raw_metadata)


def deduplicate_events(
    events: list[LogEvent],
    *,
    keep_threshold: int = 3,
    preserve_severity: set[str] | None = None,
    preserve_patterns: list[re.Pattern[str]] | None = None,
) -> list[LogEvent]:
    """Compress repeated templates while keeping leading/trailing and severe events."""
    if not events:
        return []

    preserve = {value.strip().lower() for value in (preserve_severity or HIGH_SEVERITIES)}
    patterns = DECISIVE_EVENT_PATTERNS if preserve_patterns is None else preserve_patterns
    indexed_templates = [
        (index, event, extract_event_template(event.message))
        for index, event in enumerate(events)
    ]

    grouped: dict[str, list[tuple[int, LogEvent]]] = {}
    for index, event, template in indexed_templates:
        grouped.setdefault(template, []).append((index, event))

    summaries: dict[int, tuple[str, str]] = {}
    selected_indices: set[int] = set()
    effective_keep = max(1, keep_threshold)

    for template, group in grouped.items():
        if len(group) <= effective_keep:
            selected_indices.update(index for index, _ in group)
            continue

        keep: set[int] = {index for index, _ in group[:effective_keep]}
        keep.update(index for index, _ in group[-effective_keep:])
        keep.update(
            index
            for index, event in group
            if event.severity.strip().lower() in preserve
        )
        keep.update(
            index
            for index, event in group
            if any(pattern.search(event.message) for pattern in patterns)
        )
        selected_indices.update(keep)

        first_selected = min(keep)
        summary = format_template_summary(
            template,
            len(group),
            severity_range_for_events([event for _, event in group]),
            time_range_for_events([event for _, event in group]),
        )
        summaries[first_selected] = (template, summary)

    deduplicated: list[LogEvent] = []
    for index, event, template in indexed_templates:
        if index not in selected_indices:
            continue
        summary = None
        if index in summaries:
            summary = summaries[index][1]
        deduplicated.append(clone_event(event, template=template, template_summary=summary))

    return deduplicated
