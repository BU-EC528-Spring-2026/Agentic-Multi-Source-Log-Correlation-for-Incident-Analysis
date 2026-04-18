from src.core.log_event import LogEvent
from src.core.log_parser import HIGH_SEVERITIES


def format_log_event_full(item: LogEvent) -> str:
    line_ref = item.raw_metadata.get("line_no", item.event_id)
    host = item.raw_metadata.get("host", "")
    pid = item.raw_metadata.get("pid", "NA")
    context_value = item.raw_metadata.get("context")
    header = (
        f"[id={line_ref}] [{item.timestamp}] "
        f"src={item.source} cat={item.category} sev={item.severity}"
    )
    if host:
        context = f" ({context_value})" if context_value else ""
        return f"{header} [{host}] {item.process}[{pid}]{context}: {item.message}"
    proc = item.process.strip()
    if proc:
        return f"{header} {proc}: {item.message}"
    return f"{header} {item.message}"


def format_log_events_for_llm(events: list[LogEvent]) -> str:
    return "\n".join(format_log_event_full(item) for item in events)


def format_log_events_compact(events: list[LogEvent]) -> str:
    lines: list[str] = []
    for item in events:
        if item.severity.strip().lower() in HIGH_SEVERITIES:
            lines.append(format_log_event_full(item))
            continue
        line_ref = item.raw_metadata.get("line_no", item.event_id)
        lines.append(
            f"[{line_ref}] {item.timestamp} "
            f"{item.source}|{item.category}|{item.severity}: {item.message}"
        )
    return "\n".join(lines)
