from src.core.log_event import LogEvent


def format_log_events_for_llm(events: list[LogEvent]) -> str:
    lines: list[str] = []
    for item in events:
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
            lines.append(
                f"{header} [{host}] {item.process}[{pid}]{context}: {item.message}"
            )
        else:
            proc = item.process.strip()
            if proc:
                lines.append(f"{header} {proc}: {item.message}")
            else:
                lines.append(f"{header} {item.message}")
    return "\n".join(lines)
