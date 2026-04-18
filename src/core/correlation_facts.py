import re

from src.core.log_event import LogEvent

AUTH_SUCCESS_PATTERN = re.compile(
    r"\bAccepted\s+(?:password|publickey)\b|\bsession\s+opened\b",
    re.IGNORECASE,
)
AUTH_BURST_PATTERN = re.compile(r"\bFailed\s+password\b|\bInvalid\s+user\b", re.IGNORECASE)
FTP_ACTIVITY_PATTERN = re.compile(r"\bFTP\s+connection\b|\bftp\b|\bvsftpd\b", re.IGNORECASE)
SERVICE_FAILURE_PATTERN = re.compile(
    r"\blogrotate\b.*\bexited?\b.*\bwith\b|\bsegfault\b|\bOOM\b|\bout of memory\b|\bsignal\b",
    re.IGNORECASE,
)
OPENSTACK_ANOMALY_PATTERN = re.compile(r"\bnova\b|\bneutron\b|\bERROR\b", re.IGNORECASE)

SECURITY_FACT_PATTERNS = [
    AUTH_SUCCESS_PATTERN,
    AUTH_BURST_PATTERN,
    FTP_ACTIVITY_PATTERN,
    SERVICE_FAILURE_PATTERN,
    OPENSTACK_ANOMALY_PATTERN,
]

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USER_PATTERN = re.compile(r"\bfor (?:invalid user )?([A-Za-z0-9_.-]+)", re.IGNORECASE)


def format_fact_line(event: LogEvent) -> str:
    line_no = event.raw_metadata.get("line_no", event.event_id)
    return f"{event.timestamp} [{event.source}:{line_no}] {event.message}"


def auth_burst_key(event: LogEvent) -> tuple[str, str, str]:
    message = event.message
    ip_match = IP_PATTERN.search(message)
    user_match = USER_PATTERN.search(message)
    ip = ip_match.group(0) if ip_match else ""
    user = user_match.group(1) if user_match else ""
    return ("auth_burst", user, ip)


def extract_security_facts(events: list[LogEvent], *, max_lines: int = 50) -> list[str]:
    if max_lines <= 0:
        return []

    facts: list[str] = []
    seen: set[tuple[str, ...]] = set()
    for event in events:
        message = event.message
        haystack = f"{event.process} {message}"
        key: tuple[str, ...] | None = None
        if AUTH_SUCCESS_PATTERN.search(haystack):
            key = ("event", event.event_id)
        elif AUTH_BURST_PATTERN.search(haystack):
            key = auth_burst_key(event)
        elif FTP_ACTIVITY_PATTERN.search(haystack):
            key = ("event", event.event_id)
        elif SERVICE_FAILURE_PATTERN.search(haystack):
            key = ("event", event.event_id)
        elif event.source.strip().lower() == "openstack" and OPENSTACK_ANOMALY_PATTERN.search(haystack):
            key = ("event", event.event_id)

        if key is None or key in seen:
            continue
        seen.add(key)
        facts.append(format_fact_line(event))
        if len(facts) >= max_lines:
            break
    return facts


def format_facts_block(
    facts: list[str],
    total_chunks_shown: int,
    total_chunks_available: int,
) -> str:
    if not facts:
        return ""
    note = f"Showing {total_chunks_shown} of {total_chunks_available} chunk summaries."
    if total_chunks_shown < total_chunks_available:
        note += " Key events below may not appear in those summaries."
    return note + "\n" + "\n".join(f"- {fact}" for fact in facts)
