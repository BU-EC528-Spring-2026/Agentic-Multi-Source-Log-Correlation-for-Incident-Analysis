import re
from dataclasses import dataclass

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


def chunk_logs(entries: list[ParsedLog], chunk_size: int) -> list[list[ParsedLog]]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be > 0")
    return [entries[i : i + chunk_size] for i in range(0, len(entries), chunk_size)]
