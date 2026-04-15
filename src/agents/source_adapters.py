from src.agents.log_analyzer import ReasoningAgent
from src.core.log_event import LogEvent

AUTH_SOURCE_KEYS = frozenset({"openssh"})
INFRA_SOURCE_KEYS = frozenset({"openstack", "linux", "apache"})


def source_label_for_filter(raw: str) -> str:
    s = raw.strip().lower()
    if not s:
        return s
    if "/" in s:
        return s.split("/", 1)[0]
    if "\\" in s:
        return s.split("\\", 1)[0]
    return s


def event_matches_sources(event: LogEvent, want: frozenset[str]) -> bool:
    want_l = {x.lower() for x in want}
    label = source_label_for_filter(event.source)
    return label in want_l or event.source.strip().lower() in want_l


def events_for_sources(events: list[LogEvent], sources: frozenset[str]) -> list[LogEvent]:
    return [e for e in events if event_matches_sources(e, sources)]


def contiguous_runs_for_sources(
    events: list[LogEvent],
    sources: frozenset[str],
) -> list[list[LogEvent]]:
    runs: list[list[LogEvent]] = []
    current: list[LogEvent] = []
    for event in events:
        if event_matches_sources(event, sources):
            current.append(event)
        else:
            if current:
                runs.append(current)
                current = []
    if current:
        runs.append(current)
    return runs


def empty_chunk_analysis(summary: str, chunk_id: int = 1) -> dict:
    return {
        "chunk_id": chunk_id,
        "line_start": 1,
        "line_end": 1,
        "category_counts": {},
        "top_findings": [],
        "suspicious_events": [],
        "summary": summary,
    }


def analyze_auth_events(
    agent: ReasoningAgent,
    events: list[LogEvent],
    *,
    chunk_id: int = 1,
    seed: int | None = None,
) -> list[dict]:
    runs = contiguous_runs_for_sources(events, AUTH_SOURCE_KEYS)
    if not runs:
        return [empty_chunk_analysis("No auth-source events in input.", chunk_id=chunk_id)]
    results = []
    for offset, run in enumerate(runs):
        results.append(
            agent.analyze_chunk(
                chunk_id=chunk_id + offset,
                entries=run,
                seed=None if seed is None else seed + offset,
            )
        )
    return results


def analyze_infra_events(
    agent: ReasoningAgent,
    events: list[LogEvent],
    *,
    chunk_id: int = 2,
    seed: int | None = None,
) -> list[dict]:
    runs = contiguous_runs_for_sources(events, INFRA_SOURCE_KEYS)
    if not runs:
        return [
            empty_chunk_analysis(
                "No infrastructure-source events in input.",
                chunk_id=chunk_id,
            )
        ]
    results = []
    for offset, run in enumerate(runs):
        results.append(
            agent.analyze_chunk(
                chunk_id=chunk_id + offset,
                entries=run,
                seed=None if seed is None else seed + offset,
            )
        )
    return results
