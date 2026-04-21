import time

from src.agents.log_analyzer import ReasoningAgent
from src.core.log_event import LogEvent
from src.core.log_parser import chunk_logs

AUTH_SOURCE_KEYS = frozenset({"openssh"})
OPENSTACK_SOURCE_KEYS = frozenset({"openstack"})
LINUX_SOURCE_KEYS = frozenset({"linux"})
APACHE_SOURCE_KEYS = frozenset({"apache"})


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


def select_lane_chunks(
    chunks: list[list[LogEvent]],
    max_chunks: int,
) -> list[list[LogEvent]]:
    if max_chunks <= 0 or len(chunks) <= max_chunks:
        return chunks
    if max_chunks == 1:
        return [chunks[0]]
    last = len(chunks) - 1
    return [chunks[(i * last) // (max_chunks - 1)] for i in range(max_chunks)]


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


def analyze_source_events(
    agent: ReasoningAgent,
    events: list[LogEvent],
    sources: frozenset[str],
    label: str,
    *,
    chunk_id: int = 1,
    seed: int | None = None,
    lane_chunk_size: int = 250,
    max_chunks: int = 0,
    deadline_at: float | None = None,
    compact_events: bool = True,
) -> tuple[list[dict], int]:
    source_events = events_for_sources(events, sources)
    if not source_events:
        return [empty_chunk_analysis(f"No {label} events in input.", chunk_id=chunk_id)], 0
    chunks = select_lane_chunks(chunk_logs(source_events, lane_chunk_size), max_chunks)
    results = []
    for offset, chunk in enumerate(chunks):
        if deadline_at is not None and time.monotonic() > deadline_at:
            raise TimeoutError(f"Source lane deadline exceeded for {label}")
        results.append(
            agent.analyze_chunk(
                chunk_id=chunk_id + offset,
                entries=chunk,
                seed=None if seed is None else seed + offset,
                compact_events=compact_events,
            )
        )
    return results, len(chunks)


def analyze_auth_events(
    agent: ReasoningAgent,
    events: list[LogEvent],
    *,
    chunk_id: int = 1,
    seed: int | None = None,
    lane_chunk_size: int = 250,
    max_chunks: int = 0,
    deadline_at: float | None = None,
    compact_events: bool = True,
) -> tuple[list[dict], int]:
    return analyze_source_events(
        agent,
        events,
        AUTH_SOURCE_KEYS,
        "auth-source",
        chunk_id=chunk_id,
        seed=seed,
        lane_chunk_size=lane_chunk_size,
        max_chunks=max_chunks,
        deadline_at=deadline_at,
        compact_events=compact_events,
    )


def analyze_openstack_events(
    agent: ReasoningAgent,
    events: list[LogEvent],
    *,
    chunk_id: int = 1,
    seed: int | None = None,
    lane_chunk_size: int = 250,
    max_chunks: int = 0,
    deadline_at: float | None = None,
    compact_events: bool = True,
) -> tuple[list[dict], int]:
    return analyze_source_events(
        agent,
        events,
        OPENSTACK_SOURCE_KEYS,
        "openstack",
        chunk_id=chunk_id,
        seed=seed,
        lane_chunk_size=lane_chunk_size,
        max_chunks=max_chunks,
        deadline_at=deadline_at,
        compact_events=compact_events,
    )


def analyze_linux_events(
    agent: ReasoningAgent,
    events: list[LogEvent],
    *,
    chunk_id: int = 1,
    seed: int | None = None,
    lane_chunk_size: int = 250,
    max_chunks: int = 0,
    deadline_at: float | None = None,
    compact_events: bool = True,
) -> tuple[list[dict], int]:
    return analyze_source_events(
        agent,
        events,
        LINUX_SOURCE_KEYS,
        "linux",
        chunk_id=chunk_id,
        seed=seed,
        lane_chunk_size=lane_chunk_size,
        max_chunks=max_chunks,
        deadline_at=deadline_at,
        compact_events=compact_events,
    )


def analyze_apache_events(
    agent: ReasoningAgent,
    events: list[LogEvent],
    *,
    chunk_id: int = 1,
    seed: int | None = None,
    lane_chunk_size: int = 250,
    max_chunks: int = 0,
    deadline_at: float | None = None,
    compact_events: bool = True,
) -> tuple[list[dict], int]:
    return analyze_source_events(
        agent,
        events,
        APACHE_SOURCE_KEYS,
        "apache",
        chunk_id=chunk_id,
        seed=seed,
        lane_chunk_size=lane_chunk_size,
        max_chunks=max_chunks,
        deadline_at=deadline_at,
        compact_events=compact_events,
    )
