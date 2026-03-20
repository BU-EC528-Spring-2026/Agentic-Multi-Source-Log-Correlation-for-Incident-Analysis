import pytest
from datetime import datetime, timezone, timedelta

from src.agents.correlation.correlation_agent import LogEvent, CorrelationAgent


def _dt(seconds: int) -> datetime:
    # fixed baseline for deterministic tests
    base = datetime(2026, 3, 4, 12, 0, 0, tzinfo=timezone.utc)
    return base + timedelta(seconds=seconds)


def test_correlate_by_trace_id_across_sources():
    events = [
        LogEvent.from_dict({
            "event_id": "a1",
            "timestamp": _dt(0).isoformat(),
            "source": "app",
            "message": "request failed with 500",
            "trace_id": "t-123",
            "service": "checkout",
        }),
        LogEvent.from_dict({
            "event_id": "b1",
            "timestamp": _dt(10).isoformat(),
            "source": "infra",
            "message": "pod restarted",
            "trace_id": "t-123",
            "service": "checkout",
        }),
        LogEvent.from_dict({
            "event_id": "c1",
            "timestamp": _dt(200).isoformat(),
            "source": "app",
            "message": "unrelated later event",
            "trace_id": "t-999",
            "service": "search",
        }),
    ]

    agent = CorrelationAgent(time_window_seconds=30)
    groups = agent.correlate(events)

    # expect 2 groups: (a1,b1) together and c1 alone
    assert len(groups) == 2
    g0 = groups[0]
    assert [e.event_id for e in g0.events] == ["a1", "b1"]
    assert any("entity_match" in r for r in g0.reasons)


def test_no_correlation_outside_time_window():
    events = [
        LogEvent.from_dict({
            "event_id": "a1",
            "timestamp": _dt(0).isoformat(),
            "source": "app",
            "message": "timeout contacting db",
            "host": "node-1",
            "service": "api",
        }),
        # same host/service but 2 minutes later (outside window)
        LogEvent.from_dict({
            "event_id": "b1",
            "timestamp": _dt(120).isoformat(),
            "source": "infra",
            "message": "high cpu on node-1",
            "host": "node-1",
            "service": "api",
        }),
    ]

    agent = CorrelationAgent(time_window_seconds=30)
    groups = agent.correlate(events)

    assert len(groups) == 2
    assert [e.event_id for e in groups[0].events] == ["a1"]
    assert [e.event_id for e in groups[1].events] == ["b1"]


def test_message_similarity_fallback_within_window():
    events = [
        LogEvent.from_dict({
            "event_id": "a1",
            "timestamp": _dt(0).isoformat(),
            "source": "app",
            "message": "TLS handshake failed for upstream 10.0.0.12",
            "service": "gateway",
        }),
        LogEvent.from_dict({
            "event_id": "b1",
            "timestamp": _dt(8).isoformat(),
            "source": "network",
            "message": "tls handshake failure to upstream 10.0.0.99",
            "service": "gateway",
        }),
    ]

    agent = CorrelationAgent(
        time_window_seconds=30,
        use_message_similarity_fallback=True,
        min_message_similarity=0.70,
        # IMPORTANT: exclude "service" so entity matching doesn't "steal" the correlation
        entity_keys=("trace_id", "request_id", "span_id", "host", "ip"),
    )
    groups = agent.correlate(events)

    assert len(groups) == 1
    assert [e.event_id for e in groups[0].events] == ["a1", "b1"]
    assert any(r.startswith("msg_sim(") for r in groups[0].reasons)


def test_require_distinct_sources_filters_single_source_groups():
    events = [
        LogEvent.from_dict({
            "event_id": "a1",
            "timestamp": _dt(0).isoformat(),
            "source": "app",
            "message": "error 1",
            "trace_id": "t-1",
        }),
        LogEvent.from_dict({
            "event_id": "a2",
            "timestamp": _dt(5).isoformat(),
            "source": "app",
            "message": "error 2",
            "trace_id": "t-1",
        }),
    ]

    agent = CorrelationAgent(time_window_seconds=30, require_distinct_sources=True)
    groups = agent.correlate(events)

    # Since both are from the same source only, the group is filtered out,
    # leaving both events unassigned -> result is empty.
    # (This setting is optional; keep it False for most demos.)
    assert groups == []