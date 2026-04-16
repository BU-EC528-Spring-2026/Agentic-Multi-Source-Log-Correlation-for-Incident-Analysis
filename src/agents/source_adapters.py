from src.agents.log_analyzer import ReasoningAgent
from src.core.log_event import LogEvent

AUTH_SOURCE_KEYS = frozenset({"openssh"})
OPENSTACK_SOURCE_KEYS = frozenset({"openstack"})
LINUX_SOURCE_KEYS = frozenset({"linux"})
APACHE_SOURCE_KEYS = frozenset({"apache"})
INFRA_SOURCE_KEYS = OPENSTACK_SOURCE_KEYS | LINUX_SOURCE_KEYS | APACHE_SOURCE_KEYS
SOURCE_PROMPT_HINTS = {
    "auth-source": (
        "Source focus: authentication anomalies.\n"
        "- Prioritize failed logins, brute-force bursts, invalid users, lockouts, "
        "and privilege-escalation indicators.\n"
        "- Distinguish scanner noise from sustained actor behavior by repeated "
        "principal + host patterns in close time windows."
    ),
    "openstack": (
        "Source focus: OpenStack VM lifecycle anomalies.\n"
        "- Prioritize restart loops, stop/start churn, and lifecycle transitions "
        "that violate expected ordering.\n"
        "- Use instance identifiers and controller/compute components as evidence."
    ),
    "linux": (
        "Source focus: Linux runtime and kernel/system health anomalies.\n"
        "- Prioritize kernel panic, OOM kills, filesystem errors, service crashes, "
        "permission denials, and timeout cascades.\n"
        "- Flag possible root-cause signals vs downstream symptoms."
    ),
    "apache": (
        "Source focus: Apache access anomalies.\n"
        "- Prioritize concentrated 4xx/5xx patterns, suspicious probe paths, and "
        "host/client patterns indicating automated abuse.\n"
        "- Separate normal crawling noise from impactful access failures."
    ),
    "infrastructure-source": (
        "Source focus: cross-infrastructure anomalies (OpenStack + Linux + Apache).\n"
        "- Prioritize temporally linked failures across components and likely "
        "dependency chains."
    ),
}


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


def _severity_rank(value: str) -> int:
    order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return order.get(str(value).upper(), 2)


def calibrate_source_result(label: str, payload: dict) -> dict:
    out = dict(payload)
    suspicious = [dict(x) for x in out.get("suspicious_events", []) if isinstance(x, dict)]
    findings = [dict(x) for x in out.get("top_findings", []) if isinstance(x, dict)]

    if label == "auth-source":
        # Promote repeated auth failure evidence; suppress isolated noise.
        auth_signals = [
            e for e in suspicious
            if any(token in str(e.get("rationale", "")).lower() for token in ("failed", "invalid", "brute"))
        ]
        if len(auth_signals) >= 3:
            for event in suspicious:
                if _severity_rank(str(event.get("severity", "MEDIUM"))) < 3:
                    event["severity"] = "HIGH"
        elif len(suspicious) <= 1:
            for event in suspicious:
                if _severity_rank(str(event.get("severity", "MEDIUM"))) > 2:
                    event["severity"] = "MEDIUM"

    elif label == "apache":
        # Avoid over-triggering on one-off scans; require concentration.
        if len(suspicious) <= 1:
            for event in suspicious:
                if _severity_rank(str(event.get("severity", "MEDIUM"))) > 2:
                    event["severity"] = "MEDIUM"

    elif label == "linux":
        # Kernel panic / OOM-like signals are generally high-confidence operational incidents.
        for event in suspicious:
            text = f"{event.get('rationale', '')} {event.get('category', '')}".lower()
            if any(token in text for token in ("panic", "oom", "filesystem", "segfault")):
                if _severity_rank(str(event.get("severity", "MEDIUM"))) < 3:
                    event["severity"] = "HIGH"

    elif label == "openstack":
        # Lifecycle churn with multiple suspicious records should stay high.
        if len(suspicious) >= 2:
            for event in suspicious:
                text = f"{event.get('rationale', '')} {event.get('category', '')}".lower()
                if any(token in text for token in ("restart", "lifecycle", "churn", "stop")):
                    if _severity_rank(str(event.get("severity", "MEDIUM"))) < 3:
                        event["severity"] = "HIGH"

    findings.sort(key=lambda x: int(x.get("count", 0)), reverse=True)
    suspicious.sort(key=lambda x: int(x.get("line_no", 0)))
    out["top_findings"] = findings[:8]
    out["suspicious_events"] = suspicious[:12]
    return out


def analyze_source_events(
    agent: ReasoningAgent,
    events: list[LogEvent],
    sources: frozenset[str],
    label: str,
    *,
    chunk_id: int = 1,
    seed: int | None = None,
    rule_findings_hint: str = "",
) -> list[dict]:
    runs = contiguous_runs_for_sources(events, sources)
    if not runs:
        return [empty_chunk_analysis(f"No {label} events in input.", chunk_id=chunk_id)]
    prompt_hint = SOURCE_PROMPT_HINTS.get(label, "")
    guidance_parts = [part for part in (prompt_hint, rule_findings_hint.strip()) if part]
    guidance_suffix = "\n\n".join(guidance_parts)
    results = []
    for offset, run in enumerate(runs):
        results.append(
            calibrate_source_result(
                label,
                agent.analyze_chunk(
                    chunk_id=chunk_id + offset,
                    entries=run,
                    seed=None if seed is None else seed + offset,
                    extra_user_suffix=guidance_suffix,
                ),
            )
        )
    return results


def analyze_auth_events(
    agent: ReasoningAgent,
    events: list[LogEvent],
    *,
    chunk_id: int = 1,
    seed: int | None = None,
    rule_findings_hint: str = "",
) -> list[dict]:
    return analyze_source_events(
        agent, events, AUTH_SOURCE_KEYS, "auth-source",
        chunk_id=chunk_id, seed=seed, rule_findings_hint=rule_findings_hint,
    )


def analyze_openstack_events(
    agent: ReasoningAgent,
    events: list[LogEvent],
    *,
    chunk_id: int = 1,
    seed: int | None = None,
    rule_findings_hint: str = "",
) -> list[dict]:
    return analyze_source_events(
        agent, events, OPENSTACK_SOURCE_KEYS, "openstack",
        chunk_id=chunk_id, seed=seed, rule_findings_hint=rule_findings_hint,
    )


def analyze_linux_events(
    agent: ReasoningAgent,
    events: list[LogEvent],
    *,
    chunk_id: int = 1,
    seed: int | None = None,
    rule_findings_hint: str = "",
) -> list[dict]:
    return analyze_source_events(
        agent, events, LINUX_SOURCE_KEYS, "linux",
        chunk_id=chunk_id, seed=seed, rule_findings_hint=rule_findings_hint,
    )


def analyze_apache_events(
    agent: ReasoningAgent,
    events: list[LogEvent],
    *,
    chunk_id: int = 1,
    seed: int | None = None,
    rule_findings_hint: str = "",
) -> list[dict]:
    return analyze_source_events(
        agent, events, APACHE_SOURCE_KEYS, "apache",
        chunk_id=chunk_id, seed=seed, rule_findings_hint=rule_findings_hint,
    )


def analyze_infra_events(
    agent: ReasoningAgent,
    events: list[LogEvent],
    *,
    chunk_id: int = 2,
    seed: int | None = None,
) -> list[dict]:
    return analyze_source_events(
        agent, events, INFRA_SOURCE_KEYS, "infrastructure-source",
        chunk_id=chunk_id, seed=seed,
    )
