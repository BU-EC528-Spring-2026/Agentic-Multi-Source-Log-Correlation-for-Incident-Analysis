import json
import re
from collections import Counter
from typing import Any

from src.core.client import InferenceClient, TieredInferenceClient
from src.core.llm_input import format_log_events_compact, format_log_events_for_llm
from src.core.log_event import LogEvent
from src.templates.prompts import (
    CATEGORY_TAXONOMY,
    CORRELATION_PROMPT,
    CORRELATION_SYSTEM,
    LOG_CATEGORIZATION_PROMPT,
    LOG_CATEGORIZATION_SYSTEM,
)

CATEGORIES = {
    "network",
    "dns_service_discovery",
    "authz_security",
    "process_lifecycle",
    "power_thermal_kernel",
    "application",
    "system_configuration",
    "hardware",
    "other",
}

CATEGORY_COUNT_PROPERTIES = {
    category: {"type": "integer"} for category in sorted(CATEGORIES)
}

CATEGORY_ALIASES = {
    "dns": "dns_service_discovery",
    "security": "authz_security",
    "auth": "authz_security",
    "authz": "authz_security",
    "process": "process_lifecycle",
    "lifecycle": "process_lifecycle",
    "power": "power_thermal_kernel",
    "thermal": "power_thermal_kernel",
    "kernel": "power_thermal_kernel",
    "config": "system_configuration",
    "configuration": "system_configuration",
}

SEVERITY_WEIGHTS = {
    "CRITICAL": 5.0,
    "HIGH": 3.0,
    "MEDIUM": 1.5,
    "LOW": 0.5,
}
VALID_SPURIOUS_RISKS = {"low", "medium", "high"}
VALID_CONFIDENCE_LEVELS = {"high", "medium", "low"}
FACT_REF_RE = re.compile(r"\[(?P<source>[^:\]]+):(?P<locator>[^\]]+)\]")

CHUNK_ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "chunk_id": {"type": "integer"},
        "line_start": {"type": "integer"},
        "line_end": {"type": "integer"},
        "category_counts": {
            "type": "object",
            "properties": CATEGORY_COUNT_PROPERTIES,
        },
        "top_findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "category": {"type": "string"},
                    "severity": {"type": "string"},
                    "count": {"type": "integer"},
                    "evidence": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["category", "severity", "count", "evidence"],
            },
        },
        "suspicious_events": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "line_no": {"type": "integer"},
                    "timestamp": {"type": "string"},
                    "process": {"type": "string"},
                    "category": {"type": "string"},
                    "severity": {"type": "string"},
                    "rationale": {"type": "string"},
                },
                "required": [
                    "line_no",
                    "timestamp",
                    "process",
                    "category",
                    "severity",
                    "rationale",
                ],
            },
        },
        "summary": {"type": "string"},
    },
    "required": [
        "chunk_id",
        "line_start",
        "line_end",
        "category_counts",
        "top_findings",
        "suspicious_events",
        "summary",
    ],
}

CORRELATION_SCHEMA = {
    "type": "object",
    "properties": {
        "global_summary": {"type": "string"},
        "category_totals": {
            "type": "object",
            "properties": CATEGORY_COUNT_PROPERTIES,
        },
        "key_correlations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "pattern_id": {"type": "string"},
                    "correlation_type": {"type": "string"},
                    "confidence": {"type": "number"},
                    "related_categories": {"type": "array", "items": {"type": "string"}},
                    "sources": {"type": "array", "items": {"type": "string"}},
                    "supporting_evidence": {"type": "array", "items": {"type": "string"}},
                    "explanation": {"type": "string"},
                },
                "required": [
                    "pattern_id",
                    "correlation_type",
                    "confidence",
                    "related_categories",
                    "sources",
                    "supporting_evidence",
                    "explanation",
                ],
            },
        },
        "hypotheses": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "hypothesis": {"type": "string"},
                    "sources_cited": {"type": "array", "items": {"type": "string"}},
                    "ordered_narrative": {"type": "string"},
                    "confidence": {"type": "number"},
                    "counterevidence": {"type": "string"},
                    "falsifiable_by": {"type": "string"},
                    "benign_alternatives": {"type": "array", "items": {"type": "string"}},
                    "causal_chain": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "step": {"type": "integer"},
                                "cause": {"type": "string"},
                                "effect": {"type": "string"},
                                "mechanism": {"type": "string"},
                            },
                            "required": ["step", "cause", "effect", "mechanism"],
                        },
                    },
                    "spurious_risk": {"type": "string"},
                    "spurious_risk_reasoning": {"type": "string"},
                    "red_herrings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "event": {"type": "string"},
                                "why_misleading": {"type": "string"},
                                "actual_explanation": {"type": "string"},
                            },
                            "required": ["event", "why_misleading"],
                        },
                    },
                    "confidence_level": {"type": "string"},
                    "confidence_detail": {"type": "string"},
                    "confounding_factors": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": [
                    "hypothesis",
                    "sources_cited",
                    "ordered_narrative",
                    "confidence",
                    "counterevidence",
                    "falsifiable_by",
                    "benign_alternatives",
                ],
            },
        },
        "timeline_highlights": {"type": "array", "items": {"type": "string"}},
        "next_queries": {"type": "array", "items": {"type": "string"}},
        "red_herrings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "event": {"type": "string"},
                    "why_misleading": {"type": "string"},
                    "actual_explanation": {"type": "string"},
                },
                "required": ["event", "why_misleading"],
            },
        },
    },
    "required": [
        "global_summary",
        "category_totals",
        "key_correlations",
        "hypotheses",
        "timeline_highlights",
        "next_queries",
    ],
}


def compact_chunk_payload(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "chunk_id": item.get("chunk_id"),
        "line_range": [item.get("line_start"), item.get("line_end")],
        "category_counts": item.get("category_counts", {}),
        "top_findings": item.get("top_findings", [])[:4],
        "suspicious_events": item.get("suspicious_events", [])[:8],
        "summary": item.get("summary", ""),
    }


def source_label(value: object) -> str:
    raw = str(value).strip().lower()
    if "/" in raw:
        return raw.split("/", 1)[0]
    if "\\" in raw:
        return raw.split("\\", 1)[0]
    return raw


def parse_fact_refs(fact_lines: list[str] | None) -> set[tuple[str, str]]:
    refs: set[tuple[str, str]] = set()
    for line in fact_lines or []:
        match = FACT_REF_RE.search(line)
        if not match:
            continue
        refs.add(
            (
                source_label(match.group("source")),
                match.group("locator").strip(),
            )
        )
    return refs


def chunk_event_refs(events: list[LogEvent]) -> set[tuple[str, str]]:
    refs: set[tuple[str, str]] = set()
    for event in events:
        source = source_label(event.source)
        for locator in (
            event.raw_metadata.get("line_no"),
            event.raw_metadata.get("line_id"),
            event.event_id,
        ):
            text = str(locator).strip()
            if text:
                refs.add((source, text))
    return refs


def chunk_sources(events: list[LogEvent]) -> set[str]:
    return {source_label(event.source) for event in events if str(event.source).strip()}


def chunk_categories(item: dict[str, Any], events: list[LogEvent]) -> set[str]:
    categories = {
        str(category).strip()
        for category, count in item.get("category_counts", {}).items()
        if count
    }
    for event in events:
        if str(event.category).strip():
            categories.add(str(event.category).strip())
    return categories


def chunk_severity_score(item: dict[str, Any]) -> float:
    score = 0.0
    for finding in item.get("top_findings", []):
        score += SEVERITY_WEIGHTS.get(
            str(finding.get("severity", "")).upper(),
            0.0,
        ) * max(1, int(finding.get("count", 1)))
    for event in item.get("suspicious_events", []):
        score += SEVERITY_WEIGHTS.get(
            str(event.get("severity", "")).upper(),
            0.0,
        )
    return score


def build_selection_candidates(
    chunk_analyses: list[dict[str, Any]],
    chunk_events: list[list[LogEvent]] | None,
    fact_lines: list[str] | None,
) -> list[dict[str, Any]]:
    total = len(chunk_analyses)
    fact_refs = parse_fact_refs(fact_lines)
    if total == 0:
        return []
    window_count = min(4, total)
    candidates: list[dict[str, Any]] = []
    for index, item in enumerate(chunk_analyses):
        events = chunk_events[index] if chunk_events and index < len(chunk_events) else []
        sources = chunk_sources(events)
        categories = chunk_categories(item, events)
        fact_overlap = len(chunk_event_refs(events) & fact_refs)
        suspicious_count = len(item.get("suspicious_events", []))
        severity_score = chunk_severity_score(item)
        window = min(window_count - 1, (index * window_count) // max(1, total))
        base_score = (
            fact_overlap * 12.0
            + suspicious_count * 4.0
            + severity_score * 1.5
            + len(categories) * 2.0
            + len(sources) * 2.0
        )
        candidates.append(
            {
                "index": index,
                "chunk_id": item.get("chunk_id"),
                "payload": compact_chunk_payload(item),
                "sources": sources,
                "categories": categories,
                "window": window,
                "fact_overlap": fact_overlap,
                "suspicious_count": suspicious_count,
                "base_score": base_score,
            }
        )
    return candidates


def candidate_sort_key(candidate: dict[str, Any]) -> tuple[float, float, int]:
    return (
        candidate["fact_overlap"],
        candidate["base_score"],
        -candidate["index"],
    )


def select_correlation_chunks(
    chunk_analyses: list[dict[str, Any]],
    *,
    chunk_events: list[list[LogEvent]] | None = None,
    fact_lines: list[str] | None = None,
    max_correlation_chunks: int | None = None,
    selection_strategy: str = "stratified",
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    compact_payload = [compact_chunk_payload(item) for item in chunk_analyses]
    total = len(compact_payload)
    limit = total if max_correlation_chunks is None else max_correlation_chunks
    strategy = selection_strategy if selection_strategy in {"head", "stratified"} else "stratified"
    if total <= limit:
        return compact_payload, {
            "strategy": strategy,
            "selected_chunk_ids": [
                item.get("chunk_id") for item in compact_payload if item.get("chunk_id") is not None
            ],
            "selection_note": "All chunk analyses were provided to correlation.",
            "selected_chunk_count": total,
            "total_available_chunks": total,
        }

    if strategy == "head":
        selected_payload = compact_payload[:limit]
        selected_ids = [
            item.get("chunk_id") for item in selected_payload if item.get("chunk_id") is not None
        ]
        note = (
            f"Showing {limit} of {total} chunks using head selection."
        )
        return selected_payload + [{
            "_note": note,
            "total_chunks": total,
            "selection_strategy": "head",
            "selected_chunk_ids": selected_ids,
        }], {
            "strategy": "head",
            "selected_chunk_ids": selected_ids,
            "selection_note": note,
            "selected_chunk_count": len(selected_ids),
            "total_available_chunks": total,
        }

    candidates = build_selection_candidates(
        chunk_analyses,
        chunk_events,
        fact_lines,
    )
    selected: set[int] = set()

    def choose(index: int) -> None:
        if 0 <= index < total and len(selected) < limit:
            selected.add(index)

    choose(0)
    choose(total - 1)

    fact_candidates = sorted(candidates, key=candidate_sort_key, reverse=True)
    for candidate in fact_candidates:
        if candidate["fact_overlap"] <= 0 or len(selected) >= limit:
            break
        choose(candidate["index"])

    window_best: dict[int, dict[str, Any]] = {}
    for candidate in candidates:
        best = window_best.get(candidate["window"])
        if best is None or candidate_sort_key(candidate) > candidate_sort_key(best):
            window_best[candidate["window"]] = candidate
    for window in sorted(window_best):
        if len(selected) >= limit:
            break
        choose(window_best[window]["index"])

    dominant_sources = Counter(
        source
        for candidate in candidates
        for source in candidate["sources"]
    )
    for source, _ in dominant_sources.most_common():
        if len(selected) >= limit:
            break
        source_candidates = [
            candidate for candidate in candidates
            if source in candidate["sources"] and candidate["index"] not in selected
        ]
        if not source_candidates:
            continue
        source_candidates.sort(key=candidate_sort_key, reverse=True)
        choose(source_candidates[0]["index"])

    while len(selected) < limit:
        covered_sources = {
            source
            for candidate in candidates
            if candidate["index"] in selected
            for source in candidate["sources"]
        }
        covered_categories = {
            category
            for candidate in candidates
            if candidate["index"] in selected
            for category in candidate["categories"]
        }
        covered_windows = {
            candidate["window"] for candidate in candidates if candidate["index"] in selected
        }

        best_candidate: dict[str, Any] | None = None
        best_score: tuple[float, int] | None = None
        for candidate in candidates:
            if candidate["index"] in selected:
                continue
            score = (
                candidate["base_score"]
                + len(candidate["sources"] - covered_sources) * 6.0
                + len(candidate["categories"] - covered_categories) * 2.5
                + (3.0 if candidate["window"] not in covered_windows else 0.0)
            )
            score_key = (score, -candidate["index"])
            if best_score is None or score_key > best_score:
                best_candidate = candidate
                best_score = score_key
        if best_candidate is None:
            break
        choose(best_candidate["index"])

    ordered = [candidate for candidate in candidates if candidate["index"] in selected]
    ordered.sort(key=lambda candidate: candidate["index"])
    selected_payload = [candidate["payload"] for candidate in ordered]
    selected_ids = [
        candidate["chunk_id"] for candidate in ordered if candidate["chunk_id"] is not None
    ]
    covered_source_count = len({
        source for candidate in ordered for source in candidate["sources"]
    })
    covered_window_count = len({candidate["window"] for candidate in ordered})
    fact_overlap_chunks = sum(1 for candidate in ordered if candidate["fact_overlap"] > 0)
    note = (
        f"Showing {len(selected_payload)} of {total} chunks using stratified selection "
        f"across {covered_window_count} time windows, {covered_source_count} sources, "
        f"and {fact_overlap_chunks} fact-overlap chunks."
    )
    return selected_payload + [{
        "_note": note,
        "total_chunks": total,
        "selection_strategy": "stratified",
        "selected_chunk_ids": selected_ids,
    }], {
        "strategy": "stratified",
        "selected_chunk_ids": selected_ids,
        "selection_note": note,
        "selected_chunk_count": len(selected_ids),
        "total_available_chunks": total,
    }


class ReasoningAgent:
    def __init__(self, llm_client: InferenceClient):
        self.llm = llm_client
        self.last_correlation_selection: dict[str, Any] = {}

    def _chat_structured(self, *, tier: str, **kwargs) -> dict:
        if isinstance(self.llm, TieredInferenceClient):
            return self.llm.chat_structured(tier=tier, **kwargs)
        return self.llm.chat_structured(**kwargs)

    def analyze_chunk(
        self,
        *,
        chunk_id: int,
        entries: list[LogEvent],
        seed: int | None = None,
        extra_user_suffix: str = "",
        compact_events: bool = True,
        include_retrieval: bool = True,
    ) -> dict:
        if not entries:
            raise ValueError("entries cannot be empty")

        line_start = int(entries[0].raw_metadata.get("line_no", 1))
        line_end = int(entries[-1].raw_metadata.get("line_no", line_start))
        prompt = LOG_CATEGORIZATION_PROMPT.format(
            chunk_id=chunk_id,
            line_start=line_start,
            line_end=line_end,
            log_block=(
                format_log_events_compact(entries)
                if compact_events
                else format_log_events_for_llm(entries)
            ),
            category_taxonomy=CATEGORY_TAXONOMY,
        )
        if include_retrieval and extra_user_suffix.strip():
            prompt = f"{prompt}\n\n{extra_user_suffix.strip()}"
        analysis = self._chat_structured(
            tier="chunk",
            schema=CHUNK_ANALYSIS_SCHEMA,
            system_prompt=LOG_CATEGORIZATION_SYSTEM,
            user_prompt=prompt,
            seed=seed,
            telemetry={"stage": "chunk_analysis", "chunk_id": chunk_id},
        )
        return self.normalize_chunk_analysis(
            payload=analysis,
            chunk_id=chunk_id,
            line_start=line_start,
            line_end=line_end,
        )

    def correlate(
        self,
        *,
        chunk_analyses: list[dict],
        chunk_events: list[list[LogEvent]] | None = None,
        source_scoped_analyses: dict[str, list[dict]] | None = None,
        source_agent_findings: str = "",
        facts_block: str = "",
        fact_lines: list[str] | None = None,
        seed: int | None = None,
        max_correlation_chunks: int | None = None,
        selection_strategy: str = "stratified",
    ) -> dict:
        if not chunk_analyses:
            raise ValueError("chunk_analyses cannot be empty")

        compact_payload, selection_meta = select_correlation_chunks(
            chunk_analyses,
            chunk_events=chunk_events,
            fact_lines=fact_lines,
            max_correlation_chunks=max_correlation_chunks,
            selection_strategy=selection_strategy,
        )
        self.last_correlation_selection = selection_meta

        source_scoped_section = ""
        if source_scoped_analyses:
            source_scoped_section = self.format_source_scoped_section(
                source_scoped_analyses,
            )

        findings_section = ""
        if source_agent_findings.strip():
            findings_section = (
                "\n\nRule-based source-agent incidents (pre-LLM):\n"
                + source_agent_findings.strip()
                + "\n"
            )

        prompt = CORRELATION_PROMPT.format(
            chunk_analysis_json=json.dumps(compact_payload),
            source_scoped_section=source_scoped_section,
            source_agent_findings_section=findings_section,
            category_taxonomy=CATEGORY_TAXONOMY,
        )
        if facts_block.strip():
            prompt = prompt.replace(
                "Category taxonomy:\n",
                "Key event facts (deterministically extracted, not LLM-generated):\n"
                + facts_block.strip()
                + "\n\nCategory taxonomy:\n",
                1,
            )
        payload = self._chat_structured(
            tier="correlation",
            schema=CORRELATION_SCHEMA,
            system_prompt=CORRELATION_SYSTEM,
            user_prompt=prompt,
            seed=seed,
            telemetry={"stage": "correlation"},
        )
        return self.normalize_correlation(payload)

    @staticmethod
    def format_source_scoped_section(
        source_scoped: dict[str, list[dict]],
    ) -> str:
        parts: list[str] = []
        for scope_name, analyses in sorted(source_scoped.items()):
            substantive = [
                a for a in analyses
                if a.get("top_findings") or a.get("suspicious_events")
            ]
            if not substantive:
                continue
            compact = []
            for item in substantive:
                compact.append({
                    "chunk_id": item.get("chunk_id"),
                    "category_counts": item.get("category_counts", {}),
                    "top_findings": item.get("top_findings", [])[:6],
                    "suspicious_events": item.get("suspicious_events", [])[:8],
                    "summary": item.get("summary", ""),
                })
            parts.append(
                f"Source-scoped analyses ({scope_name}):\n"
                + json.dumps(compact)
            )
        if not parts:
            return ""
        return "\n\n" + "\n\n".join(parts) + "\n"

    def normalize_chunk_analysis(
        self,
        *,
        payload: dict,
        chunk_id: int,
        line_start: int,
        line_end: int,
    ) -> dict:
        allowed_severity = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

        findings = []
        for item in payload.get("top_findings", []):
            if not isinstance(item, dict):
                continue
            severity = str(item.get("severity", "MEDIUM")).upper()
            if severity not in allowed_severity:
                severity = "MEDIUM"
            evidence = []
            for raw_evidence in item.get("evidence", []):
                text = str(raw_evidence).strip()
                if text and text not in evidence:
                    evidence.append(text)
            category = self.normalize_category(item.get("category", "other"))
            findings.append(
                {
                    "category": category,
                    "severity": severity,
                    "count": max(0, int(item.get("count", 0))),
                    "evidence": evidence[:4],
                }
            )

        suspicious = []
        for item in payload.get("suspicious_events", []):
            if not isinstance(item, dict):
                continue
            severity = str(item.get("severity", "MEDIUM")).upper()
            if severity not in allowed_severity:
                severity = "MEDIUM"
            category = self.normalize_category(item.get("category", "other"))
            suspicious.append(
                {
                    "line_no": max(1, int(item.get("line_no", line_start))),
                    "timestamp": str(item.get("timestamp", "")),
                    "process": str(item.get("process", "")),
                    "category": category,
                    "severity": severity,
                    "rationale": str(item.get("rationale", "")),
                }
            )

        category_counts = {}
        for key, value in payload.get("category_counts", {}).items():
            try:
                category = self.normalize_category(key)
                category_counts[category] = category_counts.get(category, 0) + max(0, int(value))
            except (TypeError, ValueError):
                continue

        findings.sort(key=lambda x: x["count"], reverse=True)
        suspicious.sort(key=lambda x: x["line_no"])

        return {
            "chunk_id": chunk_id,
            "line_start": line_start,
            "line_end": line_end,
            "category_counts": dict(sorted(category_counts.items())),
            "top_findings": findings[:8],
            "suspicious_events": suspicious[:12],
            "summary": str(payload.get("summary", "")),
        }

    def normalize_correlation(self, payload: dict) -> dict:
        normalized_patterns = []
        for item in payload.get("key_correlations", []):
            if not isinstance(item, dict):
                continue
            confidence_raw = item.get("confidence", 0.0)
            try:
                confidence = float(confidence_raw)
            except (TypeError, ValueError):
                confidence = 0.0
            confidence = min(1.0, max(0.0, confidence))
            related_categories = []
            for raw_category in item.get("related_categories", []):
                normalized = self.normalize_category(raw_category)
                if normalized not in related_categories:
                    related_categories.append(normalized)
            supporting = []
            for raw_supporting in item.get("supporting_evidence", []):
                text = str(raw_supporting).strip()
                if text and text not in supporting:
                    supporting.append(text)
            sources = self.clean_text_list(item.get("sources", []))
            normalized_patterns.append(
                {
                    "pattern_id": str(item.get("pattern_id", "P?")),
                    "correlation_type": str(item.get("correlation_type", "other")),
                    "confidence": round(confidence, 3),
                    "related_categories": related_categories,
                    "sources": sources,
                    "supporting_evidence": supporting[:6],
                    "explanation": str(item.get("explanation", "")),
                }
            )

        category_totals = {}
        for key, value in payload.get("category_totals", {}).items():
            try:
                category = self.normalize_category(key)
                category_totals[category] = category_totals.get(category, 0) + max(0, int(value))
            except (TypeError, ValueError):
                continue

        normalized_patterns.sort(key=lambda item: item["confidence"], reverse=True)

        return {
            "global_summary": str(payload.get("global_summary", "")),
            "category_totals": dict(sorted(category_totals.items())),
            "key_correlations": normalized_patterns,
            "hypotheses": self._normalize_hypotheses(payload.get("hypotheses", [])),
            "timeline_highlights": self.clean_text_list(payload.get("timeline_highlights", [])),
            "next_queries": self.clean_text_list(payload.get("next_queries", [])),
            "red_herrings": self._normalize_red_herrings(payload.get("red_herrings", [])),
        }

    def _normalize_hypotheses(self, raw: object) -> list[dict]:
        if not isinstance(raw, list):
            return []
        out: list[dict] = []
        for item in raw:
            if isinstance(item, str):
                out.append({
                    "hypothesis": item.strip(),
                    "sources_cited": [],
                    "ordered_narrative": "",
                    "confidence": 0.0,
                    "counterevidence": "",
                    "falsifiable_by": "",
                    "benign_alternatives": [],
                    "causal_chain": [],
                    "spurious_risk": "medium",
                    "spurious_risk_reasoning": "",
                    "red_herrings": [],
                    "confidence_level": "medium",
                    "confidence_detail": "",
                    "confounding_factors": [],
                })
                continue
            if not isinstance(item, dict):
                continue
            conf_raw = item.get("confidence", 0.0)
            try:
                conf = min(1.0, max(0.0, float(conf_raw)))
            except (TypeError, ValueError):
                conf = 0.0
            out.append({
                "hypothesis": str(item.get("hypothesis", "")).strip(),
                "sources_cited": self.clean_text_list(item.get("sources_cited", [])),
                "ordered_narrative": str(item.get("ordered_narrative", "")).strip(),
                "confidence": round(conf, 3),
                "counterevidence": str(item.get("counterevidence", "")).strip(),
                "falsifiable_by": str(item.get("falsifiable_by", "")).strip(),
                "benign_alternatives": self.clean_text_list(
                    item.get("benign_alternatives", [])
                ),
                "causal_chain": self._normalize_causal_chain(item.get("causal_chain", [])),
                "spurious_risk": self._normalize_choice(
                    item.get("spurious_risk", "medium"),
                    VALID_SPURIOUS_RISKS,
                ),
                "spurious_risk_reasoning": str(
                    item.get("spurious_risk_reasoning", "")
                ).strip(),
                "red_herrings": self._normalize_red_herrings(item.get("red_herrings", [])),
                "confidence_level": self._normalize_choice(
                    item.get("confidence_level", "medium"),
                    VALID_CONFIDENCE_LEVELS,
                ),
                "confidence_detail": str(item.get("confidence_detail", "")).strip(),
                "confounding_factors": self.clean_text_list(
                    item.get("confounding_factors", [])
                ),
            })
        return [h for h in out if h["hypothesis"]]

    @staticmethod
    def _normalize_choice(value: object, allowed: set[str], default: str = "medium") -> str:
        normalized = str(value).strip().lower()
        if normalized in allowed:
            return normalized
        return default

    @staticmethod
    def _normalize_causal_chain(raw: object) -> list[dict]:
        if not isinstance(raw, list):
            return []
        out: list[dict] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            raw_step = item.get("step", len(out) + 1)
            try:
                step = int(raw_step)
            except (TypeError, ValueError):
                step = len(out) + 1
            normalized = {
                "step": step,
                "cause": str(item.get("cause", "")).strip(),
                "effect": str(item.get("effect", "")).strip(),
                "mechanism": str(item.get("mechanism", "")).strip(),
            }
            if normalized["cause"] and normalized["effect"]:
                out.append(normalized)
        return out

    @staticmethod
    def _normalize_red_herrings(raw: object) -> list[dict]:
        if not isinstance(raw, list):
            return []
        out: list[dict] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            event = str(item.get("event", "")).strip()
            why = str(item.get("why_misleading", "")).strip()
            if not event or not why:
                continue
            out.append(
                {
                    "event": event,
                    "why_misleading": why,
                    "actual_explanation": str(
                        item.get("actual_explanation", "")
                    ).strip(),
                }
            )
        return out

    def normalize_category(self, value: object) -> str:
        normalized = str(value).strip().lower().replace(" ", "_").replace("-", "_")
        if normalized in CATEGORIES:
            return normalized
        if normalized in CATEGORY_ALIASES:
            return CATEGORY_ALIASES[normalized]
        return "other"

    def clean_text_list(self, values: object) -> list[str]:
        if not isinstance(values, list):
            return []
        cleaned = []
        for value in values:
            text = str(value).strip()
            if text and text not in cleaned:
                cleaned.append(text)
        return cleaned
