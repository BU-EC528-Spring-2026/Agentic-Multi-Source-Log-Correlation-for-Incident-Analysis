import json

from src.core.client import InferenceClient
from src.core.llm_input import format_log_events_for_llm
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
                    "supporting_evidence": {"type": "array", "items": {"type": "string"}},
                    "explanation": {"type": "string"},
                },
                "required": [
                    "pattern_id",
                    "correlation_type",
                    "confidence",
                    "related_categories",
                    "supporting_evidence",
                    "explanation",
                ],
            },
        },
        "hypotheses": {"type": "array", "items": {"type": "string"}},
        "timeline_highlights": {"type": "array", "items": {"type": "string"}},
        "next_queries": {"type": "array", "items": {"type": "string"}},
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


class ReasoningAgent:
    def __init__(self, llm_client: InferenceClient):
        self.llm = llm_client

    def analyze_chunk(
        self,
        *,
        chunk_id: int,
        entries: list[LogEvent],
        seed: int | None = None,
        extra_user_suffix: str = "",
    ) -> dict:
        if not entries:
            raise ValueError("entries cannot be empty")

        line_start = int(entries[0].raw_metadata.get("line_no", 1))
        line_end = int(entries[-1].raw_metadata.get("line_no", line_start))
        prompt = LOG_CATEGORIZATION_PROMPT.format(
            chunk_id=chunk_id,
            line_start=line_start,
            line_end=line_end,
            log_block=format_log_events_for_llm(entries),
            category_taxonomy=CATEGORY_TAXONOMY,
        )
        if extra_user_suffix.strip():
            prompt = f"{prompt}\n\n{extra_user_suffix.strip()}"
        analysis = self.llm.chat_structured(
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
        seed: int | None = None,
    ) -> dict:
        if not chunk_analyses:
            raise ValueError("chunk_analyses cannot be empty")

        compact_payload = []
        for item in chunk_analyses:
            compact_payload.append(
                {
                    "chunk_id": item.get("chunk_id"),
                    "line_range": [item.get("line_start"), item.get("line_end")],
                    "category_counts": item.get("category_counts", {}),
                    "top_findings": item.get("top_findings", [])[:6],
                    "suspicious_events": item.get("suspicious_events", [])[:12],
                    "summary": item.get("summary", ""),
                }
            )

        prompt = CORRELATION_PROMPT.format(
            chunk_analysis_json=json.dumps(compact_payload, indent=2),
            category_taxonomy=CATEGORY_TAXONOMY,
        )
        payload = self.llm.chat_structured(
            schema=CORRELATION_SCHEMA,
            system_prompt=CORRELATION_SYSTEM,
            user_prompt=prompt,
            seed=seed,
            telemetry={"stage": "correlation"},
        )
        return self.normalize_correlation(payload)

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
            normalized_patterns.append(
                {
                    "pattern_id": str(item.get("pattern_id", "P?")),
                    "correlation_type": str(item.get("correlation_type", "other")),
                    "confidence": round(confidence, 3),
                    "related_categories": related_categories,
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
            "hypotheses": self.clean_text_list(payload.get("hypotheses", [])),
            "timeline_highlights": self.clean_text_list(payload.get("timeline_highlights", [])),
            "next_queries": self.clean_text_list(payload.get("next_queries", [])),
        }

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
