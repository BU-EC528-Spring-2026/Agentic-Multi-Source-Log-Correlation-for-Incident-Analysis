import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.agents.correlation.correlation_agent import (
    CorrelationAgent,
    LogEvent as CorrelationLogEvent,
)
from src.agents.log_analyzer import ReasoningAgent
from src.agents.orchestrator_agent import run_source_agents
from src.agents.source_adapters import analyze_auth_events, analyze_infra_events
from src.common import load_logs
from src.core.client import create_client
from src.core.config import (
    BEDROCK_MODEL,
    BEDROCK_REGION,
    DEFAULT_CHUNK_SIZE,
    DEFAULT_MAX_LINES,
    DEFAULT_MAX_RETRIES,
    DEFAULT_PROVIDER,
    DEFAULT_TEMPERATURE,
    DEFAULT_TIMEOUT_SECONDS,
    GROQ_API_KEY,
    GROQ_CHUNK_SIZE,
    GROQ_MODEL,
    OPENROUTER_API_KEY,
    OPENROUTER_MODEL,
    OPENROUTER_MODEL_CANDIDATES,
    RETRIEVAL_CONTEXT,
    RETRIEVAL_TOP_K,
    bedrock_configured,
)
from src.core.log_event import (
    LogEvent,
    build_events,
    build_events_from_ingestion_records,
    build_source_name,
)
from src.core.log_parser import ParsedLog, chunk_logs, parse_logs
from src.ingestion.ingest_logs import (
    DATA_ROOT,
    DATASET_PATHS,
    OUTPUT_JSONL,
    OUTPUT_SUMMARY,
    compute_summary,
    load_all_datasets,
    validate_all_records,
    write_jsonl,
    write_summary_json,
)
from src.retrieval.rag_context import RetrievalContext

LOW_SIGNAL_MARKERS = (
    "scheduler_evaluate_activity told me to run this job",
    "location icon should now be in state",
)
DEMO_NORMALIZED_LOG_FILE = (
    Path(__file__).resolve().parent.parent / "examples" / "demo_unified_logs.jsonl"
)
DEFAULT_RAW_LOG_FILE = str(DATA_ROOT / "Mac" / "Mac_2k.log")


def load_log_file(path: str, max_lines: int) -> list[str]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"log file not found: {p}")
    with p.open("r", encoding="utf-8", errors="replace") as handle:
        lines = [line for _, line in zip(range(max_lines), handle)]
    return lines


def drop_low_signal_lines(
    entries: list[ParsedLog],
    enabled: bool,
) -> tuple[list[ParsedLog], int]:
    if not enabled:
        return entries, 0
    kept = []
    dropped = 0
    for item in entries:
        message = item.message.lower()
        if any(marker in message for marker in LOW_SIGNAL_MARKERS):
            dropped += 1
            continue
        kept.append(item)
    return kept, dropped


def available_dataset_paths() -> list[str]:
    missing = []
    for path in DATASET_PATHS.values():
        if not path.exists():
            missing.append(str(path))
    return missing


def ingest_normalized_logs() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    all_records, per_dataset = load_all_datasets(DATASET_PATHS)
    validate_all_records(all_records)
    all_records.sort(key=lambda record: record["timestamp_epoch"])

    write_jsonl(all_records, OUTPUT_JSONL)
    summary = compute_summary(all_records, per_dataset)
    write_summary_json(summary, OUTPUT_SUMMARY)
    return all_records, summary


def load_normalized_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"normalized log file not found: {path}")
    return load_logs(path)


def prepare_pipeline_inputs(
    *,
    log_file: str,
    normalized_log_file: str,
    max_lines: int,
    drop_low_signal: bool,
    ingest_if_needed: bool,
) -> tuple[list[LogEvent], dict[str, Any]]:
    normalized_path = Path(normalized_log_file)
    raw_path = Path(log_file) if log_file else None

    if normalized_path.exists():
        records = load_normalized_records(normalized_path)
        events, rejected = build_events_from_ingestion_records(records)
        if not events:
            raise RuntimeError("normalized log file did not contain any usable events")
        return events, {
            "input_mode": "normalized_jsonl",
            "input_path": str(normalized_path.resolve()),
            "normalized_record_count": len(records),
            "event_count": len(events),
            "rejected_record_count": len(rejected),
            "rejected_examples": rejected[:20],
        }

    if ingest_if_needed:
        missing = available_dataset_paths()
        if not missing:
            records, ingestion_summary = ingest_normalized_logs()
            events, rejected = build_events_from_ingestion_records(records)
            if not events:
                raise RuntimeError("ingestion completed but produced no usable events")
            return events, {
                "input_mode": "ingested_datasets",
                "input_path": str(OUTPUT_JSONL.resolve()),
                "normalized_record_count": len(records),
                "event_count": len(events),
                "rejected_record_count": len(rejected),
                "rejected_examples": rejected[:20],
                "ingestion_summary": ingestion_summary,
            }

    if raw_path and raw_path.exists():
        raw_lines = load_log_file(str(raw_path), max_lines=max_lines)
        parsed_lines, skipped_lines = parse_logs(raw_lines)
        parsed_before_filter_count = len(parsed_lines)
        parsed_lines, dropped_low_signal_count = drop_low_signal_lines(
            parsed_lines,
            enabled=drop_low_signal,
        )
        if not parsed_lines:
            raise RuntimeError("No parsable log lines found in input file")

        source = build_source_name(str(raw_path))
        events = build_events(parsed_lines, source=source)
        return events, {
            "input_mode": "raw_log_file",
            "input_path": str(raw_path.resolve()),
            "source": source,
            "raw_line_count": len(raw_lines),
            "parsed_line_count": parsed_before_filter_count,
            "parsed_after_filter_count": len(parsed_lines),
            "skipped_line_count": len(skipped_lines),
            "dropped_low_signal_count": dropped_low_signal_count,
            "parser": {
                "skip_rate": round(len(skipped_lines) / max(1, len(raw_lines)), 4),
                "skipped_examples": skipped_lines[:20],
            },
        }

    if DEMO_NORMALIZED_LOG_FILE.exists():
        missing_datasets = available_dataset_paths()
        print(
            "Warning: falling back to the bundled demo fixture because no normalized "
            "JSONL, ingestible datasets, or raw log file were found. Run "
            "`python -m src.ingestion.ingest_logs` first for the full LogHub pipeline.",
            file=sys.stderr,
        )
        records = load_normalized_records(DEMO_NORMALIZED_LOG_FILE)
        events, rejected = build_events_from_ingestion_records(records)
        if not events:
            raise RuntimeError("bundled demo log file did not contain any usable events")
        return events, {
            "input_mode": "bundled_demo",
            "input_path": str(DEMO_NORMALIZED_LOG_FILE.resolve()),
            "normalized_record_count": len(records),
            "event_count": len(events),
            "rejected_record_count": len(rejected),
            "rejected_examples": rejected[:20],
            "missing_dataset_files": missing_datasets,
            "note": (
                "No user-provided datasets or raw logs were found, so the pipeline "
                "fell back to the bundled demo fixture."
            ),
        }

    missing_datasets = available_dataset_paths()
    raise RuntimeError(
        "No usable input found. Checked normalized JSONL at "
        f"{normalized_path.resolve()}, raw log file at "
        f"{raw_path.resolve() if raw_path else '<none>'}, and dataset CSVs. "
        f"Missing dataset files: {missing_datasets[:4]}"
    )


def build_chunk_overview(chunk_analyses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    overview = []
    for item in chunk_analyses:
        category_counts = item.get("category_counts", {})
        top_categories = sorted(
            [{"category": key, "count": value} for key, value in category_counts.items()],
            key=lambda entry: entry["count"],
            reverse=True,
        )[:3]
        overview.append(
            {
                "chunk_id": item.get("chunk_id"),
                "line_range": [item.get("line_start"), item.get("line_end")],
                "summary": item.get("summary", ""),
                "suspicious_event_count": len(item.get("suspicious_events", [])),
                "top_categories": top_categories,
            }
        )
    return overview


def build_overview(correlation: dict[str, Any], totals: dict[str, int]) -> dict[str, Any]:
    top_categories = sorted(
        [{"category": key, "count": value} for key, value in totals.items()],
        key=lambda entry: entry["count"],
        reverse=True,
    )[:8]
    top_correlations = []
    for item in correlation.get("key_correlations", [])[:5]:
        top_correlations.append(
            {
                "pattern_id": item.get("pattern_id"),
                "type": item.get("correlation_type"),
                "confidence": item.get("confidence"),
                "related_categories": item.get("related_categories", []),
                "explanation": item.get("explanation", ""),
            }
        )
    return {
        "global_summary": correlation.get("global_summary", ""),
        "top_categories": top_categories,
        "top_correlations": top_correlations,
        "hypotheses": correlation.get("hypotheses", []),
        "timeline_highlights": correlation.get("timeline_highlights", []),
        "recommended_next_queries": correlation.get("next_queries", []),
    }


def summarize_source_agent_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    by_category = Counter()
    by_severity = Counter()
    by_agent = Counter()

    for item in results:
        by_agent.update([str(item.get("agent", "unknown"))])
        by_category.update([str(item.get("event_category", "unknown"))])
        by_severity.update([str(item.get("severity", "unknown"))])

    return {
        "total_findings": len(results),
        "by_agent": dict(sorted(by_agent.items())),
        "by_category": dict(sorted(by_category.items())),
        "by_severity": dict(sorted(by_severity.items())),
    }


def to_correlation_events(events: list[LogEvent]) -> list[CorrelationLogEvent]:
    converted: list[CorrelationLogEvent] = []
    for item in events:
        attributes: dict[str, Any] = {}
        for entity in item.entities:
            name = str(entity.get("name", "")).strip()
            value = entity.get("value")
            if name and value not in (None, ""):
                attributes[name] = value
        for key, value in item.raw_metadata.items():
            if value in (None, ""):
                continue
            if isinstance(value, (str, int, float, bool)):
                attributes[key] = value

        if item.process:
            attributes.setdefault("component", item.process)
            attributes.setdefault("process", item.process)
        if item.source:
            attributes.setdefault("dataset", item.source)

        converted.append(
            CorrelationLogEvent.from_dict(
                {
                    "event_id": item.event_id,
                    "timestamp": item.timestamp,
                    "source": item.source,
                    "level": item.severity.upper() if item.severity else "INFO",
                    "message": item.message,
                    "attributes": attributes,
                }
            )
        )
    return converted


def build_rule_correlation_summary(events: list[LogEvent]) -> dict[str, Any]:
    correlation_agent = CorrelationAgent(
        time_window_seconds=120,
        min_shared_entities=1,
        use_message_similarity_fallback=True,
        min_message_similarity=0.84,
        require_distinct_sources=False,
    )
    groups = correlation_agent.correlate(to_correlation_events(events))
    summarized_groups = []
    for group in groups:
        if len(group.events) < 2:
            continue
        sources = sorted({event.source for event in group.events})
        summarized_groups.append(
            {
                "group_id": group.group_id,
                "start_time_utc": group.start_time.isoformat(),
                "end_time_utc": group.end_time.isoformat(),
                "event_count": len(group.events),
                "sources": sources,
                "reasons": group.reasons,
                "event_ids": [event.event_id for event in group.events],
                "sample_messages": [event.message for event in group.events[:3]],
            }
        )

    summarized_groups.sort(key=lambda item: item["event_count"], reverse=True)
    return {
        "group_count": len(summarized_groups),
        "top_groups": summarized_groups[:10],
    }


def run_llm_pipeline(
    *,
    events: list[LogEvent],
    provider: str,
    models: list[str],
    api_key: str,
    region: str = "",
    chunk_size: int,
    temperature: float,
    timeout_seconds: int,
    max_retries: int,
    seed: int | None,
) -> dict[str, Any]:
    chunks = chunk_logs(events, chunk_size=chunk_size)
    retrieval_context = RetrievalContext.load() if RETRIEVAL_CONTEXT else None
    llm = create_client(
        provider=provider,
        models=models,
        api_key=api_key,
        region=region,
        temperature=temperature,
        timeout_seconds=timeout_seconds,
        max_retries=max_retries,
    )
    agent = ReasoningAgent(llm)

    chunk_analyses = []
    for chunk_id, chunk in enumerate(chunks, start=1):
        chunk_seed = None if seed is None else seed + chunk_id
        retrieval_suffix = ""
        if retrieval_context is not None:
            retrieval_suffix = retrieval_context.build_chunk_suffix(
                chunk,
                top_k=RETRIEVAL_TOP_K,
            )
        chunk_analyses.append(
            agent.analyze_chunk(
                chunk_id=chunk_id,
                entries=chunk,
                seed=chunk_seed,
                extra_user_suffix=retrieval_suffix,
            )
        )

    source_scoped = {
        "auth": analyze_auth_events(
            agent,
            events,
            chunk_id=max(1000, len(chunk_analyses) + 1),
            seed=None if seed is None else seed + 1000,
        ),
        "infra": analyze_infra_events(
            agent,
            events,
            chunk_id=max(2000, len(chunk_analyses) + 1001),
            seed=None if seed is None else seed + 2000,
        ),
    }

    correlation = agent.correlate(chunk_analyses=chunk_analyses, seed=seed)

    totals = Counter()
    for item in chunk_analyses:
        totals.update(item.get("category_counts", {}))

    totals_dict = dict(sorted(totals.items()))
    return {
        "meta": {
            "provider": provider,
            "model": llm.model,
            "model_candidates": models,
            "chunk_size": chunk_size,
            "temperature": temperature,
            "seed": seed,
            "chunk_count": len(chunks),
            "retrieval_context": retrieval_context is not None,
            "retrieval_top_k": RETRIEVAL_TOP_K if retrieval_context is not None else 0,
        },
        "overview": build_overview(correlation=correlation, totals=totals_dict),
        "inference": llm.get_inference_telemetry(),
        "chunk_overview": build_chunk_overview(chunk_analyses),
        "details": {
            "category_totals_from_chunks": totals_dict,
            "correlation_report": correlation,
            "chunk_analyses": chunk_analyses,
            "source_scoped_chunk_analyses": source_scoped,
        },
    }


def run(
    *,
    log_file: str,
    normalized_log_file: str,
    output_file: str,
    provider: str = "bedrock",
    models: list[str],
    api_key: str,
    region: str = "",
    chunk_size: int,
    max_lines: int,
    temperature: float,
    timeout_seconds: int,
    max_retries: int,
    seed: int | None,
    drop_low_signal: bool,
    ingest_if_needed: bool,
    skip_llm: bool,
    strict_llm: bool,
    provider_ready: bool | None = None,
    provider_hint: str | None = None,
) -> dict[str, Any]:
    events, input_meta = prepare_pipeline_inputs(
        log_file=log_file,
        normalized_log_file=normalized_log_file,
        max_lines=max_lines,
        drop_low_signal=drop_low_signal,
        ingest_if_needed=ingest_if_needed,
    )

    report: dict[str, Any] = {
        "meta": {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "input_mode": input_meta.get("input_mode"),
            "input_path": input_meta.get("input_path"),
            "event_count": len(events),
        },
        "input": input_meta,
        "rule_based_correlation": build_rule_correlation_summary(events),
    }

    if input_meta.get("input_mode") in {
        "normalized_jsonl",
        "ingested_datasets",
        "bundled_demo",
    }:
        normalized_path = Path(str(input_meta["input_path"]))
        normalized_logs = load_normalized_records(normalized_path)
        source_agent_results = run_source_agents(normalized_logs)
        report["source_agents"] = {
            "summary": summarize_source_agent_results(source_agent_results),
            "findings": source_agent_results,
        }
    else:
        report["source_agents"] = {
            "summary": {
                "total_findings": 0,
                "by_agent": {},
                "by_category": {},
                "by_severity": {},
            },
            "findings": [],
            "note": "Source-specific normalized-data agents were skipped for raw log input.",
        }

    if skip_llm:
        report["llm_analysis"] = {
            "status": "skipped",
            "reason": "disabled via --skip-llm",
        }
    else:
        if provider_ready is None:
            if provider == "bedrock":
                provider_ready = bedrock_configured(models[0] if models else "")
            else:
                provider_ready = bool(api_key)
        if provider_hint is None:
            if provider == "groq":
                provider_hint = "groq_demo2_key / GROQ_API_KEY"
            elif provider == "openrouter":
                provider_hint = "OPENROUTER_API_KEY"
            else:
                provider_hint = (
                    "BEDROCK_MODEL_ID or AWS_BEDROCK_MODEL_ID, region "
                    "(BEDROCK_REGION or AWS_REGION), and AWS credentials "
                    "(env or ~/.aws profile)"
                )

    if not skip_llm and not provider_ready:
        if strict_llm:
            raise RuntimeError(
                f"{provider_hint} is not set. Export it in your shell or add it to .env"
            )
        report["llm_analysis"] = {
            "status": "skipped",
            "reason": f"{provider_hint} is not configured",
        }
    elif not skip_llm:
        report["llm_analysis"] = run_llm_pipeline(
            events=events,
            provider=provider,
            models=models,
            api_key=api_key,
            region=region,
            chunk_size=chunk_size,
            temperature=temperature,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            seed=seed,
        )

    out_path = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Integrated multi-source incident analysis pipeline. Retrieval index "
            "construction is a separate step."
        ),
    )
    parser.add_argument("--log-file", default=DEFAULT_RAW_LOG_FILE)
    parser.add_argument("--normalized-log-file", default=str(OUTPUT_JSONL))
    parser.add_argument("--output-file", default="reports/report.json")
    parser.add_argument(
        "--provider",
        default=DEFAULT_PROVIDER,
        choices=["bedrock", "groq", "openrouter"],
        help="LLM provider (default selection: bedrock, then groq, then openrouter).",
    )
    parser.add_argument("--model", default=None)
    parser.add_argument("--chunk-size", type=int, default=None)
    parser.add_argument("--max-lines", type=int, default=DEFAULT_MAX_LINES)
    parser.add_argument("--temperature", type=float, default=DEFAULT_TEMPERATURE)
    parser.add_argument("--timeout-seconds", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--max-retries", type=int, default=DEFAULT_MAX_RETRIES)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--drop-low-signal", action="store_true")
    parser.add_argument(
        "--skip-ingestion",
        action="store_true",
        help="Do not auto-ingest dataset CSVs when normalized JSONL is missing.",
    )
    parser.add_argument("--skip-llm", action="store_true")
    parser.add_argument(
        "--strict-llm",
        action="store_true",
        help="Fail instead of skipping when provider credentials are missing.",
    )
    return parser


def resolve_provider_settings(
    provider: str,
    model_override: str | None,
) -> tuple[str, list[str], str, str, bool, str]:
    if provider == "bedrock":
        model = (model_override or BEDROCK_MODEL).strip()
        return (
            model,
            [model] if model else [],
            "",
            BEDROCK_REGION,
            bedrock_configured(model),
            (
                "BEDROCK_MODEL_ID or AWS_BEDROCK_MODEL_ID, region, "
                "and AWS credentials (env or ~/.aws profile)"
            ),
        )
    if provider == "groq":
        model = (model_override or GROQ_MODEL).strip()
        return (
            model,
            [model] if model else [],
            GROQ_API_KEY,
            "",
            bool(GROQ_API_KEY),
            "groq_demo2_key / GROQ_API_KEY",
        )

    model = (model_override or OPENROUTER_MODEL).strip()
    models = [model] if model and model != OPENROUTER_MODEL else OPENROUTER_MODEL_CANDIDATES
    return (
        model,
        models,
        OPENROUTER_API_KEY,
        "",
        bool(OPENROUTER_API_KEY),
        "OPENROUTER_API_KEY",
    )


if __name__ == "__main__":
    args = build_parser().parse_args()
    try:
        provider = args.provider
        model, cli_models, api_key, region, provider_ready, provider_hint = (
            resolve_provider_settings(provider, args.model)
        )

        chunk_size = args.chunk_size
        if chunk_size is None:
            chunk_size = GROQ_CHUNK_SIZE if provider == "groq" else DEFAULT_CHUNK_SIZE

        result = run(
            log_file=args.log_file,
            normalized_log_file=args.normalized_log_file,
            output_file=args.output_file,
            provider=provider,
            models=cli_models,
            api_key=api_key,
            region=region,
            chunk_size=chunk_size,
            max_lines=args.max_lines,
            temperature=args.temperature,
            timeout_seconds=args.timeout_seconds,
            max_retries=args.max_retries,
            seed=args.seed,
            drop_low_signal=args.drop_low_signal,
            ingest_if_needed=not args.skip_ingestion,
            skip_llm=args.skip_llm,
            strict_llm=args.strict_llm,
            provider_ready=provider_ready,
            provider_hint=provider_hint,
        )
        print(f"Wrote report: {args.output_file}")
        print(f"Provider: {provider} | Model: {model}")
        print(f"Input mode: {result['meta']['input_mode']}")
        print(f"Events analyzed: {result['meta']['event_count']}")
        llm_status = result.get("llm_analysis", {}).get("status", "completed")
        print(f"LLM status: {llm_status}")
        if llm_status == "skipped":
            reason = result.get("llm_analysis", {}).get("reason", "unknown")
            print(f"LLM reason: {reason}")
        if result.get("input", {}).get("note"):
            print(result["input"]["note"])
    except Exception as exc:
        print(f"Error: {exc}")
        raise SystemExit(1) from exc
