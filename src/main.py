import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from src.agents.log_analyzer import ReasoningAgent
from src.core.client import create_client
from src.core.config import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_MAX_LINES,
    DEFAULT_MAX_RETRIES,
    DEFAULT_TEMPERATURE,
    DEFAULT_TIMEOUT_SECONDS,
    OPENROUTER_API_KEY,
    OPENROUTER_MODEL,
)
from src.core.log_parser import ParsedLog, chunk_logs, parse_logs

LOW_SIGNAL_MARKERS = (
    "scheduler_evaluate_activity told me to run this job",
    "location icon should now be in state",
)


def load_log_file(path: str, max_lines: int) -> list[str]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"log file not found: {p}")
    with p.open("r", encoding="utf-8", errors="replace") as f:
        lines = [line for _, line in zip(range(max_lines), f)]
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


def build_chunk_overview(chunk_analyses: list[dict]) -> list[dict]:
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


def build_overview(correlation: dict, totals: dict[str, int]) -> dict:
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


def run(
    *,
    log_file: str,
    output_file: str,
    model: str,
    api_key: str,
    chunk_size: int,
    max_lines: int,
    temperature: float,
    timeout_seconds: int,
    max_retries: int,
    seed: int | None,
    drop_low_signal: bool,
) -> dict:
    if not api_key:
        raise RuntimeError(
            "OPENROUTER_API_KEY is not set. "
            "Export it in your shell or add it to .env"
        )

    raw_lines = load_log_file(log_file, max_lines=max_lines)
    parsed_lines, skipped_lines = parse_logs(raw_lines)
    parsed_before_filter_count = len(parsed_lines)
    parsed_lines, dropped_low_signal_count = drop_low_signal_lines(
        parsed_lines,
        enabled=drop_low_signal,
    )
    if not parsed_lines:
        raise RuntimeError("No parsable log lines found in input file")

    chunks = chunk_logs(parsed_lines, chunk_size=chunk_size)
    llm = create_client(
        model=model,
        api_key=api_key,
        temperature=temperature,
        timeout_seconds=timeout_seconds,
        max_retries=max_retries,
    )
    agent = ReasoningAgent(llm)

    chunk_analyses = []
    for chunk_id, chunk in enumerate(chunks, start=1):
        chunk_seed = None if seed is None else seed + chunk_id
        chunk_analyses.append(
            agent.analyze_chunk(
                chunk_id=chunk_id,
                entries=chunk,
                seed=chunk_seed,
            )
        )

    correlation = agent.correlate(chunk_analyses=chunk_analyses, seed=seed)

    totals = Counter()
    for item in chunk_analyses:
        totals.update(item.get("category_counts", {}))

    totals_dict = dict(sorted(totals.items()))
    overview = build_overview(correlation=correlation, totals=totals_dict)

    report = {
        "meta": {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "provider": "openrouter",
            "model": model,
            "log_file": str(Path(log_file).resolve()),
            "max_lines": max_lines,
            "chunk_size": chunk_size,
            "temperature": temperature,
            "seed": seed,
            "raw_line_count": len(raw_lines),
            "parsed_line_count": parsed_before_filter_count,
            "parsed_after_filter_count": len(parsed_lines),
            "skipped_line_count": len(skipped_lines),
            "dropped_low_signal_count": dropped_low_signal_count,
            "chunk_count": len(chunks),
            "low_signal_filter_enabled": drop_low_signal,
        },
        "parser": {
            "skip_rate": round(len(skipped_lines) / max(1, len(raw_lines)), 4),
            "skipped_examples": skipped_lines[:20],
        },
        "overview": overview,
        "chunk_overview": build_chunk_overview(chunk_analyses),
        "details": {
            "category_totals_from_chunks": totals_dict,
            "correlation_report": correlation,
            "chunk_analyses": chunk_analyses,
        },
    }

    out_path = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="LLM log categorization + correlation via OpenRouter",
    )
    parser.add_argument("--log-file", default="loghub/Mac/Mac_2k.log")
    parser.add_argument("--output-file", default="reports/report.json")
    parser.add_argument("--model", default=OPENROUTER_MODEL)
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE)
    parser.add_argument("--max-lines", type=int, default=DEFAULT_MAX_LINES)
    parser.add_argument("--temperature", type=float, default=DEFAULT_TEMPERATURE)
    parser.add_argument("--timeout-seconds", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--max-retries", type=int, default=DEFAULT_MAX_RETRIES)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--drop-low-signal", action="store_true")
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    try:
        result = run(
            log_file=args.log_file,
            output_file=args.output_file,
            model=args.model,
            api_key=OPENROUTER_API_KEY,
            chunk_size=args.chunk_size,
            max_lines=args.max_lines,
            temperature=args.temperature,
            timeout_seconds=args.timeout_seconds,
            max_retries=args.max_retries,
            seed=args.seed,
            drop_low_signal=args.drop_low_signal,
        )
        print(f"Wrote report: {args.output_file}")
        print(f"Summary: {result['overview']['global_summary']}")
    except Exception as exc:
        print(f"Error: {exc}")
        raise SystemExit(1) from exc
