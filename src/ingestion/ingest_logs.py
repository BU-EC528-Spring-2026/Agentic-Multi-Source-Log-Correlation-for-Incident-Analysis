#!/usr/bin/env python3
# Pipeline step 1: Ingest structured CSVs → normalized unified_logs.jsonl and ingestion_summary.json.

"""
LogHub multi-source incident reasoning — data ingestion.

Loads structured CSVs from OpenStack, OpenSSH, Linux, and Apache datasets,
normalizes timestamps to ISO8601 and epoch milliseconds, validates records,
and writes unified JSONL plus an ingestion summary metadata file.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

import pandas as pd

from src.common import setup_logging

# Repo root (parent of src/)
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
OUTPUT_DIR = REPO_ROOT / "normalized"
OUTPUT_JSONL = OUTPUT_DIR / "unified_logs.jsonl"
OUTPUT_SUMMARY = OUTPUT_DIR / "ingestion_summary.json"

# External data root: LOG_DATA_ROOT env (default "data"), relative to repo or absolute
_LOG_DATA_ROOT = os.environ.get("LOG_DATA_ROOT", "data")
DATA_ROOT = Path(_LOG_DATA_ROOT) if Path(_LOG_DATA_ROOT).is_absolute() else REPO_ROOT / _LOG_DATA_ROOT
LOGHUB_DATA_ROOT = DATA_ROOT / "loghub"

DATASET_FILENAMES: dict[str, tuple[str, str]] = {
    "openstack": ("OpenStack", "OpenStack_2k.log_structured.csv"),
    "openssh": ("OpenSSH", "OpenSSH_2k.log_structured.csv"),
    "linux": ("Linux", "Linux_2k.log_structured.csv"),
    "apache": ("Apache", "Apache_2k.log_structured.csv"),
}


def resolve_dataset_paths() -> dict[str, Path]:
    """
    Support both of these layouts:
    - data/OpenStack/OpenStack_2k.log_structured.csv
    - data/loghub/OpenStack/OpenStack_2k.log_structured.csv
    """
    resolved: dict[str, Path] = {}
    for dataset, (directory, filename) in DATASET_FILENAMES.items():
        candidates = (
            DATA_ROOT / directory / filename,
            LOGHUB_DATA_ROOT / directory / filename,
        )
        existing = next((path for path in candidates if path.exists()), candidates[0])
        resolved[dataset] = existing
    return resolved


DATASET_PATHS: dict[str, Path] = resolve_dataset_paths()

REQUIRED_FIELDS: tuple[str, ...] = (
    "line_id",
    "dataset",
    "timestamp_iso",
    "timestamp_epoch",
    "event_id",
    "event_template",
    "message",
    "source_file",
)

# When EventTemplate is missing or empty in source CSV, use this placeholder
# instead of failing. Enables downstream reasoning to treat unknown templates
# explicitly.
EVENT_TEMPLATE_PLACEHOLDER: str = "unknown_template"

SCHEMA_FIELDS: list[dict[str, str]] = [
    {"name": "line_id", "type": "string", "required": "true"},
    {"name": "dataset", "type": "string", "required": "true"},
    {"name": "timestamp_iso", "type": "string", "required": "true"},
    {"name": "timestamp_epoch", "type": "integer", "required": "true"},
    {"name": "level", "type": "string | null", "required": "false"},
    {"name": "component", "type": "string | null", "required": "false"},
    {"name": "pid", "type": "string | null", "required": "false"},
    {"name": "event_id", "type": "string", "required": "true"},
    {"name": "event_template", "type": "string", "required": "true"},
    {"name": "message", "type": "string", "required": "true"},
    {"name": "source_file", "type": "string", "required": "true"},
]


# -----------------------------------------------------------------------------
# Timestamp parsing (per-dataset)
# -----------------------------------------------------------------------------


def parse_openstack(df: pd.DataFrame) -> pd.DataFrame:
    """Parse OpenStack CSV: combine Date + Time into `_ts`; coerce malformed values."""
    df = df.copy()
    ts_str = df["Date"].astype(str) + " " + df["Time"].astype(str)
    df["_ts"] = pd.to_datetime(ts_str, format="%Y-%m-%d %H:%M:%S.%f", errors="coerce")
    mask = df["_ts"].isna()
    if mask.any():
        df.loc[mask, "_ts"] = pd.to_datetime(
            ts_str[mask], format="%Y-%m-%d %H:%M:%S", errors="coerce"
        )
    return df


def parse_openssh(df: pd.DataFrame, year: int = 2015) -> pd.DataFrame:
    """Parse OpenSSH CSV: Date (month) + Day + Time with assumed year → `_ts`."""
    df = df.copy()
    ts_str = (
        f"{year} "
        + df["Date"].astype(str)
        + " "
        + df["Day"].astype(str)
        + " "
        + df["Time"].astype(str)
    )
    df["_ts"] = pd.to_datetime(ts_str, format="%Y %b %d %H:%M:%S", errors="coerce")
    return df


def parse_linux(df: pd.DataFrame, year: int = 2015) -> pd.DataFrame:
    """Parse Linux CSV: Month + Date + Time with assumed year → `_ts`."""
    df = df.copy()
    ts_str = (
        f"{year} "
        + df["Month"].astype(str)
        + " "
        + df["Date"].astype(str)
        + " "
        + df["Time"].astype(str)
    )
    df["_ts"] = pd.to_datetime(ts_str, format="%Y %b %d %H:%M:%S", errors="coerce")
    return df


def parse_apache(df: pd.DataFrame) -> pd.DataFrame:
    """Parse Apache CSV: Time column is full datetime string → `_ts`."""
    df = df.copy()
    df["_ts"] = pd.to_datetime(
        df["Time"].astype(str), format="%a %b %d %H:%M:%S %Y", errors="coerce"
    )
    return df


def add_iso_and_epoch_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add timestamp_iso (ISO8601 with Z suffix) and timestamp_epoch (ms) to a
    DataFrame that has a `_ts` datetime column.

    Invalid timestamps (NaT) are left as pd.NA / NaN; only valid _ts rows are
    converted. Callers must skip rows where _ts is NaT before using
    timestamp_epoch (e.g. int()).
    """
    df = df.copy()
    valid = df["_ts"].notna()
    df["timestamp_iso"] = pd.NA
    df["timestamp_epoch"] = float("nan")
    if valid.any():
        ts_valid = df.loc[valid, "_ts"]
        iso = (
            ts_valid.dt.strftime("%Y-%m-%dT%H:%M:%S.%f")
            .str.rstrip("0")
            .str.rstrip(".")
            + "Z"
        )
        df.loc[valid, "timestamp_iso"] = iso.values
        df.loc[valid, "timestamp_epoch"] = (
            ts_valid.astype("int64") // 1_000_000
        ).astype(int)
    return df


# -----------------------------------------------------------------------------
# Normalized record building and validation
# -----------------------------------------------------------------------------


def normalize_log(
    *,
    line_id: str,
    dataset: str,
    timestamp_iso: str,
    timestamp_epoch: int,
    event_id: str,
    event_template: str,
    message: str,
    source_file: str,
    level: str | None = None,
    component: str | None = None,
    pid: str | None = None,
) -> dict[str, Any]:
    """Build one normalized log record (unified schema). Keys in canonical order."""
    return {
        "line_id": line_id,
        "dataset": dataset,
        "timestamp_iso": timestamp_iso,
        "timestamp_epoch": timestamp_epoch,
        "level": level,
        "component": component,
        "pid": pid,
        "event_id": event_id,
        "event_template": event_template,
        "message": message,
        "source_file": source_file,
    }


def validate_record(record: dict[str, Any], index: int) -> None:
    """
    Ensure the record has all required fields and meets validation policy:
    - message may be empty; event_id and event_template must be non-empty.
    - timestamp_epoch must be an int.
    Raises ValueError with details on first failure.
    """
    missing: list[str] = []
    empty: list[str] = []
    for field in REQUIRED_FIELDS:
        if field not in record:
            missing.append(field)
            continue
        val = record[field]
        if val is None:
            empty.append(field)
        elif field == "message":
            # message may be empty
            pass
        elif field != "timestamp_epoch" and isinstance(val, str) and not val.strip():
            empty.append(field)
    if missing:
        raise ValueError(
            f"Record at index {index} missing required fields: {missing}. "
            f"Record keys: {list(record.keys())}"
        )
    if empty:
        raise ValueError(
            f"Record at index {index} has empty/null required fields: {empty}. "
            f"Record line_id={record.get('line_id')!r}"
        )
    if not isinstance(record["timestamp_epoch"], int):
        raise ValueError(
            f"Record at index {index} timestamp_epoch must be int, got {type(record['timestamp_epoch']).__name__}"
        )


def validate_all_records(records: list[dict[str, Any]]) -> None:
    """Validate every record; fail loudly on first invalid one."""
    for i, rec in enumerate(records):
        validate_record(rec, i)


# -----------------------------------------------------------------------------
# Dataset loaders (load CSV, parse timestamps, emit normalized records)
# -----------------------------------------------------------------------------


def _safe_str(val: Any) -> str:
    """Convert value to string for output; empty or NaN -> empty string."""
    if val is None or (isinstance(val, float) and pd.isna(val)):
        return ""
    return str(val).strip()


def _safe_int_str(val: Any) -> str | None:
    """Convert to string if numeric and non-empty; else None."""
    if val is None or (isinstance(val, float) and pd.isna(val)):
        return None
    s = str(val).strip()
    if not s:
        return None
    try:
        return str(int(float(s)))
    except (ValueError, TypeError):
        return None


def load_and_normalize_openstack(path: Path) -> list[dict[str, Any]]:
    """Load OpenStack structured CSV and return list of normalized records."""
    log = logging.getLogger(__name__)
    log.info("Loading OpenStack dataset from %s", path)
    df = pd.read_csv(path)
    df = parse_openstack(df)
    df = add_iso_and_epoch_columns(df)
    records: list[dict[str, Any]] = []
    for _, row in df.iterrows():
        if pd.isna(row["_ts"]):
            continue
        rec = normalize_log(
            line_id=f"openstack_{row['LineId']}",
            dataset="openstack",
            timestamp_iso=row["timestamp_iso"],
            timestamp_epoch=int(row["timestamp_epoch"]),
            event_id=_safe_str(row["EventId"]) or "unknown",
            event_template=_safe_str(row["EventTemplate"]) or EVENT_TEMPLATE_PLACEHOLDER,
            message=_safe_str(row["Content"]),
            source_file=_safe_str(row.get("Logrecord")) or "OpenStack_2k.log",
            level=_safe_str(row["Level"]) or None,
            component=_safe_str(row["Component"]) or None,
            pid=_safe_int_str(row.get("Pid")),
        )
        records.append(rec)
    log.info("OpenStack: %d records", len(records))
    return records


def load_and_normalize_openssh(path: Path, year: int = 2015) -> list[dict[str, Any]]:
    """Load OpenSSH structured CSV and return list of normalized records."""
    log = logging.getLogger(__name__)
    log.info("Loading OpenSSH dataset from %s", path)
    df = pd.read_csv(path)
    df = parse_openssh(df, year=year)
    df = add_iso_and_epoch_columns(df)
    records: list[dict[str, Any]] = []
    for _, row in df.iterrows():
        if pd.isna(row["_ts"]):
            continue
        rec = normalize_log(
            line_id=f"openssh_{row['LineId']}",
            dataset="openssh",
            timestamp_iso=row["timestamp_iso"],
            timestamp_epoch=int(row["timestamp_epoch"]),
            event_id=_safe_str(row["EventId"]) or "unknown",
            event_template=_safe_str(row["EventTemplate"]) or EVENT_TEMPLATE_PLACEHOLDER,
            message=_safe_str(row["Content"]),
            source_file="OpenSSH_2k.log",
            level=None,
            component=_safe_str(row["Component"]) or None,
            pid=_safe_int_str(row.get("Pid")),
        )
        records.append(rec)
    log.info("OpenSSH: %d records", len(records))
    return records


def load_and_normalize_linux(path: Path, year: int = 2015) -> list[dict[str, Any]]:
    """Load Linux structured CSV and return list of normalized records."""
    log = logging.getLogger(__name__)
    log.info("Loading Linux dataset from %s", path)
    df = pd.read_csv(path)
    df = parse_linux(df, year=year)
    df = add_iso_and_epoch_columns(df)
    records: list[dict[str, Any]] = []
    for _, row in df.iterrows():
        if pd.isna(row["_ts"]):
            continue
        pid_val = row.get("PID", row.get("Pid"))
        rec = normalize_log(
            line_id=f"linux_{row['LineId']}",
            dataset="linux",
            timestamp_iso=row["timestamp_iso"],
            timestamp_epoch=int(row["timestamp_epoch"]),
            event_id=_safe_str(row["EventId"]) or "unknown",
            event_template=_safe_str(row["EventTemplate"]) or EVENT_TEMPLATE_PLACEHOLDER,
            message=_safe_str(row["Content"]),
            source_file="Linux_2k.log",
            level=_safe_str(row["Level"]) or None,
            component=_safe_str(row["Component"]) or None,
            pid=_safe_int_str(pid_val),
        )
        records.append(rec)
    log.info("Linux: %d records", len(records))
    return records


def load_and_normalize_apache(path: Path) -> list[dict[str, Any]]:
    """Load Apache structured CSV and return list of normalized records."""
    log = logging.getLogger(__name__)
    log.info("Loading Apache dataset from %s", path)
    df = pd.read_csv(path)
    df = parse_apache(df)
    df = add_iso_and_epoch_columns(df)
    records: list[dict[str, Any]] = []
    for _, row in df.iterrows():
        if pd.isna(row["_ts"]):
            continue
        rec = normalize_log(
            line_id=f"apache_{row['LineId']}",
            dataset="apache",
            timestamp_iso=row["timestamp_iso"],
            timestamp_epoch=int(row["timestamp_epoch"]),
            event_id=_safe_str(row["EventId"]) or "unknown",
            event_template=_safe_str(row["EventTemplate"]) or EVENT_TEMPLATE_PLACEHOLDER,
            message=_safe_str(row["Content"]),
            source_file="Apache_2k.log",
            level=_safe_str(row["Level"]) or None,
            component="apache",
            pid=None,
        )
        records.append(rec)
    log.info("Apache: %d records", len(records))
    return records


def load_all_datasets(datasets: dict[str, Path]) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    """
    Load and normalize all configured datasets.

    Returns (all_records, per_dataset_records). Raises FileNotFoundError
    if any path is missing.
    """
    all_records: list[dict[str, Any]] = []
    per_dataset: dict[str, list[dict[str, Any]]] = {}
    loaders = {
        "openstack": load_and_normalize_openstack,
        "openssh": load_and_normalize_openssh,
        "linux": load_and_normalize_linux,
        "apache": load_and_normalize_apache,
    }
    for name, path in datasets.items():
        if not path.exists():
            raise FileNotFoundError(f"Dataset not found: {path}")
        loader = loaders[name]
        if name in ("openssh", "linux"):
            records = loader(path, year=2015)
        else:
            records = loader(path)
        per_dataset[name] = records
        all_records.extend(records)
    return all_records, per_dataset


# -----------------------------------------------------------------------------
# Summary and output
# -----------------------------------------------------------------------------


def compute_summary(
    all_records: list[dict[str, Any]],
    per_dataset: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    """Compute ingestion summary: total, per-dataset counts, time range, schema."""
    total = len(all_records)
    logs_per_dataset = {name: len(recs) for name, recs in per_dataset.items()}
    earliest_timestamp: str | None = None
    latest_timestamp: str | None = None
    if all_records:
        epochs = [r["timestamp_epoch"] for r in all_records]
        earliest_ms = min(epochs)
        latest_ms = max(epochs)
        earliest_timestamp = next(
            r["timestamp_iso"] for r in all_records if r["timestamp_epoch"] == earliest_ms
        )
        latest_timestamp = next(
            r["timestamp_iso"] for r in all_records if r["timestamp_epoch"] == latest_ms
        )
    return {
        "total_logs": total,
        "logs_per_dataset": logs_per_dataset,
        "earliest_timestamp": earliest_timestamp,
        "latest_timestamp": latest_timestamp,
        "schema_fields": SCHEMA_FIELDS,
    }


def write_jsonl(records: list[dict[str, Any]], path: Path) -> None:
    """Write records as one JSON object per line (JSONL)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    logging.getLogger(__name__).info("Wrote %d records to %s", len(records), path)


def write_summary_json(summary: dict[str, Any], path: Path) -> None:
    """Write ingestion summary to a JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    logging.getLogger(__name__).info("Wrote summary to %s", path)


def main() -> None:
    """Run the full ingestion pipeline: load, validate, write JSONL and summary."""
    setup_logging()
    log = logging.getLogger(__name__)

    all_records, per_dataset = load_all_datasets(DATASET_PATHS)
    validate_all_records(all_records)
    all_records.sort(key=lambda r: r["timestamp_epoch"])

    write_jsonl(all_records, OUTPUT_JSONL)
    summary = compute_summary(all_records, per_dataset)
    write_summary_json(summary, OUTPUT_SUMMARY)

    log.info("Ingestion complete. Total logs: %d", summary["total_logs"])
    for name, count in summary["logs_per_dataset"].items():
        log.info("  %s: %d", name, count)
    log.info("Earliest timestamp: %s", summary["earliest_timestamp"])
    log.info("Latest timestamp: %s", summary["latest_timestamp"])
    log.info("Output: %s", OUTPUT_JSONL)
    log.info("Summary: %s", OUTPUT_SUMMARY)


if __name__ == "__main__":
    main()
