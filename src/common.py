# Shared logging and JSONL loading for pipeline scripts.

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"


def setup_logging(level: int = logging.INFO) -> None:
    """Configure root logger with pipeline-standard format."""
    logging.basicConfig(
        level=level,
        format=LOG_FORMAT,
        datefmt=LOG_DATEFMT,
        stream=sys.stdout,
    )


def load_logs(path: Path) -> list[dict[str, Any]]:
    """Load normalized logs from a JSONL file. Returns list of log records."""
    log = logging.getLogger(__name__)
    records: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    log.info("Loaded %d logs from %s", len(records), path)
    return records
