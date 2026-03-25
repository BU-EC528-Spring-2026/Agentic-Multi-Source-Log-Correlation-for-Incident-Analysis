import json
from pathlib import Path
from typing import Any

import numpy as np

from src.core.log_event import LogEvent

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
NORMALIZED_DIR = REPO_ROOT / "normalized"
OUTPUT_METADATA = NORMALIZED_DIR / "retrieval_metadata.jsonl"
OUTPUT_EMBEDDINGS = NORMALIZED_DIR / "message_embeddings.npy"
OUTPUT_FAISS = NORMALIZED_DIR / "faiss.index"


class RetrievalContext:
    def __init__(
        self,
        *,
        metadata: list[dict[str, Any]],
        embeddings: np.ndarray,
        index: Any,
        line_id_to_row: dict[str, int],
    ):
        self.metadata = metadata
        self.embeddings = embeddings
        self.index = index
        self.line_id_to_row = line_id_to_row

    @classmethod
    def load(cls) -> "RetrievalContext | None":
        if not (OUTPUT_METADATA.exists() and OUTPUT_EMBEDDINGS.exists() and OUTPUT_FAISS.exists()):
            return None

        try:
            import faiss
        except Exception:
            return None

        try:
            metadata = []
            with OUTPUT_METADATA.open("r", encoding="utf-8") as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    if not line:
                        continue
                    payload = json.loads(line)
                    if isinstance(payload, dict):
                        metadata.append(payload)

            embeddings = np.load(OUTPUT_EMBEDDINGS)
            embeddings = np.asarray(embeddings, dtype=np.float32)
            index = faiss.read_index(str(OUTPUT_FAISS))
        except Exception:
            return None

        if embeddings.ndim != 2:
            return None
        if len(metadata) != embeddings.shape[0]:
            return None
        if getattr(index, "ntotal", -1) != embeddings.shape[0]:
            return None

        line_id_to_row = {}
        for row, item in enumerate(metadata):
            line_id = str(item.get("line_id", "")).strip()
            if line_id and line_id not in line_id_to_row:
                line_id_to_row[line_id] = row

        return cls(
            metadata=metadata,
            embeddings=embeddings,
            index=index,
            line_id_to_row=line_id_to_row,
        )

    def build_chunk_suffix(
        self,
        entries: list[LogEvent],
        *,
        top_k: int,
    ) -> str:
        if top_k <= 0:
            return ""

        chunk_rows: list[int] = []
        chunk_line_ids: set[str] = set()
        for item in entries:
            line_id = str(item.raw_metadata.get("line_id", "")).strip()
            if not line_id:
                continue
            chunk_line_ids.add(line_id)
            row = self.line_id_to_row.get(line_id)
            if row is not None:
                chunk_rows.append(row)

        if not chunk_rows:
            return ""

        query = np.mean(self.embeddings[chunk_rows], axis=0, dtype=np.float32).reshape(1, -1)
        norm = float(np.linalg.norm(query))
        if norm <= 0.0:
            return ""
        query /= norm
        neighbor_count = min(len(self.metadata), top_k + len(set(chunk_rows)))
        _, indices = self.index.search(query, neighbor_count)
        chunk_row_set = set(chunk_rows)
        lines: list[str] = []
        seen_rows: set[int] = set()
        for row in indices[0]:
            row_index = int(row)
            if row_index < 0 or row_index in seen_rows or row_index in chunk_row_set:
                continue
            seen_rows.add(row_index)
            item = self.metadata[row_index]
            line_id = str(item.get("line_id", "")).strip()
            if line_id and line_id in chunk_line_ids:
                continue
            dataset = str(item.get("dataset", "")).strip()
            timestamp = str(item.get("timestamp_iso", "")).strip()
            component = str(item.get("component", "") or "").strip()
            message = str(item.get("message", "")).strip()
            if not message:
                continue
            lines.append(
                f"- dataset={dataset} timestamp={timestamp} component={component} message={message}"
            )
            if len(lines) >= top_k:
                break

        if not lines:
            return ""
        return "Related lines (semantic retrieval):\n" + "\n".join(lines)
