import json
import re
from pathlib import Path
from typing import Any

import numpy as np

from src.core.log_event import LogEvent

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
NORMALIZED_DIR = REPO_ROOT / "normalized"
OUTPUT_METADATA = NORMALIZED_DIR / "retrieval_metadata.jsonl"
OUTPUT_EMBEDDINGS = NORMALIZED_DIR / "message_embeddings.npy"
OUTPUT_FAISS = NORMALIZED_DIR / "faiss.index"
TOKEN_RE = re.compile(r"[a-z0-9_./:-]+")


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
        self._row_token_sets: list[set[str]] = []
        self._query_cache: dict[tuple[int, ...], np.ndarray] = {}
        self._build_row_token_sets()

    def _build_row_token_sets(self) -> None:
        for item in self.metadata:
            terms = item.get("retrieval_terms")
            if isinstance(terms, list):
                token_set = {str(t).strip().lower() for t in terms if str(t).strip()}
            else:
                merged = " ".join(
                    [
                        str(item.get("message") or ""),
                        str(item.get("event_template") or ""),
                        str(item.get("component") or ""),
                    ]
                ).lower()
                token_set = set(TOKEN_RE.findall(merged))
            self._row_token_sets.append(token_set)

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

        cache_key = tuple(sorted(set(chunk_rows)))
        cached_query = self._query_cache.get(cache_key)
        if cached_query is None:
            query = np.mean(self.embeddings[list(cache_key)], axis=0, dtype=np.float32).reshape(
                1, -1
            )
            self._query_cache[cache_key] = query
        else:
            query = cached_query.copy()
        norm = float(np.linalg.norm(query))
        if norm <= 0.0:
            return ""
        query /= norm
        chunk_tokens: set[str] = set()
        for row in set(chunk_rows):
            chunk_tokens.update(self._row_token_sets[row])

        neighbor_count = min(len(self.metadata), max(top_k * 5, top_k + len(set(chunk_rows))))
        scores, indices = self.index.search(query, neighbor_count)
        chunk_row_set = set(chunk_rows)
        ranked: list[tuple[float, int, dict[str, Any]]] = []
        seen_rows: set[int] = set()
        for score_raw, row in zip(scores[0], indices[0]):
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
            lexical_overlap = 0.0
            row_tokens = self._row_token_sets[row_index]
            if chunk_tokens and row_tokens:
                lexical_overlap = len(chunk_tokens.intersection(row_tokens)) / max(
                    1, len(chunk_tokens)
                )
            semantic_score = float(score_raw)
            blended = 0.82 * semantic_score + 0.18 * lexical_overlap
            ranked.append((blended, row_index, item))

        if not ranked:
            return ""
        ranked.sort(key=lambda entry: entry[0], reverse=True)

        lines: list[str] = []
        used_datasets: dict[str, int] = {}
        for blended, _, item in ranked:
            dataset = str(item.get("dataset", "")).strip()
            if dataset and used_datasets.get(dataset, 0) >= 2:
                continue
            timestamp = str(item.get("timestamp_iso", "")).strip()
            component = str(item.get("component", "") or "").strip()
            message = str(item.get("message", "")).strip()
            if not message:
                continue
            lines.append(
                f"- score={blended:.4f} dataset={dataset} timestamp={timestamp} component={component} message={message}"
            )
            if dataset:
                used_datasets[dataset] = used_datasets.get(dataset, 0) + 1
            if len(lines) >= top_k:
                break

        if not lines:
            return ""
        return "Related lines (hybrid semantic+lexical retrieval):\n" + "\n".join(lines)
