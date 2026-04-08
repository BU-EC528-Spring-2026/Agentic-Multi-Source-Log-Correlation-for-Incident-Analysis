#!/usr/bin/env python3
# Pipeline step 2: Build retrieval index over unified logs (metadata, embeddings, FAISS).

"""
Build the first retrieval layer on top of normalized/unified_logs.jsonl.

Creates retrieval_metadata.jsonl, message_embeddings.npy, faiss.index.
Provides keyword/filter retrieval, semantic search, and hybrid search.
Requires: sentence-transformers, faiss-cpu (or faiss), numpy
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

import numpy as np

from src.common import load_logs, setup_logging

# Paths relative to repo root
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
NORMALIZED_DIR = REPO_ROOT / "normalized"
UNIFIED_LOGS = NORMALIZED_DIR / "unified_logs.jsonl"
OUTPUT_METADATA = NORMALIZED_DIR / "retrieval_metadata.jsonl"
OUTPUT_EMBEDDINGS = NORMALIZED_DIR / "message_embeddings.npy"
OUTPUT_FAISS = NORMALIZED_DIR / "faiss.index"

METADATA_KEYS: tuple[str, ...] = (
    "line_id",
    "dataset",
    "timestamp_iso",
    "timestamp_epoch",
    "level",
    "component",
    "event_id",
    "event_template",
    "message",
    "source_file",
)

EMBEDDING_MODEL = "all-MiniLM-L6-v2"
TOKEN_RE = re.compile(r"[a-z0-9_./:-]+")


# -----------------------------------------------------------------------------
# Metadata
# -----------------------------------------------------------------------------


def build_metadata(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build metadata store: one dict per log with METADATA_KEYS only."""
    metadata: list[dict[str, Any]] = []
    for rec in logs:
        meta = {k: rec.get(k) for k in METADATA_KEYS}
        msg = str(meta.get("message") or "").lower()
        template = str(meta.get("event_template") or "").lower()
        comp = str(meta.get("component") or "").lower()
        merged = f"{msg} {template} {comp}".strip()
        meta["retrieval_terms"] = sorted(set(TOKEN_RE.findall(merged)))
        metadata.append(meta)
    logging.getLogger(__name__).info("Built metadata for %d logs", len(metadata))
    return metadata


def validate_metadata(metadata: list[dict[str, Any]]) -> None:
    """
    Validate metadata before indexing. Each record must have:
    - line_id (present)
    - dataset (present)
    - timestamp_epoch (present and int)
    - message (present)
    Raises ValueError with index and field details on first invalid record.
    """
    for i, meta in enumerate(metadata):
        if "line_id" not in meta or meta.get("line_id") is None:
            raise ValueError(
                f"Metadata record at index {i} missing required field 'line_id'. "
                f"Keys: {list(meta.keys())}"
            )
        if "dataset" not in meta or meta.get("dataset") is None:
            raise ValueError(
                f"Metadata record at index {i} missing required field 'dataset'. "
                f"line_id={meta.get('line_id')!r}"
            )
        if "message" not in meta:
            raise ValueError(
                f"Metadata record at index {i} missing required field 'message'. "
                f"line_id={meta.get('line_id')!r}"
            )
        te = meta.get("timestamp_epoch")
        if te is None:
            raise ValueError(
                f"Metadata record at index {i} missing required field 'timestamp_epoch'. "
                f"line_id={meta.get('line_id')!r}"
            )
        if not isinstance(te, int):
            raise ValueError(
                f"Metadata record at index {i} 'timestamp_epoch' must be int, got {type(te).__name__}. "
                f"line_id={meta.get('line_id')!r}"
            )
    logging.getLogger(__name__).info("Validated %d metadata records", len(metadata))


# -----------------------------------------------------------------------------
# Keyword / filter retrieval
# -----------------------------------------------------------------------------


def keyword_filter(
    metadata: list[dict[str, Any]],
    *,
    dataset: str | None = None,
    component: str | None = None,
    level: str | None = None,
    event_template: str | None = None,
    ts_min: int | None = None,
    ts_max: int | None = None,
    message_substring: str | None = None,
) -> list[int]:
    """
    Return indices of metadata records matching all given filters.

    Optional filters: dataset, component, level, event_template (exact match),
    ts_min/ts_max (timestamp_epoch range, inclusive), message_substring (case-insensitive).
    """
    indices: list[int] = []
    for i, meta in enumerate(metadata):
        if dataset is not None and meta.get("dataset") != dataset:
            continue
        if component is not None and meta.get("component") != component:
            continue
        if level is not None and meta.get("level") != level:
            continue
        if event_template is not None and meta.get("event_template") != event_template:
            continue
        ts = meta.get("timestamp_epoch")
        if ts_min is not None and (ts is None or ts < ts_min):
            continue
        if ts_max is not None and (ts is None or ts > ts_max):
            continue
        if message_substring is not None:
            msg = (meta.get("message") or "").lower()
            if message_substring.lower() not in msg:
                continue
        indices.append(i)
    return indices


# -----------------------------------------------------------------------------
# Embeddings and FAISS
# -----------------------------------------------------------------------------


def build_embeddings(
    metadata: list[dict[str, Any]],
    model: Any,
) -> np.ndarray:
    """
    Embed each log message using the provided SentenceTransformer model.
    Returns array of shape (n_logs, embedding_dim), float32.
    """
    log = logging.getLogger(__name__)
    messages = [meta.get("message") or "" for meta in metadata]
    log.info("Encoding %d messages", len(messages))
    embeddings = model.encode(messages, show_progress_bar=True, convert_to_numpy=True)
    assert isinstance(embeddings, np.ndarray)
    embeddings = np.asarray(embeddings, dtype=np.float32)
    log.info("Embeddings shape: %s", embeddings.shape)
    return embeddings


def build_faiss_index(embeddings: np.ndarray) -> Any:
    """
    Build a FAISS IndexFlatIP (inner product = cosine when vectors are normalized).
    Embeddings are L2-normalized so that inner product equals cosine similarity.
    """
    log = logging.getLogger(__name__)
    import faiss

    d = embeddings.shape[1]
    index = faiss.IndexFlatIP(d)
    # Normalize for cosine similarity via inner product
    faiss.normalize_L2(embeddings)
    index.add(embeddings)
    log.info("FAISS index built: %d vectors, dim %d", index.ntotal, d)
    return index


def semantic_search(
    query: str,
    metadata: list[dict[str, Any]],
    embeddings: np.ndarray,
    index: Any,
    model: Any,
    top_k: int = 5,
) -> list[tuple[int, float, dict[str, Any]]]:
    """
    Run semantic search: embed query with the provided model, search FAISS,
    return top_k (index, score, meta). Expects index to be L2-normalized (cosine = inner product).
    """
    q = model.encode([query], convert_to_numpy=True, normalize_embeddings=True)
    q = np.asarray(q, dtype=np.float32)
    scores, indices = index.search(q, min(top_k, len(metadata)))
    results: list[tuple[int, float, dict[str, Any]]] = []
    for idx, score in zip(indices[0], scores[0]):
        if idx < 0:
            continue
        results.append((int(idx), float(score), metadata[idx]))
    return results


def hybrid_search(
    query: str,
    metadata: list[dict[str, Any]],
    embeddings: np.ndarray,
    model: Any,
    *,
    dataset: str | None = None,
    component: str | None = None,
    level: str | None = None,
    event_template: str | None = None,
    ts_min: int | None = None,
    ts_max: int | None = None,
    message_substring: str | None = None,
    top_k: int = 10,
) -> list[dict[str, Any]]:
    """
    Hybrid search: filter by keyword/filters to get candidates, then rank by
    cosine similarity of query embedding vs candidate message embeddings.
    Returns evidence-ready dicts: line_id, dataset, timestamp_iso, component,
    event_template, message, score.
    """
    import faiss

    candidate_indices = keyword_filter(
        metadata,
        dataset=dataset,
        component=component,
        level=level,
        event_template=event_template,
        ts_min=ts_min,
        ts_max=ts_max,
        message_substring=message_substring,
    )
    if not candidate_indices:
        return []

    q = model.encode([query], convert_to_numpy=True, normalize_embeddings=True)
    q = np.asarray(q, dtype=np.float32)
    candidate_emb = np.take(embeddings, candidate_indices, axis=0).astype(np.float32).copy()
    faiss.normalize_L2(candidate_emb)
    scores = (q @ candidate_emb.T).flatten()
    top_positions = np.argsort(scores)[::-1][:top_k]

    results: list[dict[str, Any]] = []
    for pos in top_positions:
        idx = candidate_indices[pos]
        meta = metadata[idx]
        results.append({
            "line_id": meta["line_id"],
            "dataset": meta["dataset"],
            "timestamp_iso": meta["timestamp_iso"],
            "component": meta.get("component"),
            "event_template": meta.get("event_template"),
            "message": meta.get("message"),
            "score": float(scores[pos]),
        })
    return results


# -----------------------------------------------------------------------------
# Save / load
# -----------------------------------------------------------------------------


def save_metadata(metadata: list[dict[str, Any]], path: Path) -> None:
    """Write metadata as JSONL."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for meta in metadata:
            f.write(json.dumps(meta, ensure_ascii=False) + "\n")
    logging.getLogger(__name__).info("Wrote metadata to %s", path)


def save_embeddings(embeddings: np.ndarray, path: Path) -> None:
    """Write embeddings as .npy."""
    path.parent.mkdir(parents=True, exist_ok=True)
    np.save(path, embeddings)
    logging.getLogger(__name__).info("Wrote embeddings to %s (%s)", path, embeddings.shape)


def save_faiss_index(index: Any, path: Path) -> None:
    """Write FAISS index to disk."""
    import faiss

    path.parent.mkdir(parents=True, exist_ok=True)
    faiss.write_index(index, str(path))
    logging.getLogger(__name__).info("Wrote FAISS index to %s", path)


# -----------------------------------------------------------------------------
# Main and CLI test
# -----------------------------------------------------------------------------


def _print_top5(label: str, results: list[dict[str, Any]]) -> None:
    """Print up to 5 results (evidence-ready or (idx, score, meta) tuples)."""
    if not results:
        print("  (no results)")
        return
    for rank, item in enumerate(results[:5], 1):
        if "score" in item and "line_id" in item:
            meta = item
            score = meta["score"]
        else:
            idx, score, meta = item
        msg = (meta.get("message") or "")[:80]
        if len(meta.get("message") or "") > 80:
            msg += "..."
        print(f"  {rank}. line_id={meta['line_id']!r} dataset={meta['dataset']!r} "
              f"timestamp_iso={meta['timestamp_iso']!r} component={meta.get('component')!r} score={score:.4f}")
        print(f"      message={msg!r}")


def main() -> None:
    """Build retrieval index and run CLI tests (semantic + hybrid)."""
    setup_logging()
    log = logging.getLogger(__name__)

    from sentence_transformers import SentenceTransformer

    log.info("Loading embedding model: %s", EMBEDDING_MODEL)
    model = SentenceTransformer(EMBEDDING_MODEL)

    logs = load_logs(UNIFIED_LOGS)
    metadata = build_metadata(logs)
    validate_metadata(metadata)
    save_metadata(metadata, OUTPUT_METADATA)

    embeddings = build_embeddings(metadata, model)
    save_embeddings(embeddings, OUTPUT_EMBEDDINGS)

    index = build_faiss_index(embeddings.copy())
    save_faiss_index(index, OUTPUT_FAISS)

    print()
    print("--- Retrieval index ---")
    print(f"Total indexed logs: {len(metadata)}")
    print(f"Embedding dimension: {embeddings.shape[1]}")

    # A. Semantic query
    q_a = "authentication failure"
    print(f"\nA. Semantic query: {q_a!r}")
    top_a = semantic_search(q_a, metadata, embeddings, index, model, top_k=5)
    print("Top 5:")
    _print_top5("semantic", top_a)

    # B. Hybrid query: "authentication failure" with dataset="linux"
    q_b = "authentication failure"
    print(f"\nB. Hybrid query: {q_b!r} with dataset='linux'")
    top_b = hybrid_search(
        q_b, metadata, embeddings, model,
        dataset="linux",
        top_k=5,
    )
    print("Top 5:")
    _print_top5("hybrid_linux", top_b)

    # C. Hybrid query: "vm error" with dataset="openstack"
    q_c = "vm error"
    print(f"\nC. Hybrid query: {q_c!r} with dataset='openstack'")
    top_c = hybrid_search(
        q_c, metadata, embeddings, model,
        dataset="openstack",
        top_k=5,
    )
    print("Top 5:")
    _print_top5("hybrid_openstack", top_c)

    print()
    log.info("Done.")


if __name__ == "__main__":
    main()
