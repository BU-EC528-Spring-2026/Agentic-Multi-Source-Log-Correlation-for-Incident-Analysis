# Log pipeline backend

Standalone backend for log ingestion, retrieval, and source agents. Reads structured LogHub-style CSVs from a configurable data root and produces normalized logs plus anomaly outputs.

## Components

- **Ingestion** — Loads OpenStack, OpenSSH, Linux, and Apache structured CSVs; normalizes timestamps and schema; writes `normalized/unified_logs.jsonl` and `normalized/ingestion_summary.json`.
- **Retrieval** — Builds metadata JSONL, message embeddings, and a FAISS index over unified logs for semantic/keyword search.
- **Auth agent** — Detects auth-related anomalies (repeated failures, invalid user, successful auth after failures, login burst) from Linux/OpenSSH logs.
- **OpenStack VM agent** — Detects VM lifecycle anomalies (repeated restart cycle, unexpected stop, lifecycle churn) from OpenStack logs.

## Data root (`LOG_DATA_ROOT`)

Datasets are **not** stored in this repo. All dataset paths are under a single configurable root:

- **Environment variable:** `LOG_DATA_ROOT`
- **Default:** `data` (relative to project root)

Expected layout under that root:

- `LOG_DATA_ROOT/OpenStack/OpenStack_2k.log_structured.csv`
- `LOG_DATA_ROOT/OpenSSH/OpenSSH_2k.log_structured.csv`
- `LOG_DATA_ROOT/Linux/Linux_2k.log_structured.csv`
- `LOG_DATA_ROOT/Apache/Apache_2k.log_structured.csv`

Use a path relative to the project (e.g. `data`) or an absolute path (e.g. `/opt/loghub`) so the same code works whether data lives inside the repo or in an external LogHub clone.

See `data/README.md` for required datasets and file names.

## Running the pipeline

From the project root:

```bash
# Optional: use external data (e.g. LogHub clone)
export LOG_DATA_ROOT=/path/to/loghub

# 1. Ingest
python -m src.ingestion.ingest_logs

# 2. Build retrieval index (optional)
python -m src.retrieval.build_retrieval_index

# 3. Run source agents
python -m src.agents.auth_agent
python -m src.agents.openstack_vm_agent
```

Outputs go under `normalized/`. Example anomaly records are in `reports/`.

## Tests

```bash
pytest tests/ -v
```

## Project layout

```
src/
  ingestion/   ingest_logs.py
  retrieval/   build_retrieval_index.py
  agents/      auth_agent.py, openstack_vm_agent.py
tests/
reports/       sample agent outputs
data/README.md
```
