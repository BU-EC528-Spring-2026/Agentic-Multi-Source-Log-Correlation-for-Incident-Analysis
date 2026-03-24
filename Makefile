VENV ?= .venv
PYTHON ?= $(VENV)/bin/python
LOG_DATA_ROOT ?= data/loghub

.PHONY: clean clean-cache clean-reports ingest retrieval pipeline pipeline-skip-llm test

ingest:
	LOG_DATA_ROOT=$(LOG_DATA_ROOT) $(PYTHON) -m src.ingestion.ingest_logs

retrieval:
	LOG_DATA_ROOT=$(LOG_DATA_ROOT) $(PYTHON) -m src.retrieval.build_retrieval_index

pipeline: ingest retrieval
	LOG_DATA_ROOT=$(LOG_DATA_ROOT) $(PYTHON) -m src.main

pipeline-skip-llm: ingest retrieval
	LOG_DATA_ROOT=$(LOG_DATA_ROOT) $(PYTHON) -m src.main --skip-llm

test:
	$(PYTHON) -m pytest

clean: clean-cache clean-reports

clean-cache:
	find . -type d -name "__pycache__" -prune -exec rm -rf {} +
	find . -name ".DS_Store" -delete
	find . -type d -name ".pytest_cache" -prune -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete

clean-reports:
	find reports -maxdepth 1 -type f \( -name "*.json" -o -name "*.jsonl" \) -delete
	find normalized -maxdepth 1 -type f \( -name "*.json" -o -name "*.jsonl" -o -name "*.npy" -o -name "*.index" \) -delete 2>/dev/null || true
