# Agentic Multi-Source Log Correlation for Incident Analysis

This EC528 project explores how agentic workflows can analyze heterogeneous logs, extract source-specific findings, and correlate them into a single incident view.

## Current Pipeline

The current implementation supports an integrated pipeline in [src/main.py](src/main.py):

1. Load input from one of these sources, in order:
   - `normalized/unified_logs.jsonl`
   - structured LogHub CSV datasets under `data/` or `LOG_DATA_ROOT`
   - a raw log file passed through `--log-file`
   - the bundled demo fixture at `examples/demo_unified_logs.jsonl`
2. Convert logs into canonical `LogEvent` objects.
3. Run source-specific rule-based agents:
   - auth agent
   - OpenStack VM agent
4. Run deterministic correlation over the canonical events.
5. Optionally run LLM-based chunk analysis and cross-chunk correlation through **Amazon Bedrock**.
6. Write a combined report to `reports/report.json` by default.

## Project Layout

- `src/main.py`: integrated pipeline entrypoint
- `src/ingestion/ingest_logs.py`: normalize structured CSV datasets into unified JSONL
- `src/agents/auth_agent.py`: auth anomaly detection
- `src/agents/openstack_vm_agent.py`: OpenStack VM anomaly detection
- `src/agents/correlation/correlation_agent.py`: deterministic event correlation
- `src/agents/log_analyzer.py`: LLM-driven chunk analysis and correlation
- `examples/demo_unified_logs.jsonl`: bundled demo input when no real data is present
- `reports/`: generated reports and sample artifacts

## Requirements

- Python **3.11** or newer (3.12 is fine)
- For Bedrock-backed LLM analysis: an **AWS account** with **Amazon Bedrock** access to the model you plan to use

## Installation

Create a Python environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## AWS Bedrock setup

1. Install the [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) and sign in (`aws configure`, or your organization’s SSO / IAM role flow).
2. In the **AWS console**, open **Amazon Bedrock** and enable **model access** for the model you will call.
3. Pick a region where that model is available and use it consistently below.

Set these environment variables (or put them in a `.env` file in the repo root; the app loads it automatically):

```bash
export AWS_REGION=us-east-1
export BEDROCK_MODEL_ID=global.anthropic.claude-sonnet-4-6
```

`BEDROCK_MODEL_ID` can also be set as `BEDROCK_MODEL` or `AWS_BEDROCK_MODEL_ID`. If `AWS_REGION` is unset, `BEDROCK_REGION` or `AWS_DEFAULT_REGION` are used.

## Workflow

Ingest, build the retrieval index, then run Bedrock-backed `main` (same sequence as `reports/sonnet_report.json`). Step 4 needs [AWS Bedrock setup](#aws-bedrock-setup).

From the **repository root**, with the venv activated:

1. **Data** — Place the structured CSVs under `data/` as described in [Using Real LogHub Data](#using-real-loghub-data), or point at your tree with `LOG_DATA_ROOT`. If `normalized/unified_logs.jsonl` is already present, ingest is optional.
2. **Ingest** — `make ingest` (or `LOG_DATA_ROOT=... make ingest` if your CSVs are not under `data/`).
3. **Retrieval index** — `make retrieval` (needed for the same retrieval-augmented chunk context as the sample report).
4. **Pipeline** —

```bash
python -m src.main --provider bedrock --output-file reports/sonnet_report.json
```

It took Claude Sonnet-4.6 around **15–20 minutes** to generate an analysis report for 8000 structured events. 

`llm_analysis.meta` and `llm_analysis.inference` sections record model id and timing.

Equivalent using Make (writes default `reports/report.json` unless you override the command):

```bash
make pipeline
```

To use a different output path with Make, run step 4 manually as shown.

## How To Run

### Deterministic only (no Bedrock, fast)

```bash
python -m src.main --skip-llm
```

If no real datasets or raw logs are available, the pipeline falls back to `examples/demo_unified_logs.jsonl`. The report will show `input_mode: bundled_demo`.

### Full pipeline with Bedrock

Configure Bedrock as in [AWS Bedrock setup](#aws-bedrock-setup). For ingest, retrieval, and the Bedrock command, follow [Workflow](#workflow).

If `normalized/unified_logs.jsonl` and the retrieval index are already built, you can run `main` alone. Default output path:

```bash
python -m src.main --provider bedrock
```

Use a specific normalized JSONL file:

```bash
python -m src.main --normalized-log-file /path/to/unified_logs.jsonl --skip-llm
```

Use a specific raw log file:

```bash
python -m src.main --log-file /path/to/logfile.log --skip-ingestion --skip-llm
```

Change the output path:

```bash
python -m src.main --skip-llm --output-file reports/my_report.json
```

## Using Real LogHub Data

By default, ingestion looks for these files under `data/`:

- `data/OpenStack/OpenStack_2k.log_structured.csv`
- `data/OpenSSH/OpenSSH_2k.log_structured.csv`
- `data/Linux/Linux_2k.log_structured.csv`
- `data/Apache/Apache_2k.log_structured.csv`

You can also point the pipeline at a different data root:

```bash
export LOG_DATA_ROOT=/absolute/path/to/loghub
python -m src.main --skip-llm
```

When those structured CSVs are present and `normalized/unified_logs.jsonl` does not already exist, the pipeline will ingest them automatically.

## Output

The generated report includes:

- pipeline metadata
- detected source-agent findings
- deterministic correlation groups
- optional LLM analysis
- chunk-level summaries and correlation hypotheses when LLM mode is enabled

Default output file:

```text
reports/report.json
```

## Testing

Run the test suite locally:

```bash
pytest -q
```

Show more detail:

```bash
pytest -vv
```

GitHub Actions also runs the test suite automatically on pushes and pull requests via `.github/workflows/tests.yml`.

## Cleanup

Use the Make targets to remove generated artifacts:

```bash
make clean
```

Available targets:

- `make clean`: remove caches and generated reports
- `make clean-cache`: remove `__pycache__`, `.pyc`, `.pytest_cache`, `.DS_Store`
- `make clean-reports`: remove generated files under `reports/` and `normalized/`

## Notes

- The bundled demo input is static, but the report is still generated by the real pipeline code.
- LLM mode with Bedrock requires valid AWS credentials, a region, and a `BEDROCK_MODEL_ID` (or equivalent) the account is allowed to invoke.
- The retrieval module lives in `src/retrieval/`; `make retrieval` should be run before a full Bedrock run if you want retrieval context in chunk analysis.

## Demo Presentations

- [Demo 1](https://docs.google.com/presentation/d/1GPAEH4Cf7paiDZ0z6zxIpxNn0OVbhj9mYld-0ZLKsgY/edit?slide=id.p#slide=id.p)
- [Demo 2](https://docs.google.com/presentation/d/1utnqEQaKfqSOjF4wya7j3ddD0Xs1_japXFvNtP1JG6o/edit?usp=sharing)
