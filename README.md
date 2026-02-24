# LLM Reasoning

## Pipeline

```text
Mac_2k.log
   |
   v
log_parser.py
   |
   v
chunked parsed logs
   |
   v
log_analyzer.py  (categorization, correlation)
   |
   v
report.json
```

## Implementation 

The implementation follows the official `ollama-python` sync client examples:
- `Client(host=...)`
- `client.chat(...)`
- `format=<json_schema>` for structured outputs

This project uses the `chat()` workflow because the task is multi-step:
1. chunk-level categorization
2. cross-chunk correlation

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Start Ollama

```bash
ollama serve
ollama pull llama3.1:8b
```

## Run

```bash
python3 -m src.main \
  --log-file data/Mac_2k.log \
  --model llama3.1:8b \
  --chunk-size 250 \
  --max-lines 2000 \
  --temperature 0.2 \
  --output-file reports/report.json
```

Drop Low-Signal Logs:

```bash
python3 -m src.main \
  --log-file data/Mac_2k.log \
  --drop-low-signal
```
