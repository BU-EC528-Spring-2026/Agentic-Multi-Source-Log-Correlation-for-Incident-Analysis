# Demo 1 — Omar’s Part (Ingestion + Normalization + Alignment)

This repo chunk is **my contribution** for Demo 1:
I took Tahira’s macOS dataset (`mac_system_logs.csv`) and turned it into a **clean ingestion + normalization + alignment pipeline** that the rest of the multi-agent system can build on.

If ingestion is messy, everything downstream becomes a guessing game.
So this is strict, reproducible, and easy to extend.

---

## What this pipeline does (real data, full file)
✅ Reads the **full** `mac_system_logs.csv` (no sampling)  
✅ Normalizes timestamps → **epoch seconds (UTC)**  
✅ Unifies events into a single schema: `{ts, source, message, level, fields}`  
✅ Supports window-based alignment: events within **±Δ seconds**  
✅ Runs the existing **thermal agent** on the full host dataset (Demo 1 focus)  
✅ Outputs a structured incident report: `out/incident_report.json`

Optional:
- Adds a second source via `--auth-jsonl` (auth logs JSONL).  
  If you don’t have auth logs ready yet, the pipeline still runs host-only, but the interface is already there.

---

## Why this helps Demo 2 / the rest of the semester
- Every future agent (auth/network/metrics) plugs into the same `Event` schema.
- Correlation agent later can cite exact timestamps + events (traceability).
- No one has to rewrite parsing logic again.

---

## Run (host-only)
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python -m src.cli run-demo1 --host-csv /path/to/mac_system_logs.csv --mac-year 2026 --window-seconds 120
```

## Run (host + auth) — second source
```bash
python -m src.cli run-demo1 \
  --host-csv /path/to/mac_system_logs.csv \
  --auth-jsonl /path/to/auth.jsonl \
  --mac-year 2026 \
  --window-seconds 120
```

---

## Output
- `out/incident_report.json` (structured, explainable)
- Console preview:
  - data ranges for each source
  - aligned window around anchor
  - a small timeline preview

---

## Notes (important + honest)
- mac_system_logs.csv has Month/Date/Time but **no year**.
  We make the year explicit with `--mac-year` so the run is reproducible.
- For Demo 1, the thermal agent is the only analysis agent (by design).
  The goal is to prove the pipeline + one agent works end-to-end.

