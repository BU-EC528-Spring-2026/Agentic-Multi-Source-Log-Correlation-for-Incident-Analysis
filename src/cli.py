from __future__ import annotations

import argparse
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .ingest import ingest_mac_system_logs, ingest_auth_jsonl
from .align import sort_events, choose_anchor, window
from .agents.thermal import extract as extract_thermal, summarize as summarize_thermal, segments as thermal_segments
from .report import build_report
from .time_utils import iso_utc

console = Console()

def _print_ranges(events, name: str):
    if not events:
        console.print(f"[yellow]{name}: 0 events[/yellow]")
        return
    lo = min(e.ts for e in events)
    hi = max(e.ts for e in events)
    console.print(f"[bold]{name}[/bold] events={len(events)} range={iso_utc(lo)} -> {iso_utc(hi)}")

def _print_window_preview(events, title: str, limit: int):
    table = Table(title=title)
    table.add_column("time")
    table.add_column("source")
    table.add_column("component")
    table.add_column("message", overflow="fold")

    for e in sorted(events, key=lambda x: x.ts)[:limit]:
        table.add_row(
            iso_utc(e.ts),
            e.source,
            str((e.fields or {}).get("component") or ""),
            e.message[:120],
        )
    console.print(table)

def run(args: argparse.Namespace) -> int:
    host_csv = Path(args.host_csv)
    auth_jsonl = Path(args.auth_jsonl) if args.auth_jsonl else None
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1) Ingest FULL host dataset
    host = ingest_mac_system_logs(host_csv, year=args.mac_year, source="host")

    # 2) Optional second source
    auth = []
    if auth_jsonl:
        try:
            auth = ingest_auth_jsonl(auth_jsonl, source="auth")
        except FileNotFoundError:
            console.print(f"[yellow]Auth file not found: {auth_jsonl} (continuing host-only)[/yellow]")

    all_events = sort_events(host + auth)

    _print_ranges(host, "Host(mac)")
    if auth:
        _print_ranges(auth, "Auth")
    _print_ranges(all_events, "ALL")

    # 3) Choose anchor + align window
    anchor = choose_anchor(all_events, strategy=args.anchor)
    win = window(all_events, anchor_ts=anchor, delta_s=args.window_seconds)

    _print_window_preview(win, f"Aligned window ±{args.window_seconds}s around {iso_utc(anchor)}", limit=args.print_limit)

    # 4) Run thermal agent on FULL host dataset (not just window)
    thermal = extract_thermal(host)
    thermal_summary = summarize_thermal(thermal)
    segs = thermal_segments(thermal, gap_s=args.segment_gap_seconds)

    # 5) Build report
    report = build_report(
        all_events=all_events,
        window_events=win,
        thermal_summary=thermal_summary,
        thermal_segments=segs,
    )

    out_path = out_dir / "incident_report.json"
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    console.print(f"✅ Wrote: {out_path}")
    console.print(report["narrative"]["human_summary"])
    return 0

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="logcorr-demo1")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run-demo1", help="Run Demo 1 pipeline on Tahira's mac CSV (and optional auth jsonl).")
    r.add_argument("--host-csv", required=True, help="Path to mac_system_logs.csv")
    r.add_argument("--auth-jsonl", default=None, help="Optional: path to auth.jsonl for 2nd source")
    r.add_argument("--mac-year", type=int, default=2026, help="Year to assume for mac CSV timestamps (CSV has no year)")
    r.add_argument("--anchor", choices=["median","first"], default="median", help="Anchor selection strategy")
    r.add_argument("--window-seconds", type=float, default=120.0, help="Alignment window ±Δ seconds")
    r.add_argument("--segment-gap-seconds", type=float, default=900.0, help="Gap threshold for thermal segments (seconds)")
    r.add_argument("--print-limit", type=int, default=25, help="Preview lines to print")
    r.add_argument("--out-dir", default="out", help="Output directory")
    r.set_defaults(func=run)

    return p

def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)

if __name__ == "__main__":
    raise SystemExit(main())
