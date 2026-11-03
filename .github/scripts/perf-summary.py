#!/usr/bin/env python3
"""Markdown summary of tunnel_bench results: median per side, head vs base.

Input files are named <side>-<outbound>-<round>.json (see perf.yml).
"""

import json
import statistics
import sys
from pathlib import Path

# (json path, label, unit, which direction is better)
METRICS = [
    ("start_ms", "Tunnel start", "ms", "lower"),
    ("rss_after_start_kb", "RSS after start", "KiB", "lower"),
    ("idle.cpu_ms_per_s", "Idle CPU", "ms/s", "lower"),
    ("idle.wakeups_per_s", "Idle wakeups", "/s", "lower"),
    ("idle_conns.cpu_ms_per_s", "Idle CPU, 100 open conns", "ms/s", "lower"),
    ("idle_conns.wakeups_per_s", "Idle wakeups, 100 open conns", "/s", "lower"),
    ("connect.handshake_p50_ms", "Handshake p50", "ms", "lower"),
    ("connect.first_byte_p50_ms", "First byte p50", "ms", "lower"),
    ("connect.first_byte_p99_ms", "First byte p99", "ms", "lower"),
    ("download_1.mbps", "Download, 1 flow", "Mbit/s", "higher"),
    ("download_1.cpu_ms_per_gib", "Download CPU, 1 flow", "ms/GiB", "lower"),
    ("download_8.mbps", "Download, 8 flows", "Mbit/s", "higher"),
    ("download_8.cpu_ms_per_gib", "Download CPU, 8 flows", "ms/GiB", "lower"),
    ("upload_1.mbps", "Upload, 1 flow", "Mbit/s", "higher"),
    ("upload_1.cpu_ms_per_gib", "Upload CPU, 1 flow", "ms/GiB", "lower"),
    ("memory.per_conn_kb", "Memory per stalled conn", "KiB", "lower"),
    ("memory.rss_stalled_kb", "RSS, 100 stalled conns", "KiB", "lower"),
    ("memory.rss_after_close_kb", "RSS after they close", "KiB", "lower"),
    ("hwm_kb", "Peak RSS", "KiB", "lower"),
]


def pick(report, path):
    value = report
    for key in path.split("."):
        if not isinstance(value, dict) or key not in value:
            return None
        value = value[key]
    return value if isinstance(value, (int, float)) else None


def median(reports, path):
    values = [v for v in (pick(r, path) for r in reports) if v is not None]
    return statistics.median(values) if values else None


def fmt(value):
    if value is None:
        return "–"
    if abs(value) >= 100:
        return f"{value:,.0f}"
    return f"{value:.2f}"


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "results")
    runs = {}
    for path in sorted(root.glob("*.json")):
        side, outbound, _round = path.stem.split("-", 2)
        runs.setdefault(outbound, {}).setdefault(side, []).append(json.loads(path.read_text()))
    print("### Tunnel benchmark")
    print()
    if not runs:
        print("No results.")
        return
    print("Median of the rounds on one runner; compare only numbers from the same run.")
    for outbound, sides in sorted(runs.items()):
        print()
        print(f"#### Outbound `{outbound}`")
        print()
        has_base = "base" in sides
        if has_base:
            print("| Metric | Base | Head | Change |")
            print("| --- | ---: | ---: | ---: |")
        else:
            print("| Metric | Head |")
            print("| --- | ---: |")
        for path, label, unit, better in METRICS:
            head = median(sides.get("head", []), path)
            if not has_base:
                print(f"| {label} ({unit}) | {fmt(head)} |")
                continue
            base = median(sides["base"], path)
            change = "–"
            if base and head is not None:
                pct = (head - base) / base * 100
                good = pct > 0 if better == "higher" else pct < 0
                mark = "" if abs(pct) < 5 else (" ✅" if good else " ⚠️")
                change = f"{pct:+.1f}%{mark}"
            print(f"| {label} ({unit}) | {fmt(base)} | {fmt(head)} | {change} |")


if __name__ == "__main__":
    main()
