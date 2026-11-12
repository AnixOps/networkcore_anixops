#!/usr/bin/env python3
"""Markdown summaries for perf.yml.

Default: tunnel_bench results, median per side, head vs base. Input files are
named <side>-<outbound>-<round>.json.

--rules FILE: the rule_bench report (decision latency by query kind, gate).
--scale DIR: tunnel_bench scale-<outbound>.json and udp-sessions.json (gates).
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


def rules_summary(path):
    print("### Rule decision benchmark")
    print()
    try:
        report = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        print("No results.")
        return
    limit = report.get("max_p99_us")
    p99 = pick(report, "all.p99_us")
    verdict = "–"
    if limit is not None and p99 is not None:
        verdict = "✅ pass" if p99 <= limit else "❌ fail"
    print(
        f"{report.get('rules')} rules, {report.get('queries')} decisions per round, "
        f"{report.get('miss_share', 0) * 100:.0f}% match no rule (whole list, resolve, FINAL); "
        f"median round of {report.get('rounds')}. Build {fmt(report.get('build_ms'))} ms. "
        f"Decide: {report.get('decide', 'linear')}, "
        f"{report.get('rules_tried_one_by_one', '–')} rules tried one by one (the rest by hash lookup)."
    )
    print()
    print(f"Gate: p99 of all decisions ≤ {fmt(limit)} µs: {verdict} (p99 {fmt(p99)} µs)")
    print()
    print("| Queries | Count | Mean (µs) | p50 | p90 | p99 | p99.9 | Max |")
    print("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    rows = [("all", report.get("all", {}))]
    rows += sorted((report.get("by_kind") or {}).items())
    for name, row in rows:
        cells = [fmt(row.get(key)) for key in ("mean_us", "p50_us", "p90_us", "p99_us", "p999_us", "max_us")]
        print(f"| {name} | {row.get('count', 0)} | " + " | ".join(cells) + " |")
    unexpected = report.get("unexpected_results", 0)
    if unexpected:
        print()
        print(f"⚠️ {unexpected} decisions did not hit or miss as the generated list expects.")


def verdict(report):
    if report.get("pass"):
        return "✅ pass"
    failures = "; ".join(report.get("failures") or []) or "no result"
    return f"❌ fail: {failures}"


def scale_summary(root):
    root = Path(root)
    print("### Tunnel scale")
    print()
    udp = root / "udp-sessions.json"
    if udp.exists():
        report = json.loads(udp.read_text())
        print(f"#### {report.get('flows')} UDP flows open at once: {verdict(report)}")
        print()
        print("| Metric | Value |")
        print("| --- | ---: |")
        rows = [
            ("Flows opened", "opened", ""),
            ("Failed / dropped", None, ""),
            ("Time to open all", "open_secs", "s"),
            ("Flows per second", "flows_per_s", "/s"),
            ("RSS after start", "rss_started_kb", "KiB"),
            ("RSS with all open", "rss_open_kb", "KiB"),
            ("Memory per flow", "per_flow_kb", "KiB"),
            ("RSS limit", "max_rss_mb", "MiB"),
        ]
        for label, key, unit in rows:
            if key is None:
                value = f"{report.get('failed', 0)} / {report.get('dropped', 0)}"
            else:
                raw = report.get(key)
                if isinstance(raw, str):
                    raw = float(raw)
                value = fmt(raw) + (f" {unit}" if unit and raw is not None else "")
            print(f"| {label} | {value} |")
        print()
    for path in sorted(root.glob("scale-*.json")):
        report = json.loads(path.read_text())
        outbound = report.get("outbound")
        print(f"#### {report.get('concurrent')} connections at once, outbound `{outbound}`: {verdict(report)}")
        print()
        print("| Metric | Value |")
        print("| --- | ---: |")
        rows = [
            ("Established", "established", ""),
            ("Connect failures", "connect_failed", ""),
            ("Time to open all", "open_secs", "s"),
            ("Echo failures", "echo_failed", ""),
            ("Echo p50, all open", "echo_p50_ms", "ms"),
            ("Echo p99, all open", "echo_p99_ms", "ms"),
            ("Tunnel TCP active", "tcp_active_open", ""),
            ("Rejected by the tunnel", "tcp_rejected", ""),
            ("RSS with all open", "rss_open_kb", "KiB"),
            ("Memory per connection", "per_conn_kb", "KiB"),
            ("RSS after close", "rss_after_close_kb", "KiB"),
            ("TCP active after close", "tcp_active_after_close", ""),
        ]
        for label, key, unit in rows:
            raw = report.get(key)
            value = fmt(raw) + (f" {unit}" if unit and raw is not None else "")
            print(f"| {label} | {value} |")
        print()
    if not udp.exists() and not any(root.glob("scale-*.json")):
        print("No results.")


def main():
    if len(sys.argv) > 2 and sys.argv[1] == "--rules":
        rules_summary(sys.argv[2])
        return
    if len(sys.argv) > 2 and sys.argv[1] == "--scale":
        scale_summary(sys.argv[2])
        return
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
