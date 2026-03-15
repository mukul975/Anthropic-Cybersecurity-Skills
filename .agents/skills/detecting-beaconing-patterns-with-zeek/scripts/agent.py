#!/usr/bin/env python3
"""Agent for detecting C2 beaconing patterns in Zeek conn.log data."""

import os
import json
import argparse
from datetime import datetime

import numpy as np
import pandas as pd
from zat.log_to_dataframe import LogToDataFrame
from zat import zeek_log_reader


def load_conn_log(log_path):
    """Load Zeek conn.log into a Pandas DataFrame using ZAT."""
    log_to_df = LogToDataFrame()
    df = log_to_df.create_dataframe(log_path)
    return df


def calculate_beacon_score(intervals):
    """Calculate a beacon score based on interval regularity."""
    if len(intervals) < 5:
        return 0.0
    std_dev = np.std(intervals)
    mean_val = np.mean(intervals)
    if mean_val == 0:
        return 0.0
    cv = std_dev / mean_val
    score = max(0, 1.0 - cv) * 100
    return round(score, 2)


def detect_beaconing(conn_df, min_connections=10, max_cv=0.3):
    """Detect beaconing by analyzing connection interval regularity."""
    conn_df = conn_df.sort_values("ts")
    beacons = []
    grouped = conn_df.groupby(["id.orig_h", "id.resp_h", "id.resp_p"])
    for (src, dst, port), group in grouped:
        if len(group) < min_connections:
            continue
        times = group["ts"].sort_values()
        intervals = times.diff().dt.total_seconds().dropna().values
        if len(intervals) < 5:
            continue
        std_dev = float(np.std(intervals))
        mean_interval = float(np.mean(intervals))
        if mean_interval == 0:
            continue
        cv = std_dev / mean_interval
        beacon_score = calculate_beacon_score(intervals)
        if cv <= max_cv:
            beacons.append({
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": int(port) if not pd.isna(port) else 0,
                "connection_count": len(group),
                "mean_interval_sec": round(mean_interval, 2),
                "std_dev_sec": round(std_dev, 2),
                "coefficient_of_variation": round(cv, 4),
                "beacon_score": beacon_score,
                "first_seen": str(times.iloc[0]),
                "last_seen": str(times.iloc[-1]),
            })
    return sorted(beacons, key=lambda x: x["beacon_score"], reverse=True)


def detect_jitter_beaconing(conn_df, base_interval=60, jitter_pct=0.2, min_conns=10):
    """Detect beaconing with expected interval and jitter tolerance."""
    conn_df = conn_df.sort_values("ts")
    matches = []
    grouped = conn_df.groupby(["id.orig_h", "id.resp_h"])
    for (src, dst), group in grouped:
        if len(group) < min_conns:
            continue
        times = group["ts"].sort_values()
        intervals = times.diff().dt.total_seconds().dropna().values
        lower = base_interval * (1 - jitter_pct)
        upper = base_interval * (1 + jitter_pct)
        matching = np.sum((intervals >= lower) & (intervals <= upper))
        match_pct = matching / len(intervals)
        if match_pct > 0.7:
            matches.append({
                "src_ip": src,
                "dst_ip": dst,
                "connections": len(group),
                "matching_intervals": int(matching),
                "match_percentage": round(match_pct * 100, 1),
                "expected_interval": base_interval,
            })
    return matches


def analyze_dns_beaconing(dns_log_path, min_queries=20, max_cv=0.25):
    """Analyze Zeek dns.log for DNS-based beaconing patterns."""
    log_to_df = LogToDataFrame()
    dns_df = log_to_df.create_dataframe(dns_log_path)
    dns_df = dns_df.sort_values("ts")
    beacons = []
    grouped = dns_df.groupby(["id.orig_h", "query"])
    for (src, query), group in grouped:
        if len(group) < min_queries:
            continue
        times = group["ts"].sort_values()
        intervals = times.diff().dt.total_seconds().dropna().values
        if len(intervals) < 5:
            continue
        std_dev = float(np.std(intervals))
        mean_val = float(np.mean(intervals))
        if mean_val == 0:
            continue
        cv = std_dev / mean_val
        if cv <= max_cv:
            beacons.append({
                "src_ip": src,
                "query": query,
                "query_count": len(group),
                "mean_interval_sec": round(mean_val, 2),
                "std_dev_sec": round(std_dev, 2),
                "cv": round(cv, 4),
                "beacon_score": calculate_beacon_score(intervals),
            })
    return sorted(beacons, key=lambda x: x["beacon_score"], reverse=True)


def filter_whitelisted(beacons, whitelist_domains=None):
    """Remove known-good destinations from beacon results."""
    if not whitelist_domains:
        whitelist_domains = ["microsoft.com", "google.com", "amazonaws.com",
                            "cloudflare.com", "akamai.net"]
    filtered = []
    for b in beacons:
        dst = b.get("dst_ip", "") or b.get("query", "")
        if not any(w in dst for w in whitelist_domains):
            filtered.append(b)
    return filtered


def main():
    parser = argparse.ArgumentParser(description="Zeek Beaconing Detection Agent")
    parser.add_argument("--conn-log", help="Path to Zeek conn.log")
    parser.add_argument("--dns-log", help="Path to Zeek dns.log")
    parser.add_argument("--min-connections", type=int, default=10)
    parser.add_argument("--max-cv", type=float, default=0.3)
    parser.add_argument("--output", default="beacon_report.json")
    parser.add_argument("--action", choices=[
        "conn_beacon", "dns_beacon", "full_hunt"
    ], default="full_hunt")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}

    if args.action in ("conn_beacon", "full_hunt") and args.conn_log:
        conn_df = load_conn_log(args.conn_log)
        beacons = detect_beaconing(conn_df, args.min_connections, args.max_cv)
        beacons = filter_whitelisted(beacons)
        report["findings"]["conn_beacons"] = beacons
        print(f"[+] Connection beacons detected: {len(beacons)}")

    if args.action in ("dns_beacon", "full_hunt") and args.dns_log:
        dns_beacons = analyze_dns_beaconing(args.dns_log, args.min_connections)
        dns_beacons = filter_whitelisted(dns_beacons)
        report["findings"]["dns_beacons"] = dns_beacons
        print(f"[+] DNS beacons detected: {len(dns_beacons)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
