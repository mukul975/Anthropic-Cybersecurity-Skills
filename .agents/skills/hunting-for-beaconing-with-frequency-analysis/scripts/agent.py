#!/usr/bin/env python3
"""Agent for detecting C2 beaconing through network traffic frequency analysis."""

import argparse
import json
import math
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone


def parse_zeek_conn_log(log_path):
    """Parse Zeek conn.log and extract connection timestamps per src-dst pair."""
    connections = defaultdict(list)
    try:
        with open(log_path, "r") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                fields = line.strip().split("\t")
                if len(fields) < 7:
                    continue
                ts = float(fields[0])
                src, dst = fields[2], fields[4]
                dst_port = fields[5]
                key = f"{src}->{dst}:{dst_port}"
                connections[key].append(ts)
    except (FileNotFoundError, ValueError):
        pass
    return connections


def calculate_jitter(intervals):
    """Calculate jitter (standard deviation of intervals)."""
    if len(intervals) < 2:
        return 0
    mean = sum(intervals) / len(intervals)
    variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
    return math.sqrt(variance)


def detect_beaconing(connections, min_connections=10, max_jitter_percent=15):
    """Detect beaconing patterns based on interval regularity."""
    beacons = []
    for key, timestamps in connections.items():
        if len(timestamps) < min_connections:
            continue
        timestamps.sort()
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        if not intervals:
            continue
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval == 0:
            continue
        jitter = calculate_jitter(intervals)
        jitter_percent = (jitter / mean_interval) * 100

        if jitter_percent <= max_jitter_percent:
            parts = key.split("->")
            src = parts[0]
            dst_port = parts[1] if len(parts) > 1 else ""
            beacons.append({
                "flow": key,
                "connection_count": len(timestamps),
                "mean_interval_seconds": round(mean_interval, 2),
                "jitter_seconds": round(jitter, 2),
                "jitter_percent": round(jitter_percent, 2),
                "duration_hours": round((timestamps[-1] - timestamps[0]) / 3600, 2),
                "confidence": "HIGH" if jitter_percent < 5 else "MEDIUM",
            })
    return sorted(beacons, key=lambda x: x["jitter_percent"])


def parse_csv_log(csv_path):
    """Parse generic CSV log with timestamp, src, dst, port columns."""
    connections = defaultdict(list)
    try:
        import csv
        with open(csv_path, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ts = row.get("timestamp") or row.get("ts") or row.get("time")
                src = row.get("src") or row.get("source") or row.get("src_ip")
                dst = row.get("dst") or row.get("destination") or row.get("dst_ip")
                port = row.get("dst_port") or row.get("port") or ""
                if ts and src and dst:
                    try:
                        ts_float = float(ts)
                    except ValueError:
                        from datetime import datetime as dt
                        try:
                            ts_float = dt.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
                        except ValueError:
                            continue
                    connections[f"{src}->{dst}:{port}"].append(ts_float)
    except (FileNotFoundError, KeyError):
        pass
    return connections


def main():
    parser = argparse.ArgumentParser(
        description="Detect C2 beaconing via frequency analysis"
    )
    parser.add_argument("--conn-log", help="Zeek conn.log path")
    parser.add_argument("--csv", help="CSV log with timestamp, src, dst columns")
    parser.add_argument("--min-connections", type=int, default=10)
    parser.add_argument("--max-jitter", type=float, default=15, help="Max jitter percent")
    parser.add_argument("--output", "-o", help="Output JSON report")
    args = parser.parse_args()

    print("[*] Beaconing Detection via Frequency Analysis")
    connections = {}

    if args.conn_log:
        connections = parse_zeek_conn_log(args.conn_log)
    elif args.csv:
        connections = parse_csv_log(args.csv)

    print(f"[*] Unique flows: {len(connections)}")
    beacons = detect_beaconing(connections, args.min_connections, args.max_jitter)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "flows_analyzed": len(connections),
        "beacons_detected": len(beacons),
        "beacons": beacons[:50],
        "risk_level": "CRITICAL" if beacons else "LOW",
    }
    print(f"[*] Beacons detected: {len(beacons)}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
