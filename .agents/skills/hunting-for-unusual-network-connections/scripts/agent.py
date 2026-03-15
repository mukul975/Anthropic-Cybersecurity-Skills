#!/usr/bin/env python3
"""Agent for hunting unusual network connections from endpoint and firewall logs."""

import json
import argparse
import re
from datetime import datetime
from collections import defaultdict, Counter
from pathlib import Path


COMMON_PORTS = {80, 443, 53, 22, 25, 110, 143, 993, 995, 587, 8080, 8443, 3389}

KNOWN_BAD_PORTS = {4444, 5555, 1234, 9999, 31337, 6666, 6667, 8888, 12345}

PRIVATE_RANGES = [
    (0x0A000000, 0x0AFFFFFF),   # 10.0.0.0/8
    (0xAC100000, 0xAC1FFFFF),   # 172.16.0.0/12
    (0xC0A80000, 0xC0A8FFFF),   # 192.168.0.0/16
]


def ip_to_int(ip):
    """Convert dotted IP to integer."""
    parts = ip.split(".")
    if len(parts) != 4:
        return 0
    try:
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    except ValueError:
        return 0


def is_private(ip):
    """Check if IP is in private RFC1918 range."""
    val = ip_to_int(ip)
    return any(start <= val <= end for start, end in PRIVATE_RANGES)


def load_connection_logs(log_path):
    """Load network connection logs from JSON lines."""
    entries = []
    with open(log_path) as f:
        for line in f:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def detect_non_standard_ports(connections):
    """Find connections to unusual destination ports."""
    findings = []
    for conn in connections:
        dst_port = int(conn.get("dest_port", conn.get("dst_port", 0)))
        if dst_port in KNOWN_BAD_PORTS:
            findings.append({
                "src_ip": conn.get("src_ip", conn.get("source_ip", "")),
                "dst_ip": conn.get("dst_ip", conn.get("dest_ip", "")),
                "dst_port": dst_port,
                "process": conn.get("process", conn.get("image", "")),
                "severity": "CRITICAL",
                "reason": "known_bad_port",
            })
        elif dst_port not in COMMON_PORTS and dst_port > 0:
            findings.append({
                "src_ip": conn.get("src_ip", conn.get("source_ip", "")),
                "dst_ip": conn.get("dst_ip", conn.get("dest_ip", "")),
                "dst_port": dst_port,
                "process": conn.get("process", conn.get("image", "")),
                "severity": "MEDIUM",
                "reason": "non_standard_port",
            })
    return findings


def detect_rare_destinations(connections, threshold=3):
    """Find rarely contacted external destinations."""
    dest_counts = Counter()
    dest_conns = defaultdict(list)
    for conn in connections:
        dst = conn.get("dst_ip", conn.get("dest_ip", ""))
        if dst and not is_private(dst):
            dest_counts[dst] += 1
            dest_conns[dst].append(conn)
    findings = []
    for dst, count in dest_counts.items():
        if count <= threshold:
            sample = dest_conns[dst][0]
            findings.append({
                "dst_ip": dst,
                "connection_count": count,
                "src_ip": sample.get("src_ip", sample.get("source_ip", "")),
                "process": sample.get("process", sample.get("image", "")),
                "severity": "HIGH",
                "reason": "rare_destination",
            })
    return sorted(findings, key=lambda x: x["connection_count"])


def detect_long_connections(connections, duration_threshold=3600):
    """Find unusually long-lived connections (potential C2)."""
    findings = []
    for conn in connections:
        duration = conn.get("duration", conn.get("connection_duration", 0))
        try:
            duration = float(duration)
        except (TypeError, ValueError):
            continue
        if duration > duration_threshold:
            findings.append({
                "src_ip": conn.get("src_ip", conn.get("source_ip", "")),
                "dst_ip": conn.get("dst_ip", conn.get("dest_ip", "")),
                "dst_port": conn.get("dest_port", conn.get("dst_port", "")),
                "duration_seconds": duration,
                "process": conn.get("process", conn.get("image", "")),
                "severity": "HIGH",
                "reason": "long_duration_connection",
            })
    return sorted(findings, key=lambda x: x["duration_seconds"], reverse=True)


def detect_high_frequency_beaconing(connections, interval_threshold=60):
    """Detect periodic connections suggestive of beaconing."""
    by_dest = defaultdict(list)
    for conn in connections:
        dst = conn.get("dst_ip", conn.get("dest_ip", ""))
        ts = conn.get("timestamp", conn.get("ts", ""))
        if dst and ts:
            try:
                t = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
                by_dest[dst].append(t)
            except (ValueError, TypeError):
                continue
    findings = []
    for dst, times in by_dest.items():
        if len(times) < 5:
            continue
        times.sort()
        intervals = [(times[i+1] - times[i]).total_seconds() for i in range(len(times)-1)]
        avg = sum(intervals) / len(intervals)
        if avg < 1:
            continue
        std = (sum((x - avg)**2 for x in intervals) / len(intervals)) ** 0.5
        cv = std / avg if avg > 0 else 999
        if cv < 0.3 and avg < interval_threshold:
            findings.append({
                "dst_ip": dst, "connection_count": len(times),
                "avg_interval_sec": round(avg, 2), "cv": round(cv, 3),
                "severity": "CRITICAL", "reason": "periodic_beaconing",
            })
    return findings


def main():
    parser = argparse.ArgumentParser(description="Unusual Network Connection Hunter")
    parser.add_argument("--log", required=True, help="JSON lines connection log")
    parser.add_argument("--output", default="unusual_network_hunt_report.json")
    parser.add_argument("--action", choices=[
        "ports", "rare", "long", "beacon", "full_analysis"
    ], default="full_analysis")
    args = parser.parse_args()

    conns = load_connection_logs(args.log)
    report = {"generated_at": datetime.utcnow().isoformat(), "total_connections": len(conns),
              "findings": {}}
    print(f"[+] Loaded {len(conns)} connections")

    if args.action in ("ports", "full_analysis"):
        f = detect_non_standard_ports(conns)
        report["findings"]["non_standard_ports"] = f
        print(f"[+] Non-standard port connections: {len(f)}")

    if args.action in ("rare", "full_analysis"):
        f = detect_rare_destinations(conns)
        report["findings"]["rare_destinations"] = f
        print(f"[+] Rare destinations: {len(f)}")

    if args.action in ("long", "full_analysis"):
        f = detect_long_connections(conns)
        report["findings"]["long_connections"] = f
        print(f"[+] Long-lived connections: {len(f)}")

    if args.action in ("beacon", "full_analysis"):
        f = detect_high_frequency_beaconing(conns)
        report["findings"]["beaconing"] = f
        print(f"[+] Beaconing patterns: {len(f)}")

    with open(args.output, "w") as fout:
        json.dump(report, fout, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
