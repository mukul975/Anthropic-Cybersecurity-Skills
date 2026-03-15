#!/usr/bin/env python3
"""Modbus command injection detection agent for ICS/SCADA environments.

Analyzes Modbus TCP traffic for unauthorized write operations, function code
abuse, and anomalous register access patterns using Zeek logs or pcap analysis.
"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime

MODBUS_FUNCTIONS = {
    1: ("Read Coils", "read"), 2: ("Read Discrete Inputs", "read"),
    3: ("Read Holding Registers", "read"), 4: ("Read Input Registers", "read"),
    5: ("Write Single Coil", "write"), 6: ("Write Single Register", "write"),
    15: ("Write Multiple Coils", "write"), 16: ("Write Multiple Registers", "write"),
    8: ("Diagnostics", "diagnostic"), 17: ("Report Server ID", "diagnostic"),
    22: ("Mask Write Register", "write"), 23: ("Read/Write Multiple", "write"),
    43: ("Read Device ID", "diagnostic"),
}

DANGEROUS_FUNCTIONS = {5, 6, 15, 16, 22, 23}
DIAGNOSTIC_FUNCTIONS = {8, 17, 43}


def parse_zeek_modbus_log(filepath):
    events = []
    with open(filepath, "r") as f:
        headers = None
        for line in f:
            if line.startswith("#fields"):
                headers = line.strip().split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            if not headers:
                continue
            fields = line.strip().split("\t")
            if len(fields) >= len(headers):
                events.append(dict(zip(headers, fields)))
    return events


def analyze_modbus_traffic(events, authorized_masters=None):
    findings = []
    fc_counter = Counter()
    write_ops = []
    src_dst = defaultdict(int)

    for evt in events:
        src = evt.get("id.orig_h", "")
        dst = evt.get("id.resp_h", "")
        fc_str = evt.get("func", evt.get("function", ""))
        try:
            fc = int(fc_str)
        except (ValueError, TypeError):
            continue

        fc_info = MODBUS_FUNCTIONS.get(fc, (f"Unknown({fc})", "unknown"))
        fc_counter[fc_info[0]] += 1
        src_dst[f"{src}->{dst}"] += 1

        if authorized_masters and src not in authorized_masters:
            findings.append({
                "type": "unauthorized_master",
                "source": src, "destination": dst,
                "function": fc_info[0], "function_code": fc,
                "severity": "CRITICAL" if fc in DANGEROUS_FUNCTIONS else "HIGH",
            })

        if fc in DANGEROUS_FUNCTIONS:
            write_ops.append({
                "timestamp": evt.get("ts", ""),
                "source": src, "destination": dst,
                "function": fc_info[0], "function_code": fc,
            })

        if fc not in MODBUS_FUNCTIONS:
            findings.append({
                "type": "unknown_function_code",
                "source": src, "function_code": fc,
                "severity": "HIGH",
                "description": f"Non-standard Modbus function code: {fc}",
            })

    return {
        "total_events": len(events),
        "function_distribution": dict(fc_counter),
        "write_operations": write_ops,
        "communication_pairs": dict(src_dst),
        "findings": findings,
    }


def detect_write_floods(events, threshold=20, window_seconds=60):
    findings = []
    src_writes = defaultdict(list)
    for evt in events:
        fc_str = evt.get("func", "0")
        try:
            fc = int(fc_str)
        except ValueError:
            continue
        if fc in DANGEROUS_FUNCTIONS:
            src = evt.get("id.orig_h", "")
            try:
                ts = float(evt.get("ts", "0"))
            except ValueError:
                continue
            src_writes[src].append(ts)

    for src, timestamps in src_writes.items():
        timestamps.sort()
        for i in range(len(timestamps) - threshold):
            if timestamps[i + threshold] - timestamps[i] <= window_seconds:
                findings.append({
                    "type": "write_flood",
                    "source": src,
                    "writes_in_window": threshold,
                    "window_seconds": window_seconds,
                    "severity": "CRITICAL",
                    "description": f">{threshold} write commands in {window_seconds}s from {src}",
                })
                break
    return findings


def main():
    parser = argparse.ArgumentParser(description="Modbus Command Injection Detector")
    parser.add_argument("--zeek-log", required=True, help="Zeek modbus.log file")
    parser.add_argument("--authorized-masters", nargs="+", help="Authorized master IPs")
    parser.add_argument("--flood-threshold", type=int, default=20)
    args = parser.parse_args()

    masters = set(args.authorized_masters) if args.authorized_masters else None
    events = parse_zeek_modbus_log(args.zeek_log)
    analysis = analyze_modbus_traffic(events, masters)
    floods = detect_write_floods(events, args.flood_threshold)

    results = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        **analysis,
        "write_floods": floods,
        "total_findings": len(analysis["findings"]) + len(floods),
    }
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
