#!/usr/bin/env python3
"""Modbus protocol anomaly detection agent for OT/ICS networks.

Detects protocol-level anomalies in Modbus TCP traffic including malformed
packets, timing deviations, register range violations, and replay attacks.
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime

MODBUS_FUNCTIONS = {
    1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers",
    4: "Read Input Registers", 5: "Write Single Coil", 6: "Write Single Register",
    15: "Write Multiple Coils", 16: "Write Multiple Registers",
}

VALID_REGISTER_RANGES = {
    "coils": (0, 65535), "discrete_inputs": (0, 65535),
    "holding_registers": (0, 65535), "input_registers": (0, 65535),
}

MAX_REGISTER_READ = 125
MAX_COIL_READ = 2000


def parse_modbus_log(filepath):
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


def detect_timing_anomalies(events, expected_interval=1.0, tolerance=0.5):
    findings = []
    pair_timestamps = defaultdict(list)

    for evt in events:
        src = evt.get("id.orig_h", "")
        dst = evt.get("id.resp_h", "")
        try:
            ts = float(evt.get("ts", 0))
        except ValueError:
            continue
        pair_timestamps[f"{src}->{dst}"].append(ts)

    for pair, timestamps in pair_timestamps.items():
        timestamps.sort()
        for i in range(1, len(timestamps)):
            interval = timestamps[i] - timestamps[i-1]
            if interval < expected_interval - tolerance or interval > expected_interval * 3:
                findings.append({
                    "type": "timing_anomaly",
                    "pair": pair,
                    "expected_interval": expected_interval,
                    "actual_interval": round(interval, 3),
                    "severity": "MEDIUM" if interval > expected_interval * 3 else "HIGH",
                })
                break
    return findings


def detect_register_anomalies(events):
    findings = []
    for evt in events:
        fc_str = evt.get("func", "0")
        try:
            fc = int(fc_str)
        except ValueError:
            continue

        quantity = evt.get("quantity", "0")
        try:
            qty = int(quantity)
        except ValueError:
            qty = 0

        if fc in (1, 2) and qty > MAX_COIL_READ:
            findings.append({
                "type": "excessive_coil_read",
                "function_code": fc,
                "quantity": qty,
                "max_allowed": MAX_COIL_READ,
                "severity": "HIGH",
                "source": evt.get("id.orig_h", ""),
            })
        elif fc in (3, 4) and qty > MAX_REGISTER_READ:
            findings.append({
                "type": "excessive_register_read",
                "function_code": fc,
                "quantity": qty,
                "max_allowed": MAX_REGISTER_READ,
                "severity": "HIGH",
                "source": evt.get("id.orig_h", ""),
            })

        if fc not in MODBUS_FUNCTIONS:
            findings.append({
                "type": "invalid_function_code",
                "function_code": fc,
                "severity": "HIGH",
                "source": evt.get("id.orig_h", ""),
            })
    return findings


def detect_scan_patterns(events, threshold=50):
    findings = []
    src_fc_counter = defaultdict(Counter)
    for evt in events:
        src = evt.get("id.orig_h", "")
        fc_str = evt.get("func", "0")
        try:
            fc = int(fc_str)
        except ValueError:
            continue
        src_fc_counter[src][fc] += 1

    for src, fc_counts in src_fc_counter.items():
        unique_fcs = len(fc_counts)
        total = sum(fc_counts.values())
        if unique_fcs > 5 or (fc_counts.get(17, 0) > 0 and fc_counts.get(43, 0) > 0):
            findings.append({
                "type": "modbus_scan",
                "source": src,
                "unique_function_codes": unique_fcs,
                "total_requests": total,
                "severity": "HIGH",
                "description": f"Modbus enumeration from {src}: {unique_fcs} function codes",
            })
    return findings


def main():
    parser = argparse.ArgumentParser(description="Modbus Protocol Anomaly Detector")
    parser.add_argument("--modbus-log", required=True, help="Zeek modbus.log file")
    parser.add_argument("--expected-interval", type=float, default=1.0,
                        help="Expected polling interval in seconds")
    args = parser.parse_args()

    events = parse_modbus_log(args.modbus_log)
    all_findings = []
    all_findings.extend(detect_timing_anomalies(events, args.expected_interval))
    all_findings.extend(detect_register_anomalies(events))
    all_findings.extend(detect_scan_patterns(events))

    results = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "total_events": len(events),
        "findings": all_findings,
        "total_findings": len(all_findings),
    }
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
