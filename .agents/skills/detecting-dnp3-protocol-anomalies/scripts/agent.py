#!/usr/bin/env python3
"""DNP3 protocol anomaly detection agent for ICS/SCADA environments.

Analyzes DNP3 network traffic captures (via Zeek or pcap) to detect
unauthorized control commands, protocol violations, and traffic anomalies.
"""

import argparse
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime

DNP3_FUNCTION_CODES = {
    0x01: ("READ", "normal"), 0x02: ("WRITE", "caution"),
    0x03: ("SELECT", "caution"), 0x04: ("OPERATE", "critical"),
    0x05: ("DIRECT_OPERATE", "critical"), 0x06: ("DIRECT_OPERATE_NR", "critical"),
    0x0D: ("COLD_RESTART", "critical"), 0x0E: ("WARM_RESTART", "critical"),
    0x0F: ("INITIALIZE_DATA", "critical"), 0x10: ("INITIALIZE_APPLICATION", "critical"),
    0x11: ("START_APPLICATION", "critical"), 0x12: ("STOP_APPLICATION", "critical"),
    0x14: ("ENABLE_UNSOLICITED", "caution"), 0x15: ("DISABLE_UNSOLICITED", "caution"),
    0x18: ("RECORD_CURRENT_TIME", "normal"),
    0x81: ("RESPONSE", "normal"), 0x82: ("UNSOLICITED_RESPONSE", "normal"),
}

AUTHORIZED_MASTERS = set()
AUTHORIZED_OUTSTATIONS = set()


def load_authorized_hosts(filepath):
    hosts = set()
    if filepath:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    hosts.add(line)
    return hosts


def parse_zeek_dnp3_log(filepath):
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
                evt = dict(zip(headers, fields))
                events.append(evt)
    return events


def analyze_dnp3_traffic(events, authorized_masters, authorized_outstations):
    findings = []
    fc_counter = Counter()
    src_dst_pairs = defaultdict(int)
    critical_ops = []

    for evt in events:
        src = evt.get("id.orig_h", evt.get("src_ip", ""))
        dst = evt.get("id.resp_h", evt.get("dst_ip", ""))
        fc_str = evt.get("fc_request", evt.get("function_code", ""))

        try:
            fc = int(fc_str, 16) if fc_str.startswith("0x") else int(fc_str)
        except (ValueError, TypeError):
            fc = -1

        fc_info = DNP3_FUNCTION_CODES.get(fc, ("UNKNOWN", "caution"))
        fc_counter[fc_info[0]] += 1
        src_dst_pairs[f"{src}->{dst}"] += 1

        if authorized_masters and src not in authorized_masters:
            findings.append({
                "type": "unauthorized_master",
                "source": src, "destination": dst,
                "function_code": fc_info[0],
                "severity": "CRITICAL",
                "description": f"DNP3 command from unauthorized master {src}",
            })

        if fc_info[1] == "critical":
            critical_ops.append({
                "timestamp": evt.get("ts", ""),
                "source": src, "destination": dst,
                "function_code": fc_info[0],
                "severity": "HIGH",
            })
            findings.append({
                "type": "critical_control_command",
                "source": src, "destination": dst,
                "function_code": fc_info[0],
                "severity": "HIGH",
                "description": f"Critical DNP3 operation: {fc_info[0]}",
            })

    return {
        "total_events": len(events),
        "function_code_distribution": dict(fc_counter),
        "communication_pairs": dict(src_dst_pairs),
        "critical_operations": critical_ops,
        "findings": findings,
    }


def detect_protocol_anomalies(events):
    anomalies = []
    burst_window = defaultdict(list)

    for evt in events:
        ts = evt.get("ts", "0")
        src = evt.get("id.orig_h", "")
        try:
            timestamp = float(ts)
        except ValueError:
            continue
        burst_window[src].append(timestamp)

    for src, timestamps in burst_window.items():
        timestamps.sort()
        for i in range(len(timestamps) - 10):
            window = timestamps[i + 10] - timestamps[i]
            if window < 1.0:
                anomalies.append({
                    "type": "burst_traffic",
                    "source": src,
                    "events_per_second": round(10 / max(window, 0.001), 1),
                    "severity": "HIGH",
                    "description": f"DNP3 traffic burst from {src}: >10 events/sec",
                })
                break
    return anomalies


def main():
    parser = argparse.ArgumentParser(description="DNP3 Protocol Anomaly Detector")
    parser.add_argument("--zeek-log", required=True, help="Zeek DNP3 log file")
    parser.add_argument("--authorized-masters", help="File with authorized master IPs")
    parser.add_argument("--authorized-outstations", help="File with authorized outstation IPs")
    args = parser.parse_args()

    masters = load_authorized_hosts(args.authorized_masters)
    outstations = load_authorized_hosts(args.authorized_outstations)
    events = parse_zeek_dnp3_log(args.zeek_log)
    traffic_analysis = analyze_dnp3_traffic(events, masters, outstations)
    anomalies = detect_protocol_anomalies(events)

    results = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        **traffic_analysis,
        "protocol_anomalies": anomalies,
        "total_findings": len(traffic_analysis["findings"]) + len(anomalies),
    }
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
