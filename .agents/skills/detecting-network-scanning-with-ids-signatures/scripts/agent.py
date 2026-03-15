#!/usr/bin/env python3
"""Network scanning detection agent using IDS signature analysis.

Detects port scanning, host sweeps, and service enumeration by analyzing
Suricata/Snort alerts and connection logs for scanning patterns.
"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime

SCAN_SIGNATURES = {
    "SYN_SCAN": {"ports_threshold": 20, "severity": "HIGH", "mitre": "T1046"},
    "CONNECT_SCAN": {"ports_threshold": 15, "severity": "HIGH", "mitre": "T1046"},
    "UDP_SCAN": {"ports_threshold": 20, "severity": "MEDIUM", "mitre": "T1046"},
    "XMAS_SCAN": {"severity": "HIGH", "mitre": "T1046"},
    "FIN_SCAN": {"severity": "HIGH", "mitre": "T1046"},
    "NULL_SCAN": {"severity": "HIGH", "mitre": "T1046"},
    "HOST_SWEEP": {"hosts_threshold": 10, "severity": "MEDIUM", "mitre": "T1018"},
    "SERVICE_ENUM": {"severity": "MEDIUM", "mitre": "T1046"},
}

NMAP_SIGNATURES = [
    r"Nmap\s+Scripting\s+Engine", r"nmap", r"masscan",
    r"zmap", r"rustscan", r"unicornscan",
]


def parse_suricata_eve(filepath, event_type="alert"):
    events = []
    with open(filepath, "r") as f:
        for line in f:
            try:
                evt = json.loads(line.strip())
                if evt.get("event_type") == event_type:
                    events.append(evt)
            except json.JSONDecodeError:
                continue
    return events


def parse_connection_log(filepath):
    connections = []
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
                connections.append(dict(zip(headers, fields)))
    return connections


def detect_port_scan(connections, threshold=20):
    findings = []
    src_dst_ports = defaultdict(set)
    src_dst_count = defaultdict(int)

    for conn in connections:
        src = conn.get("id.orig_h", "")
        dst = conn.get("id.resp_h", "")
        port = conn.get("id.resp_p", "")
        state = conn.get("conn_state", "")

        src_dst_ports[f"{src}->{dst}"].add(port)
        src_dst_count[f"{src}->{dst}"] += 1

    for pair, ports in src_dst_ports.items():
        if len(ports) >= threshold:
            src = pair.split("->")[0]
            dst = pair.split("->")[1]
            findings.append({
                "type": "port_scan",
                "source": src, "destination": dst,
                "unique_ports": len(ports),
                "total_connections": src_dst_count[pair],
                "severity": "CRITICAL" if len(ports) > 100 else "HIGH",
                "mitre": "T1046",
            })
    return findings


def detect_host_sweep(connections, threshold=10):
    findings = []
    src_dsts = defaultdict(set)
    src_port = defaultdict(set)

    for conn in connections:
        src = conn.get("id.orig_h", "")
        dst = conn.get("id.resp_h", "")
        port = conn.get("id.resp_p", "")
        src_dsts[src].add(dst)
        src_port[f"{src}:{port}"].add(dst)

    for src_p, hosts in src_port.items():
        if len(hosts) >= threshold:
            src, port = src_p.rsplit(":", 1)
            findings.append({
                "type": "host_sweep",
                "source": src,
                "port": port,
                "unique_hosts": len(hosts),
                "severity": "HIGH" if len(hosts) > 50 else "MEDIUM",
                "mitre": "T1018",
            })
    return findings


def analyze_ids_alerts(alerts):
    findings = []
    for alert in alerts:
        sig = alert.get("alert", {}).get("signature", "")
        category = alert.get("alert", {}).get("category", "")
        src = alert.get("src_ip", "")
        dst = alert.get("dest_ip", "")
        severity = alert.get("alert", {}).get("severity", 3)

        for pattern in NMAP_SIGNATURES:
            if re.search(pattern, sig, re.IGNORECASE):
                findings.append({
                    "type": "scanner_detected",
                    "tool": pattern.replace("\\s+", " "),
                    "source": src, "destination": dst,
                    "signature": sig,
                    "severity": "HIGH",
                    "mitre": "T1046",
                })

        if "scan" in category.lower() or "scan" in sig.lower():
            findings.append({
                "type": "ids_scan_alert",
                "source": src, "destination": dst,
                "signature": sig, "category": category,
                "severity": "HIGH" if severity <= 2 else "MEDIUM",
            })
    return findings


def main():
    parser = argparse.ArgumentParser(description="Network Scanning Detector")
    parser.add_argument("--eve-log", help="Suricata EVE JSON log")
    parser.add_argument("--conn-log", help="Zeek conn.log file")
    parser.add_argument("--port-threshold", type=int, default=20)
    parser.add_argument("--sweep-threshold", type=int, default=10)
    args = parser.parse_args()

    results = {"timestamp": datetime.utcnow().isoformat() + "Z", "findings": []}

    if args.eve_log:
        alerts = parse_suricata_eve(args.eve_log)
        results["findings"].extend(analyze_ids_alerts(alerts))

    if args.conn_log:
        connections = parse_connection_log(args.conn_log)
        results["findings"].extend(detect_port_scan(connections, args.port_threshold))
        results["findings"].extend(detect_host_sweep(connections, args.sweep_threshold))

    results["total_findings"] = len(results["findings"])
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
