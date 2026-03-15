#!/usr/bin/env python3
"""Detect ransomware network indicators: C2 beaconing, TOR connections, data exfiltration via Zeek/NetFlow."""

import json
import csv
import math
import argparse
import urllib.request
from datetime import datetime
from collections import defaultdict, Counter
from statistics import mean, stdev

TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"


def parse_zeek_conn_log(log_path):
    """Parse Zeek conn.log TSV format into structured records."""
    connections = []
    with open(log_path) as f:
        headers = None
        for line in f:
            if line.startswith("#fields"):
                headers = line.strip().split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            if headers:
                fields = line.strip().split("\t")
                record = {}
                for i, h in enumerate(headers):
                    record[h] = fields[i] if i < len(fields) else "-"
                connections.append(record)
    return connections


def parse_netflow_csv(log_path):
    """Parse NetFlow CSV export into connection records."""
    connections = []
    with open(log_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            connections.append({
                "ts": row.get("timestamp", row.get("start_time", "")),
                "id.orig_h": row.get("src_ip", row.get("sa", "")),
                "id.resp_h": row.get("dst_ip", row.get("da", "")),
                "id.resp_p": row.get("dst_port", row.get("dp", "")),
                "proto": row.get("protocol", row.get("pr", "")),
                "orig_bytes": row.get("src_bytes", row.get("ibyt", "0")),
                "resp_bytes": row.get("dst_bytes", row.get("obyt", "0")),
                "duration": row.get("duration", row.get("td", "0")),
            })
    return connections


def fetch_tor_exit_nodes():
    """Fetch current TOR exit node IP list from Tor Project."""
    try:
        req = urllib.request.Request(TOR_EXIT_LIST_URL, headers={"User-Agent": "SecurityAgent/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            nodes = set()
            for line in resp.read().decode().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    nodes.add(line)
            return nodes
    except Exception as e:
        return set()


def detect_beaconing(connections, min_connections=10, max_cv=0.3):
    """Detect C2 beaconing by analyzing connection interval regularity."""
    pair_timestamps = defaultdict(list)
    for conn in connections:
        src = conn.get("id.orig_h", "")
        dst = conn.get("id.resp_h", "")
        port = conn.get("id.resp_p", "")
        ts = conn.get("ts", "")
        if src and dst and ts != "-":
            try:
                pair_timestamps[(src, dst, port)].append(float(ts))
            except (ValueError, TypeError):
                continue

    beacons = []
    for (src, dst, port), timestamps in pair_timestamps.items():
        if len(timestamps) < min_connections:
            continue
        timestamps.sort()
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        if not intervals:
            continue
        avg_interval = mean(intervals)
        if avg_interval == 0:
            continue
        sd = stdev(intervals) if len(intervals) > 1 else 0
        cv = sd / avg_interval if avg_interval > 0 else 999

        if cv <= max_cv:
            beacons.append({
                "source": src, "destination": dst, "port": port,
                "connection_count": len(timestamps),
                "avg_interval_seconds": round(avg_interval, 2),
                "interval_stddev": round(sd, 2),
                "coefficient_of_variation": round(cv, 4),
                "severity": "critical" if cv < 0.1 else "high",
                "indicator": "Regular beaconing pattern detected",
                "mitre": "T1071",
            })
    return beacons


def detect_tor_connections(connections, tor_nodes):
    """Cross-reference connections against TOR exit node list."""
    tor_hits = []
    for conn in connections:
        dst = conn.get("id.resp_h", "")
        src = conn.get("id.orig_h", "")
        if dst in tor_nodes:
            tor_hits.append({
                "source": src, "destination": dst,
                "port": conn.get("id.resp_p", ""),
                "bytes_sent": conn.get("orig_bytes", "0"),
                "severity": "high",
                "indicator": "Connection to TOR exit node",
                "mitre": "T1573",
            })
    unique_tor = len({h["destination"] for h in tor_hits})
    return tor_hits, unique_tor


def detect_exfiltration(connections, byte_threshold=100_000_000):
    """Detect potential data exfiltration by high outbound byte transfer."""
    pair_bytes = defaultdict(lambda: {"sent": 0, "received": 0, "count": 0})
    for conn in connections:
        src = conn.get("id.orig_h", "")
        dst = conn.get("id.resp_h", "")
        if not src or not dst:
            continue
        if dst.startswith(("10.", "192.168.", "172.16.", "127.")):
            continue
        try:
            sent = int(conn.get("orig_bytes", 0)) if conn.get("orig_bytes", "-") != "-" else 0
            recv = int(conn.get("resp_bytes", 0)) if conn.get("resp_bytes", "-") != "-" else 0
        except ValueError:
            continue
        pair_bytes[(src, dst)]["sent"] += sent
        pair_bytes[(src, dst)]["received"] += recv
        pair_bytes[(src, dst)]["count"] += 1

    exfil_alerts = []
    for (src, dst), stats in pair_bytes.items():
        if stats["sent"] > byte_threshold:
            ratio = stats["sent"] / max(stats["received"], 1)
            exfil_alerts.append({
                "source": src, "destination": dst,
                "bytes_sent": stats["sent"],
                "bytes_received": stats["received"],
                "send_receive_ratio": round(ratio, 2),
                "connection_count": stats["count"],
                "severity": "critical" if stats["sent"] > byte_threshold * 5 else "high",
                "indicator": "High outbound data transfer (potential exfiltration)",
                "mitre": "T1041",
            })
    return exfil_alerts


def generate_report(connections, beacons, tor_hits, tor_unique, exfil_alerts, source):
    """Generate ransomware network indicator report."""
    total_alerts = len(beacons) + len(tor_hits) + len(exfil_alerts)
    risk_score = min(100, len(beacons) * 20 + tor_unique * 15 + len(exfil_alerts) * 25)
    return {
        "report_time": datetime.utcnow().isoformat(),
        "log_source": source,
        "total_connections": len(connections),
        "ransomware_risk_score": risk_score,
        "risk_level": "critical" if risk_score >= 70 else "high" if risk_score >= 40 else "medium",
        "beaconing_detections": beacons,
        "tor_connection_alerts": len(tor_hits),
        "tor_unique_nodes": tor_unique,
        "tor_hits_sample": tor_hits[:10],
        "exfiltration_alerts": exfil_alerts,
        "mitre_techniques": ["T1071", "T1573", "T1041", "T1486"],
        "total_alerts": total_alerts,
    }


def main():
    parser = argparse.ArgumentParser(description="Ransomware Network Indicator Analyzer")
    parser.add_argument("--input", required=True, help="Zeek conn.log or NetFlow CSV file")
    parser.add_argument("--format", choices=["zeek", "netflow"], default="zeek")
    parser.add_argument("--output", default="ransomware_network_report.json")
    parser.add_argument("--beacon-min", type=int, default=10, help="Min connections for beaconing")
    parser.add_argument("--exfil-threshold", type=int, default=100_000_000, help="Exfil byte threshold")
    parser.add_argument("--skip-tor", action="store_true", help="Skip TOR exit node check")
    args = parser.parse_args()

    if args.format == "zeek":
        connections = parse_zeek_conn_log(args.input)
    else:
        connections = parse_netflow_csv(args.input)

    print(f"[*] Parsed {len(connections)} connections from {args.input}")
    beacons = detect_beaconing(connections, min_connections=args.beacon_min)
    tor_nodes = set() if args.skip_tor else fetch_tor_exit_nodes()
    tor_hits, tor_unique = detect_tor_connections(connections, tor_nodes)
    exfil_alerts = detect_exfiltration(connections, args.exfil_threshold)

    report = generate_report(connections, beacons, tor_hits, tor_unique, exfil_alerts, args.input)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Beaconing: {len(beacons)} | TOR: {len(tor_hits)} ({tor_unique} nodes) | Exfil: {len(exfil_alerts)}")
    print(f"[+] Ransomware risk score: {report['ransomware_risk_score']}/100 ({report['risk_level']})")
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
