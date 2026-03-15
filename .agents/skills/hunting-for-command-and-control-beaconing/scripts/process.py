#!/usr/bin/env python3
"""
C2 Beaconing Detection Script
Analyzes network connection logs for periodic beaconing patterns
using statistical frequency analysis and jitter detection.
"""

import json
import csv
import argparse
import datetime
import math
import re
from collections import defaultdict
from pathlib import Path

# Known legitimate beaconing services to exclude
KNOWN_GOOD_DOMAINS = {
    "microsoft.com", "windowsupdate.com", "google.com", "googleapis.com",
    "gstatic.com", "amazonaws.com", "cloudflare.com", "akamai.net",
    "apple.com", "icloud.com", "adobe.com", "symantec.com",
    "norton.com", "mcafee.com", "crowdstrike.com", "sentinelone.com",
    "office365.com", "office.com", "live.com", "outlook.com",
    "github.com", "slack.com", "teams.microsoft.com",
}

# Known C2 framework default ports
C2_SUSPICIOUS_PORTS = {443, 8443, 8080, 4444, 5555, 6666, 8888, 9090, 50050, 31337}

# Beaconing detection thresholds
BEACON_THRESHOLDS = {
    "min_connections": 20,       # Minimum connections for analysis
    "max_cv": 0.25,              # Max coefficient of variation for periodicity
    "min_interval": 10,          # Minimum average interval (seconds)
    "max_interval": 86400,       # Maximum average interval (1 day)
    "max_data_cv": 0.30,         # Max CV for data size consistency
}


def parse_logs(input_path: str) -> list[dict]:
    """Parse connection logs (Zeek, CSV, JSON format)."""
    path = Path(input_path)
    events = []

    if path.suffix == ".json":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            events = data if isinstance(data, list) else data.get("events", [])
    elif path.suffix == ".csv":
        with open(path, "r", encoding="utf-8-sig") as f:
            events = [dict(row) for row in csv.DictReader(f)]
    elif path.suffix == ".log":
        # Zeek tab-separated format
        with open(path, "r", encoding="utf-8") as f:
            headers = None
            for line in f:
                if line.startswith("#fields"):
                    headers = line.strip().split("\t")[1:]
                elif line.startswith("#"):
                    continue
                elif headers:
                    values = line.strip().split("\t")
                    if len(values) == len(headers):
                        events.append(dict(zip(headers, values)))
    return events


def normalize_connection(event: dict) -> dict:
    """Normalize connection event fields."""
    field_map = {
        "timestamp": ["ts", "timestamp", "_time", "@timestamp", "Timestamp"],
        "src_ip": ["id.orig_h", "src_ip", "source_ip", "LocalIP", "DeviceName"],
        "src_port": ["id.orig_p", "src_port", "source_port", "LocalPort"],
        "dst_ip": ["id.resp_h", "dst_ip", "dest_ip", "RemoteIP", "DestinationIp"],
        "dst_port": ["id.resp_p", "dst_port", "dest_port", "RemotePort", "DestinationPort"],
        "domain": ["query", "domain", "host", "RemoteUrl", "server_name", "dest"],
        "bytes_sent": ["orig_bytes", "bytes_out", "SentBytes", "bytes_sent"],
        "bytes_recv": ["resp_bytes", "bytes_in", "ReceivedBytes", "bytes_recv"],
        "duration": ["duration", "conn_duration", "session_duration"],
        "proto": ["proto", "protocol", "Protocol"],
        "user_agent": ["user_agent", "UserAgent", "http_user_agent"],
    }
    normalized = {}
    for target, sources in field_map.items():
        for src in sources:
            if src in event and event[src] and event[src] != "-":
                normalized[target] = str(event[src])
                break
        if target not in normalized:
            normalized[target] = ""
    return normalized


def is_known_good(domain: str) -> bool:
    """Check if domain is in known-good list."""
    domain_lower = domain.lower()
    for good in KNOWN_GOOD_DOMAINS:
        if domain_lower.endswith(good):
            return True
    return False


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = defaultdict(int)
    for char in text:
        freq[char] += 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def detect_beaconing(connections: list[dict]) -> list[dict]:
    """Analyze connection patterns for beaconing behavior."""
    # Group connections by source-destination pair
    pairs = defaultdict(list)
    for conn in connections:
        src = conn.get("src_ip", "")
        dst = conn.get("domain", "") or conn.get("dst_ip", "")
        if src and dst and not is_known_good(dst):
            try:
                ts = float(conn.get("timestamp", 0))
            except (ValueError, TypeError):
                # Try parsing ISO timestamp
                try:
                    dt = datetime.datetime.fromisoformat(conn["timestamp"].replace("Z", "+00:00"))
                    ts = dt.timestamp()
                except (ValueError, KeyError):
                    continue
            pairs[(src, dst)].append({
                "timestamp": ts,
                "bytes_sent": int(conn.get("bytes_sent", 0) or 0),
                "bytes_recv": int(conn.get("bytes_recv", 0) or 0),
                "dst_port": conn.get("dst_port", ""),
                "user_agent": conn.get("user_agent", ""),
            })

    findings = []

    for (src, dst), conns in pairs.items():
        if len(conns) < BEACON_THRESHOLDS["min_connections"]:
            continue

        # Sort by timestamp
        conns.sort(key=lambda x: x["timestamp"])

        # Calculate intervals
        intervals = []
        for i in range(1, len(conns)):
            interval = conns[i]["timestamp"] - conns[i - 1]["timestamp"]
            if interval > 0:
                intervals.append(interval)

        if len(intervals) < 10:
            continue

        # Statistical analysis
        avg_interval = sum(intervals) / len(intervals)
        if avg_interval < BEACON_THRESHOLDS["min_interval"] or avg_interval > BEACON_THRESHOLDS["max_interval"]:
            continue

        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
        stdev = math.sqrt(variance)
        cv = stdev / avg_interval if avg_interval > 0 else float("inf")

        # Check if beaconing threshold met
        if cv > BEACON_THRESHOLDS["max_cv"]:
            continue

        # Calculate data size consistency
        bytes_sent_list = [c["bytes_sent"] for c in conns if c["bytes_sent"] > 0]
        data_cv = 0.0
        if bytes_sent_list:
            avg_bytes = sum(bytes_sent_list) / len(bytes_sent_list)
            if avg_bytes > 0:
                data_var = sum((x - avg_bytes) ** 2 for x in bytes_sent_list) / len(bytes_sent_list)
                data_cv = math.sqrt(data_var) / avg_bytes

        # Calculate risk score
        risk = 0
        indicators = []

        # Low CV = high periodicity
        if cv < 0.05:
            risk += 40
            indicators.append(f"Very regular interval (CV={cv:.4f})")
        elif cv < 0.15:
            risk += 30
            indicators.append(f"Regular interval (CV={cv:.4f})")
        else:
            risk += 20
            indicators.append(f"Moderately regular interval (CV={cv:.4f})")

        # Consistent data sizes
        if data_cv < 0.10 and bytes_sent_list:
            risk += 15
            indicators.append(f"Very consistent payload size (CV={data_cv:.4f})")

        # Suspicious port
        dst_ports = set(c["dst_port"] for c in conns)
        for port in dst_ports:
            try:
                if int(port) in C2_SUSPICIOUS_PORTS:
                    risk += 10
                    indicators.append(f"Suspicious port: {port}")
            except ValueError:
                pass

        # High connection count
        if len(conns) > 500:
            risk += 10
            indicators.append(f"High connection count: {len(conns)}")

        # Domain entropy (DGA indicator)
        domain_parts = dst.split(".")
        if domain_parts:
            entropy = calculate_entropy(domain_parts[0])
            if entropy > 3.5:
                risk += 15
                indicators.append(f"High domain entropy: {entropy:.2f} (possible DGA)")

        risk_level = (
            "CRITICAL" if risk >= 70 else "HIGH" if risk >= 50
            else "MEDIUM" if risk >= 30 else "LOW"
        )

        # Estimate jitter percentage
        jitter_pct = (stdev / avg_interval * 100) if avg_interval > 0 else 0

        findings.append({
            "src_ip": src,
            "destination": dst,
            "connection_count": len(conns),
            "avg_interval_sec": round(avg_interval, 2),
            "stdev_interval": round(stdev, 2),
            "coefficient_of_variation": round(cv, 4),
            "estimated_jitter_pct": round(jitter_pct, 1),
            "avg_bytes_sent": round(sum(bytes_sent_list) / len(bytes_sent_list)) if bytes_sent_list else 0,
            "data_size_cv": round(data_cv, 4),
            "first_seen": datetime.datetime.fromtimestamp(conns[0]["timestamp"]).isoformat(),
            "last_seen": datetime.datetime.fromtimestamp(conns[-1]["timestamp"]).isoformat(),
            "dst_ports": list(dst_ports),
            "risk_score": risk,
            "risk_level": risk_level,
            "indicators": indicators,
        })

    return sorted(findings, key=lambda x: x["risk_score"], reverse=True)


def detect_dns_tunneling(connections: list[dict]) -> list[dict]:
    """Detect DNS tunneling indicators."""
    domain_stats = defaultdict(lambda: {"queries": 0, "unique_subdomains": set(), "total_length": 0, "txt_queries": 0})

    for conn in connections:
        domain = conn.get("domain", "")
        if not domain:
            continue

        parts = domain.split(".")
        if len(parts) < 3:
            continue

        base_domain = ".".join(parts[-2:])
        subdomain = ".".join(parts[:-2])

        stats = domain_stats[base_domain]
        stats["queries"] += 1
        stats["unique_subdomains"].add(subdomain)
        stats["total_length"] += len(domain)

    findings = []
    for base_domain, stats in domain_stats.items():
        if stats["queries"] < 50:
            continue

        avg_len = stats["total_length"] / stats["queries"]
        unique_subs = len(stats["unique_subdomains"])

        risk = 0
        indicators = []

        if unique_subs > 100:
            risk += 30
            indicators.append(f"High unique subdomain count: {unique_subs}")
        if avg_len > 40:
            risk += 25
            indicators.append(f"Long average query length: {avg_len:.1f}")
        if stats["queries"] > 500:
            risk += 15
            indicators.append(f"High query volume: {stats['queries']}")

        # Check subdomain entropy
        for sub in list(stats["unique_subdomains"])[:10]:
            ent = calculate_entropy(sub)
            if ent > 3.5:
                risk += 20
                indicators.append(f"High subdomain entropy: {ent:.2f}")
                break

        if risk >= 30:
            risk_level = "CRITICAL" if risk >= 70 else "HIGH" if risk >= 50 else "MEDIUM"
            findings.append({
                "detection_type": "DNS_TUNNELING",
                "domain": base_domain,
                "query_count": stats["queries"],
                "unique_subdomains": unique_subs,
                "avg_query_length": round(avg_len, 1),
                "risk_score": risk,
                "risk_level": risk_level,
                "indicators": indicators,
            })

    return sorted(findings, key=lambda x: x["risk_score"], reverse=True)


def run_hunt(input_path: str, output_dir: str) -> None:
    """Execute C2 beaconing hunt."""
    print(f"[*] C2 Beaconing Hunt - {datetime.datetime.now().isoformat()}")

    connections = parse_logs(input_path)
    normalized = [normalize_connection(c) for c in connections]
    print(f"[*] Loaded {len(normalized)} connections")

    beacon_findings = detect_beaconing(normalized)
    dns_findings = detect_dns_tunneling(normalized)
    all_findings = beacon_findings + dns_findings

    print(f"[*] Beacon detections: {len(beacon_findings)}")
    print(f"[*] DNS tunnel detections: {len(dns_findings)}")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    with open(output_path / "c2_beacon_findings.json", "w", encoding="utf-8") as f:
        json.dump({
            "hunt_id": f"TH-C2-{datetime.date.today().isoformat()}",
            "total_connections": len(normalized),
            "beacon_findings": len(beacon_findings),
            "dns_tunnel_findings": len(dns_findings),
            "findings": all_findings,
        }, f, indent=2)

    with open(output_path / "hunt_report.md", "w", encoding="utf-8") as f:
        f.write(f"# C2 Beaconing Hunt Report\n\n")
        f.write(f"**Date**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Connections Analyzed**: {len(normalized)}\n\n")
        f.write("## Beaconing Detections\n\n")
        for bf in beacon_findings[:20]:
            f.write(f"### [{bf['risk_level']}] {bf['src_ip']} -> {bf['destination']}\n")
            f.write(f"- Interval: {bf['avg_interval_sec']}s (CV: {bf['coefficient_of_variation']})\n")
            f.write(f"- Jitter: ~{bf['estimated_jitter_pct']}%\n")
            f.write(f"- Connections: {bf['connection_count']}\n\n")
        f.write("## DNS Tunneling Detections\n\n")
        for df in dns_findings[:10]:
            f.write(f"### [{df['risk_level']}] {df['domain']}\n")
            f.write(f"- Queries: {df['query_count']}, Unique Subdomains: {df['unique_subdomains']}\n\n")

    print(f"[+] Results written to {output_dir}")


def main():
    parser = argparse.ArgumentParser(description="C2 Beaconing Detection")
    subparsers = parser.add_subparsers(dest="command")

    hunt_p = subparsers.add_parser("hunt")
    hunt_p.add_argument("--input", "-i", required=True)
    hunt_p.add_argument("--output", "-o", default="./c2_hunt_output")

    subparsers.add_parser("queries", help="Print hunting queries")

    args = parser.parse_args()

    if args.command == "hunt":
        run_hunt(args.input, args.output)
    elif args.command == "queries":
        print("=== Splunk Beaconing Queries ===\n")
        print("--- HTTP/S Beacon Frequency ---")
        print("""index=proxy
| bin _time span=1s
| stats count by src_ip dest _time
| streamstats current=f last(_time) as prev_time by src_ip dest
| eval interval=_time-prev_time
| stats count avg(interval) as avg stdev(interval) as sd by src_ip dest
| eval cv=sd/avg
| where count>50 AND cv<0.20 AND avg>30
| sort cv""")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
