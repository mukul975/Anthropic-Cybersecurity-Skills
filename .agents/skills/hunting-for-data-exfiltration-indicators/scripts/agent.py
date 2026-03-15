#!/usr/bin/env python3
"""Agent for hunting data exfiltration indicators in network traffic."""

import argparse
import csv
import json
import math
import sys
from collections import defaultdict
from datetime import datetime, timezone


DNS_EXFIL_ENTROPY_THRESHOLD = 3.5
DNS_LABEL_LENGTH_THRESHOLD = 40
LARGE_UPLOAD_THRESHOLD_MB = 50

SUSPICIOUS_PORTS = {
    20: "FTP Data", 21: "FTP", 22: "SSH/SCP", 53: "DNS",
    443: "HTTPS", 993: "IMAPS", 995: "POP3S",
    8443: "Alt HTTPS", 6667: "IRC",
}


def shannon_entropy(data):
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for c in data:
        freq[c] += 1
    length = len(data)
    return -sum((count/length) * math.log2(count/length) for count in freq.values())


def analyze_dns_queries(filepath):
    """Analyze DNS query log for exfiltration indicators."""
    findings = []
    domain_stats = defaultdict(lambda: {"count": 0, "total_length": 0, "queries": []})
    try:
        with open(filepath, "r") as f:
            reader = csv.DictReader(f, delimiter="\t")
            for row in reader:
                query = row.get("query", "")
                if not query:
                    continue
                parts = query.split(".")
                if len(parts) < 2:
                    continue
                domain = ".".join(parts[-2:])
                subdomain = ".".join(parts[:-2])
                domain_stats[domain]["count"] += 1
                domain_stats[domain]["total_length"] += len(subdomain)
                domain_stats[domain]["queries"].append(subdomain)
    except (OSError, csv.Error):
        return findings

    for domain, stats in domain_stats.items():
        if stats["count"] < 5:
            continue
        avg_subdomain_len = stats["total_length"] / stats["count"]
        all_subdomains = "".join(stats["queries"])
        entropy = shannon_entropy(all_subdomains)
        if entropy > DNS_EXFIL_ENTROPY_THRESHOLD and avg_subdomain_len > 20:
            findings.append({
                "type": "dns_exfiltration",
                "domain": domain,
                "query_count": stats["count"],
                "avg_subdomain_length": round(avg_subdomain_len, 1),
                "entropy": round(entropy, 3),
                "severity": "CRITICAL",
            })
    return findings


def analyze_network_flows(filepath):
    """Analyze network flow data for large outbound transfers."""
    findings = []
    dest_bytes = defaultdict(int)
    try:
        with open(filepath, "r") as f:
            reader = csv.DictReader(f, delimiter="\t")
            for row in reader:
                dst = row.get("id.resp_h", row.get("dst", ""))
                orig_bytes = int(row.get("orig_bytes", 0) or 0)
                dest_bytes[dst] += orig_bytes
    except (OSError, csv.Error, ValueError):
        return findings

    for dst, total in dest_bytes.items():
        mb = total / (1024 * 1024)
        if mb >= LARGE_UPLOAD_THRESHOLD_MB:
            findings.append({
                "type": "large_outbound_transfer",
                "destination": dst,
                "total_bytes": total,
                "total_mb": round(mb, 2),
                "severity": "HIGH",
            })
    return findings


def analyze_off_hours_traffic(filepath):
    """Check for significant data transfers during off-hours."""
    findings = []
    off_hours_transfers = defaultdict(int)
    try:
        with open(filepath, "r") as f:
            reader = csv.DictReader(f, delimiter="\t")
            for row in reader:
                ts = float(row.get("ts", 0))
                hour = datetime.fromtimestamp(ts).hour
                if hour < 6 or hour > 22:
                    dst = row.get("id.resp_h", row.get("dst", ""))
                    orig_bytes = int(row.get("orig_bytes", 0) or 0)
                    off_hours_transfers[dst] += orig_bytes
    except (OSError, csv.Error, ValueError):
        return findings

    for dst, total in off_hours_transfers.items():
        mb = total / (1024 * 1024)
        if mb >= 10:
            findings.append({
                "type": "off_hours_transfer",
                "destination": dst,
                "total_mb": round(mb, 2),
                "severity": "MEDIUM",
            })
    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Data exfiltration indicator hunter"
    )
    parser.add_argument("--conn-log", help="Zeek conn.log or network flow CSV")
    parser.add_argument("--dns-log", help="Zeek dns.log or DNS query CSV")
    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if not args.conn_log and not args.dns_log:
        parser.error("At least one of --conn-log or --dns-log is required")

    print("[*] Data Exfiltration Indicator Hunter")
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "findings": []}

    if args.dns_log:
        report["findings"].extend(analyze_dns_queries(args.dns_log))
    if args.conn_log:
        report["findings"].extend(analyze_network_flows(args.conn_log))
        report["findings"].extend(analyze_off_hours_traffic(args.conn_log))

    report["risk_level"] = (
        "CRITICAL" if any(f["severity"] == "CRITICAL" for f in report["findings"])
        else "HIGH" if any(f["severity"] == "HIGH" for f in report["findings"])
        else "MEDIUM" if report["findings"] else "LOW"
    )
    report["total_findings"] = len(report["findings"])

    print(f"[*] {report['total_findings']} exfiltration indicators found")
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
