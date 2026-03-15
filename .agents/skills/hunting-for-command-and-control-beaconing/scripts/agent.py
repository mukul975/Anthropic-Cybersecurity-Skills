#!/usr/bin/env python3
"""Agent for hunting C2 beaconing across multiple data sources."""

import argparse
import json
import math
import os
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone


C2_INDICATORS = {
    "known_ports": {443, 8443, 8080, 4444, 5555, 8888, 9090, 1337},
    "suspicious_user_agents": [
        "mozilla/4.0", "python-requests", "curl/", "wget/",
        "java/", "go-http-client",
    ],
    "dns_c2_patterns": [
        r'^[a-z0-9]{30,}\.',  # Long random subdomain (DNS tunneling)
        r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',  # Direct IP
    ],
}


def analyze_dns_queries(dns_log_path):
    """Analyze DNS query logs for C2 indicators."""
    findings = []
    domain_counts = defaultdict(int)
    try:
        with open(dns_log_path, "r") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                fields = line.strip().split("\t")
                if len(fields) < 10:
                    continue
                query = fields[9] if len(fields) > 9 else ""
                domain_counts[query] += 1
                for pattern in C2_INDICATORS["dns_c2_patterns"]:
                    if re.match(pattern, query):
                        findings.append({
                            "type": "suspicious_dns",
                            "query": query,
                            "pattern": pattern,
                        })
    except FileNotFoundError:
        pass

    high_freq = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    for domain, count in high_freq:
        if count > 100 and len(domain) > 20:
            findings.append({
                "type": "high_frequency_dns",
                "domain": domain,
                "query_count": count,
            })
    return findings


def analyze_http_logs(http_log_path):
    """Analyze HTTP logs for C2-like traffic patterns."""
    findings = []
    try:
        with open(http_log_path, "r") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                fields = line.strip().split("\t")
                if len(fields) < 13:
                    continue
                host = fields[8] if len(fields) > 8 else ""
                uri = fields[9] if len(fields) > 9 else ""
                user_agent = fields[12] if len(fields) > 12 else ""
                for ua in C2_INDICATORS["suspicious_user_agents"]:
                    if ua in user_agent.lower():
                        findings.append({
                            "type": "suspicious_user_agent",
                            "host": host,
                            "uri": uri[:100],
                            "user_agent": user_agent[:100],
                        })
                        break
                if re.match(r'^/[a-zA-Z0-9]{4,8}$', uri):
                    findings.append({
                        "type": "c2_uri_pattern",
                        "host": host,
                        "uri": uri,
                        "note": "Short random URI typical of C2 frameworks",
                    })
    except FileNotFoundError:
        pass
    return findings


def analyze_connection_patterns(conn_log_path):
    """Detect persistent long-duration connections typical of C2."""
    findings = []
    try:
        with open(conn_log_path, "r") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                fields = line.strip().split("\t")
                if len(fields) < 10:
                    continue
                src = fields[2]
                dst = fields[4]
                dst_port = fields[5]
                duration = fields[8] if len(fields) > 8 else "0"
                orig_bytes = fields[9] if len(fields) > 9 else "0"
                resp_bytes = fields[10] if len(fields) > 10 else "0"
                try:
                    dur = float(duration) if duration != "-" else 0
                    ob = int(orig_bytes) if orig_bytes != "-" else 0
                    rb = int(resp_bytes) if resp_bytes != "-" else 0
                except ValueError:
                    continue
                if dur > 3600 and ob > 0 and rb > 0:
                    ratio = ob / rb if rb > 0 else 999
                    if 0.8 < ratio < 1.2:
                        findings.append({
                            "type": "persistent_symmetric",
                            "src": src, "dst": dst, "port": dst_port,
                            "duration_hours": round(dur / 3600, 1),
                            "data_ratio": round(ratio, 2),
                        })
    except FileNotFoundError:
        pass
    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Hunt for C2 beaconing across network data sources"
    )
    parser.add_argument("--conn-log", help="Zeek conn.log")
    parser.add_argument("--dns-log", help="Zeek dns.log")
    parser.add_argument("--http-log", help="Zeek http.log")
    parser.add_argument("--output", "-o", help="Output JSON report")
    args = parser.parse_args()

    print("[*] C2 Beaconing Hunting Agent")
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "findings": {}}

    if args.dns_log:
        dns = analyze_dns_queries(args.dns_log)
        report["findings"]["dns"] = dns
        print(f"[*] DNS findings: {len(dns)}")

    if args.http_log:
        http = analyze_http_logs(args.http_log)
        report["findings"]["http"] = http
        print(f"[*] HTTP findings: {len(http)}")

    if args.conn_log:
        conn = analyze_connection_patterns(args.conn_log)
        report["findings"]["connections"] = conn
        print(f"[*] Connection findings: {len(conn)}")

    total = sum(len(v) for v in report["findings"].values())
    report["risk_level"] = "CRITICAL" if total >= 10 else "HIGH" if total >= 5 else "MEDIUM" if total > 0 else "LOW"

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
