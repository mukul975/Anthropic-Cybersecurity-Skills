#!/usr/bin/env python3
"""API enumeration attack detection agent."""

import json
import sys
import argparse
import re
from datetime import datetime
from collections import defaultdict

try:
    import requests
except ImportError:
    print("Install: pip install requests")
    sys.exit(1)


ENUMERATION_PATTERNS = [
    re.compile(r"/api/v\d+/users/\d+", re.IGNORECASE),
    re.compile(r"/api/v\d+/accounts/[a-f0-9-]+", re.IGNORECASE),
    re.compile(r"/api/v\d+/orders/\d+", re.IGNORECASE),
    re.compile(r"/graphql.*introspection", re.IGNORECASE),
    re.compile(r"/(admin|internal|debug|swagger|api-docs)", re.IGNORECASE),
]

SEQUENTIAL_THRESHOLD = 10
RATE_THRESHOLD = 50


def parse_access_log(log_path):
    """Parse NGINX/Apache combined log format for API requests."""
    log_pattern = re.compile(
        r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) \d+'
    )
    entries = []
    with open(log_path, "r") as f:
        for line in f:
            m = log_pattern.match(line)
            if m:
                entries.append({
                    "ip": m.group(1),
                    "timestamp": m.group(2),
                    "method": m.group(3),
                    "path": m.group(4),
                    "status": int(m.group(5)),
                })
    return entries


def detect_sequential_ids(entries):
    """Detect sequential ID enumeration in API paths."""
    id_pattern = re.compile(r"/(\d+)(?:/|$|\?)")
    ip_sequences = defaultdict(list)
    for entry in entries:
        m = id_pattern.search(entry["path"])
        if m:
            ip_sequences[entry["ip"]].append(int(m.group(1)))

    findings = []
    for ip, ids in ip_sequences.items():
        if len(ids) < SEQUENTIAL_THRESHOLD:
            continue
        sorted_ids = sorted(ids)
        sequential_count = sum(1 for i in range(1, len(sorted_ids))
                               if sorted_ids[i] - sorted_ids[i-1] == 1)
        if sequential_count >= SEQUENTIAL_THRESHOLD:
            findings.append({
                "ip": ip,
                "issue": f"Sequential ID enumeration detected ({sequential_count} sequential IDs)",
                "severity": "HIGH",
                "sample_ids": sorted_ids[:20],
                "total_requests": len(ids),
            })
    return findings


def detect_rate_anomalies(entries, window_seconds=60):
    """Detect abnormal request rates per IP to API endpoints."""
    ip_counts = defaultdict(int)
    ip_404s = defaultdict(int)
    ip_401s = defaultdict(int)
    for entry in entries:
        if "/api/" in entry["path"]:
            ip_counts[entry["ip"]] += 1
            if entry["status"] == 404:
                ip_404s[entry["ip"]] += 1
            elif entry["status"] == 401:
                ip_401s[entry["ip"]] += 1

    findings = []
    for ip, count in ip_counts.items():
        if count > RATE_THRESHOLD:
            findings.append({
                "ip": ip,
                "issue": f"High API request rate ({count} requests)",
                "severity": "MEDIUM",
                "total_requests": count,
                "404_count": ip_404s.get(ip, 0),
                "401_count": ip_401s.get(ip, 0),
            })
        if ip_404s.get(ip, 0) > 20:
            findings.append({
                "ip": ip,
                "issue": f"Excessive 404s on API ({ip_404s[ip]} not-found responses)",
                "severity": "HIGH",
                "detail": "Possible endpoint discovery/fuzzing",
            })
    return findings


def detect_path_enumeration(entries):
    """Detect API path/endpoint enumeration patterns."""
    ip_paths = defaultdict(set)
    for entry in entries:
        ip_paths[entry["ip"]].add(entry["path"].split("?")[0])

    findings = []
    for ip, paths in ip_paths.items():
        for pattern in ENUMERATION_PATTERNS:
            matched = [p for p in paths if pattern.search(p)]
            if len(matched) > 5:
                findings.append({
                    "ip": ip,
                    "issue": f"Path enumeration pattern: {pattern.pattern}",
                    "severity": "HIGH",
                    "matched_paths": len(matched),
                    "samples": list(matched)[:5],
                })
    return findings


def query_waf_logs(waf_url, api_key, hours=24):
    """Query WAF API for blocked enumeration attempts."""
    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        resp = requests.get(f"{waf_url}/api/v1/events",
                            params={"hours": hours, "rule_category": "api-abuse"},
                            headers=headers, timeout=15)
        resp.raise_for_status()
        return resp.json().get("events", [])
    except Exception as e:
        return [{"error": str(e)}]


def run_audit(args):
    """Execute API enumeration detection audit."""
    print(f"\n{'='*60}")
    print(f"  API ENUMERATION ATTACK DETECTION")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    report = {}

    if args.log_file:
        entries = parse_access_log(args.log_file)
        report["total_log_entries"] = len(entries)
        print(f"Parsed {len(entries)} log entries from {args.log_file}\n")

        seq_findings = detect_sequential_ids(entries)
        report["sequential_id_findings"] = seq_findings
        print(f"--- SEQUENTIAL ID ENUMERATION ({len(seq_findings)} findings) ---")
        for f in seq_findings[:10]:
            print(f"  [{f['severity']}] {f['ip']}: {f['issue']}")

        rate_findings = detect_rate_anomalies(entries)
        report["rate_findings"] = rate_findings
        print(f"\n--- RATE ANOMALIES ({len(rate_findings)} findings) ---")
        for f in rate_findings[:10]:
            print(f"  [{f['severity']}] {f['ip']}: {f['issue']}")

        path_findings = detect_path_enumeration(entries)
        report["path_findings"] = path_findings
        print(f"\n--- PATH ENUMERATION ({len(path_findings)} findings) ---")
        for f in path_findings[:10]:
            print(f"  [{f['severity']}] {f['ip']}: {f['issue']}")

    return report


def main():
    parser = argparse.ArgumentParser(description="API Enumeration Detection Agent")
    parser.add_argument("--log-file", help="Access log file to analyze")
    parser.add_argument("--waf-url", help="WAF API URL for event queries")
    parser.add_argument("--waf-key", help="WAF API key")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
