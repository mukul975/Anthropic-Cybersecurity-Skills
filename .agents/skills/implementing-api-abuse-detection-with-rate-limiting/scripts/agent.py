#!/usr/bin/env python3
"""Agent for implementing API abuse detection with rate limiting analysis."""

import json
import argparse
import re
from datetime import datetime
from collections import defaultdict, Counter
from pathlib import Path


def load_access_logs(log_path):
    """Load API access logs from JSON lines."""
    entries = []
    with open(log_path) as f:
        for line in f:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def detect_brute_force(logs, failure_threshold=10, window_minutes=5):
    """Detect brute force attacks by counting auth failures per IP."""
    ip_failures = defaultdict(list)
    for entry in logs:
        status = entry.get("status_code", entry.get("status", 0))
        if int(status) in (401, 403):
            ip = entry.get("client_ip", entry.get("ip", ""))
            ts = entry.get("timestamp", "")
            ip_failures[ip].append(ts)
    findings = []
    for ip, timestamps in ip_failures.items():
        if len(timestamps) >= failure_threshold:
            findings.append({
                "client_ip": ip,
                "auth_failures": len(timestamps),
                "severity": "CRITICAL" if len(timestamps) > 50 else "HIGH",
                "category": "brute_force",
                "first_seen": timestamps[0],
                "last_seen": timestamps[-1],
            })
    return sorted(findings, key=lambda x: x["auth_failures"], reverse=True)


def detect_api_scraping(logs, threshold=500):
    """Detect API scraping by high request volume per IP."""
    ip_counts = Counter()
    ip_endpoints = defaultdict(set)
    for entry in logs:
        ip = entry.get("client_ip", entry.get("ip", ""))
        endpoint = entry.get("path", entry.get("endpoint", ""))
        ip_counts[ip] += 1
        ip_endpoints[ip].add(endpoint)
    findings = []
    for ip, count in ip_counts.items():
        if count >= threshold:
            findings.append({
                "client_ip": ip,
                "total_requests": count,
                "unique_endpoints": len(ip_endpoints[ip]),
                "severity": "HIGH",
                "category": "api_scraping",
            })
    return sorted(findings, key=lambda x: x["total_requests"], reverse=True)


def detect_credential_stuffing(logs, threshold=20):
    """Detect credential stuffing: many unique usernames from single IP."""
    ip_users = defaultdict(set)
    for entry in logs:
        if entry.get("path", "").endswith(("/login", "/auth", "/signin")):
            ip = entry.get("client_ip", entry.get("ip", ""))
            user = entry.get("username", entry.get("user", ""))
            if user:
                ip_users[ip].add(user)
    findings = []
    for ip, users in ip_users.items():
        if len(users) >= threshold:
            findings.append({
                "client_ip": ip,
                "unique_usernames": len(users),
                "severity": "CRITICAL",
                "category": "credential_stuffing",
            })
    return sorted(findings, key=lambda x: x["unique_usernames"], reverse=True)


def detect_rate_limit_bypass(logs):
    """Detect attempts to bypass rate limiting."""
    findings = []
    ip_ua_combos = defaultdict(set)
    for entry in logs:
        ip = entry.get("client_ip", entry.get("ip", ""))
        ua = entry.get("user_agent", "")
        ip_ua_combos[ip].add(ua)
    for ip, agents in ip_ua_combos.items():
        if len(agents) >= 10:
            findings.append({
                "client_ip": ip,
                "unique_user_agents": len(agents),
                "severity": "HIGH",
                "category": "ua_rotation",
                "reason": "Rotating User-Agent to bypass rate limits",
            })
    ip_429_count = Counter()
    for entry in logs:
        if int(entry.get("status_code", entry.get("status", 0))) == 429:
            ip = entry.get("client_ip", entry.get("ip", ""))
            ip_429_count[ip] += 1
    for ip, count in ip_429_count.items():
        if count >= 50:
            findings.append({
                "client_ip": ip,
                "rate_limit_hits": count,
                "severity": "MEDIUM",
                "category": "rate_limit_persistence",
                "reason": "Continuing requests after rate limiting",
            })
    return findings


def generate_rate_limit_config(logs):
    """Generate recommended rate limit configuration based on traffic patterns."""
    endpoint_counts = Counter()
    for entry in logs:
        path = entry.get("path", entry.get("endpoint", ""))
        endpoint_counts[path] += 1
    auth_endpoints = [p for p in endpoint_counts if any(
        k in p for k in ["login", "auth", "signin", "register", "password"])]
    config = {
        "global": {"requests_per_minute": 100, "burst": 20},
        "auth_endpoints": {
            "endpoints": auth_endpoints,
            "requests_per_minute": 10,
            "burst": 3,
            "block_duration_seconds": 300,
        },
        "sensitive_endpoints": {
            "endpoints": ["/api/admin", "/api/users", "/api/export"],
            "requests_per_minute": 30,
            "burst": 5,
        },
    }
    return config


def main():
    parser = argparse.ArgumentParser(description="API Abuse Detection Agent")
    parser.add_argument("--log", required=True, help="API access log (JSON lines)")
    parser.add_argument("--output", default="api_abuse_report.json")
    parser.add_argument("--action", choices=[
        "brute_force", "scraping", "stuffing", "bypass", "config", "full_analysis"
    ], default="full_analysis")
    args = parser.parse_args()

    logs = load_access_logs(args.log)
    report = {"generated_at": datetime.utcnow().isoformat(), "total_requests": len(logs),
              "findings": {}}
    print(f"[+] Loaded {len(logs)} API requests")

    if args.action in ("brute_force", "full_analysis"):
        f = detect_brute_force(logs)
        report["findings"]["brute_force"] = f
        print(f"[+] Brute force sources: {len(f)}")

    if args.action in ("scraping", "full_analysis"):
        f = detect_api_scraping(logs)
        report["findings"]["api_scraping"] = f
        print(f"[+] Scraping sources: {len(f)}")

    if args.action in ("stuffing", "full_analysis"):
        f = detect_credential_stuffing(logs)
        report["findings"]["credential_stuffing"] = f
        print(f"[+] Credential stuffing sources: {len(f)}")

    if args.action in ("bypass", "full_analysis"):
        f = detect_rate_limit_bypass(logs)
        report["findings"]["bypass_attempts"] = f
        print(f"[+] Rate limit bypass attempts: {len(f)}")

    if args.action in ("config", "full_analysis"):
        config = generate_rate_limit_config(logs)
        report["findings"]["recommended_config"] = config
        print("[+] Rate limit config generated")

    with open(args.output, "w") as fout:
        json.dump(report, fout, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
