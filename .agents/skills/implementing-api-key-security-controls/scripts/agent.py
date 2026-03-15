#!/usr/bin/env python3
"""Agent for implementing and auditing API key security controls."""

import json
import argparse
import hashlib
import secrets
import re
from datetime import datetime, timedelta
from pathlib import Path


def generate_api_key(prefix="sk", length=32):
    """Generate a secure API key with prefix and checksum."""
    random_part = secrets.token_hex(length)
    checksum = hashlib.sha256(random_part.encode()).hexdigest()[:6]
    key = f"{prefix}_{random_part}_{checksum}"
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    return {"api_key": key, "key_hash": key_hash, "prefix": prefix, "entropy_bits": length * 8}


def hash_api_key(api_key):
    """Hash an API key for secure storage using SHA-256."""
    return hashlib.sha256(api_key.encode()).hexdigest()


def scan_for_leaked_keys(file_path, patterns=None):
    """Scan files for leaked API key patterns."""
    if patterns is None:
        patterns = [
            (r"sk_live_[a-zA-Z0-9]{24,}", "Stripe live key"),
            (r"AKIA[0-9A-Z]{16}", "AWS access key"),
            (r"AIza[0-9A-Za-z_-]{35}", "Google API key"),
            (r"ghp_[a-zA-Z0-9]{36}", "GitHub PAT"),
            (r"xox[baprs]-[a-zA-Z0-9-]+", "Slack token"),
            (r"sk-[a-zA-Z0-9]{48}", "OpenAI key"),
            (r"[a-f0-9]{32}", "Generic hex key (32 char)"),
        ]
    findings = []
    with open(file_path) as f:
        for i, line in enumerate(f, 1):
            for pattern, desc in patterns:
                matches = re.findall(pattern, line)
                for match in matches:
                    findings.append({
                        "file": str(file_path), "line": i,
                        "pattern": desc, "key_preview": match[:8] + "...",
                        "severity": "CRITICAL",
                    })
    return findings


def audit_key_rotation(key_inventory_path):
    """Audit API key age and rotation compliance."""
    with open(key_inventory_path) as f:
        keys = json.load(f)
    findings = []
    now = datetime.utcnow()
    for key in keys:
        created = datetime.fromisoformat(key.get("created_at", now.isoformat()))
        age_days = (now - created).days
        last_used = key.get("last_used_at")
        scopes = key.get("scopes", [])
        if age_days > 90:
            findings.append({
                "key_id": key.get("id", ""), "owner": key.get("owner", ""),
                "age_days": age_days, "issue": "key_age_exceeds_90_days",
                "severity": "HIGH",
            })
        if last_used:
            unused_days = (now - datetime.fromisoformat(last_used)).days
            if unused_days > 30:
                findings.append({
                    "key_id": key.get("id", ""), "owner": key.get("owner", ""),
                    "unused_days": unused_days, "issue": "inactive_key",
                    "severity": "MEDIUM",
                })
        if not scopes or "*" in scopes:
            findings.append({
                "key_id": key.get("id", ""), "owner": key.get("owner", ""),
                "scopes": scopes, "issue": "overly_broad_scope",
                "severity": "HIGH",
            })
    return sorted(findings, key=lambda x: x.get("age_days", 0), reverse=True)


def analyze_key_usage(usage_log_path):
    """Analyze API key usage patterns for anomalies."""
    entries = []
    with open(usage_log_path) as f:
        for line in f:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    from collections import Counter, defaultdict
    key_ips = defaultdict(set)
    key_errors = Counter()
    for entry in entries:
        key_id = entry.get("api_key_id", "")
        ip = entry.get("client_ip", "")
        status = int(entry.get("status_code", 200))
        key_ips[key_id].add(ip)
        if status >= 400:
            key_errors[key_id] += 1
    findings = []
    for key_id, ips in key_ips.items():
        if len(ips) > 10:
            findings.append({
                "key_id": key_id, "unique_ips": len(ips),
                "issue": "key_shared_across_many_ips", "severity": "HIGH",
            })
    for key_id, errors in key_errors.most_common(10):
        if errors > 100:
            findings.append({
                "key_id": key_id, "error_count": errors,
                "issue": "high_error_rate", "severity": "MEDIUM",
            })
    return findings


def main():
    parser = argparse.ArgumentParser(description="API Key Security Controls Agent")
    parser.add_argument("--action", choices=[
        "generate", "scan", "audit_rotation", "analyze_usage", "full"
    ], default="full")
    parser.add_argument("--file", help="File to scan for leaked keys")
    parser.add_argument("--inventory", help="Key inventory JSON")
    parser.add_argument("--usage-log", help="Key usage log (JSON lines)")
    parser.add_argument("--output", default="api_key_audit_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}

    if args.action == "generate":
        key = generate_api_key()
        report["generated_key"] = key
        print(f"[+] Generated key: {key['api_key'][:20]}...")

    if args.action in ("scan", "full") and args.file:
        f = scan_for_leaked_keys(args.file)
        report["findings"]["leaked_keys"] = f
        print(f"[+] Leaked keys found: {len(f)}")

    if args.action in ("audit_rotation", "full") and args.inventory:
        f = audit_key_rotation(args.inventory)
        report["findings"]["rotation_audit"] = f
        print(f"[+] Rotation issues: {len(f)}")

    if args.action in ("analyze_usage", "full") and args.usage_log:
        f = analyze_key_usage(args.usage_log)
        report["findings"]["usage_anomalies"] = f
        print(f"[+] Usage anomalies: {len(f)}")

    with open(args.output, "w") as fout:
        json.dump(report, fout, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
