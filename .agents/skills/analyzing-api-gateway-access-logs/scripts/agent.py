#!/usr/bin/env python3
"""Agent for analyzing API Gateway access logs for security threats."""

import os
import re
import json
import argparse
from datetime import datetime
from collections import defaultdict

import pandas as pd
import numpy as np


def load_api_logs(log_path):
    """Load API gateway logs from JSON lines or CSV."""
    if log_path.endswith(".csv"):
        return pd.read_csv(log_path, parse_dates=["timestamp"])
    return pd.read_json(log_path, lines=True)


def detect_bola_attacks(df, threshold=50):
    """Detect Broken Object Level Authorization (BOLA/IDOR) attacks."""
    findings = []
    if "resource_id" not in df.columns:
        path_col = "request_path" if "request_path" in df.columns else "path"
        df["resource_id"] = df[path_col].str.extract(r'/(\d+)(?:/|$|\?)')
    df_with_ids = df.dropna(subset=["resource_id"])
    if df_with_ids.empty:
        return findings
    user_col = "user_id" if "user_id" in df.columns else "source_ip"
    grouped = df_with_ids.groupby([user_col]).agg(
        unique_resources=("resource_id", "nunique"),
        total_requests=("resource_id", "count"),
    ).reset_index()
    bola_suspects = grouped[grouped["unique_resources"] >= threshold]
    for _, row in bola_suspects.iterrows():
        findings.append({
            "user": row[user_col],
            "unique_resources_accessed": int(row["unique_resources"]),
            "total_requests": int(row["total_requests"]),
            "type": "BOLA/IDOR",
            "severity": "CRITICAL",
        })
    return findings


def detect_auth_scanning(df, threshold=100):
    """Detect credential scanning via 401/403 response surges."""
    findings = []
    auth_failures = df[df["status_code"].isin([401, 403])]
    if auth_failures.empty:
        return findings
    ip_col = "source_ip" if "source_ip" in df.columns else "client_ip"
    ip_failures = auth_failures.groupby(ip_col).agg(
        failure_count=("status_code", "count"),
        unique_endpoints=("request_path", "nunique") if "request_path" in df.columns
        else ("path", "nunique"),
    ).reset_index()
    scanners = ip_failures[ip_failures["failure_count"] >= threshold]
    for _, row in scanners.iterrows():
        findings.append({
            "source_ip": row[ip_col],
            "auth_failures": int(row["failure_count"]),
            "endpoints_probed": int(row["unique_endpoints"]),
            "type": "credential_scanning",
            "severity": "HIGH",
        })
    return findings


def detect_injection_attempts(df):
    """Detect SQL/NoSQL injection attempts in request parameters."""
    injection_patterns = [
        r"(?:union\s+select|select\s+.*\s+from|drop\s+table|insert\s+into)",
        r"(?:'\s*or\s+'1'\s*=\s*'1|'\s*or\s+1\s*=\s*1)",
        r'(?:\$ne|\$gt|\$lt|\$regex|\$where)',
        r'(?:<script|javascript:|onerror=|onload=)',
        r'(?:\.\./\.\./|/etc/passwd|/proc/self)',
    ]
    findings = []
    path_col = "request_path" if "request_path" in df.columns else "path"
    query_col = "query_string" if "query_string" in df.columns else path_col
    for _, row in df.iterrows():
        request_str = str(row.get(query_col, "")) + str(row.get("request_body", ""))
        for pattern in injection_patterns:
            if re.search(pattern, request_str, re.IGNORECASE):
                findings.append({
                    "source_ip": row.get("source_ip", row.get("client_ip", "")),
                    "path": row.get(path_col, ""),
                    "pattern_matched": pattern,
                    "type": "injection_attempt",
                    "severity": "HIGH",
                })
                break
    return findings[:500]


def detect_rate_limit_bypass(df, window="1min", threshold=100):
    """Detect rate limit bypass attempts."""
    findings = []
    ip_col = "source_ip" if "source_ip" in df.columns else "client_ip"
    df_copy = df.copy()
    df_copy["timestamp"] = pd.to_datetime(df_copy["timestamp"])
    df_copy = df_copy.set_index("timestamp")
    for ip, group in df_copy.groupby(ip_col):
        resampled = group.resample(window).size()
        bursts = resampled[resampled > threshold]
        if len(bursts) > 0:
            findings.append({
                "source_ip": ip,
                "max_requests_per_min": int(resampled.max()),
                "burst_periods": len(bursts),
                "type": "rate_limit_bypass",
                "severity": "MEDIUM",
            })
    return sorted(findings, key=lambda x: x["max_requests_per_min"], reverse=True)[:50]


def detect_unusual_methods(df):
    """Detect unusual HTTP methods on typically read-only endpoints."""
    findings = []
    dangerous_methods = {"DELETE", "PUT", "PATCH"}
    method_col = "method" if "method" in df.columns else "http_method"
    path_col = "request_path" if "request_path" in df.columns else "path"
    unusual = df[df[method_col].str.upper().isin(dangerous_methods)]
    for _, row in unusual.iterrows():
        findings.append({
            "source_ip": row.get("source_ip", row.get("client_ip", "")),
            "method": row[method_col],
            "path": row[path_col],
            "status_code": int(row.get("status_code", 0)),
            "type": "unusual_method",
            "severity": "MEDIUM",
        })
    return findings[:200]


def main():
    parser = argparse.ArgumentParser(description="API Gateway Log Analysis Agent")
    parser.add_argument("--log-file", required=True, help="API gateway log file")
    parser.add_argument("--output", default="api_gateway_report.json")
    parser.add_argument("--action", choices=[
        "bola", "auth_scan", "injection", "rate_limit", "full_analysis"
    ], default="full_analysis")
    args = parser.parse_args()

    df = load_api_logs(args.log_file)
    report = {"generated_at": datetime.utcnow().isoformat(), "total_requests": len(df),
              "findings": {}}
    print(f"[+] Loaded {len(df)} API requests")

    if args.action in ("bola", "full_analysis"):
        findings = detect_bola_attacks(df)
        report["findings"]["bola"] = findings
        print(f"[+] BOLA suspects: {len(findings)}")

    if args.action in ("auth_scan", "full_analysis"):
        findings = detect_auth_scanning(df)
        report["findings"]["auth_scanning"] = findings
        print(f"[+] Auth scanners: {len(findings)}")

    if args.action in ("injection", "full_analysis"):
        findings = detect_injection_attempts(df)
        report["findings"]["injection_attempts"] = findings
        print(f"[+] Injection attempts: {len(findings)}")

    if args.action in ("rate_limit", "full_analysis"):
        findings = detect_rate_limit_bypass(df)
        report["findings"]["rate_limit_bypass"] = findings
        print(f"[+] Rate limit bypasses: {len(findings)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
