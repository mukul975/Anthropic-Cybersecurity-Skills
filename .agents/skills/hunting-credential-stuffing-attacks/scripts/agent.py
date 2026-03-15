#!/usr/bin/env python3
"""Agent for hunting credential stuffing attacks in authentication logs."""

import os
import json
import argparse
from datetime import datetime
from collections import defaultdict

import pandas as pd
import numpy as np


def load_auth_logs(log_path):
    """Load authentication logs from CSV or JSON lines."""
    if log_path.endswith(".csv"):
        return pd.read_csv(log_path, parse_dates=["timestamp"])
    elif log_path.endswith(".json") or log_path.endswith(".jsonl"):
        return pd.read_json(log_path, lines=True)
    else:
        return pd.read_csv(log_path, parse_dates=["timestamp"])


def detect_credential_stuffing(df, ip_threshold=20, time_window="1h"):
    """Detect credential stuffing by analyzing failed login patterns."""
    failed = df[df["status"] == "failed"].copy()
    if failed.empty:
        return []
    failed = failed.sort_values("timestamp")
    findings = []
    ip_account = failed.groupby("source_ip").agg(
        unique_accounts=("username", "nunique"),
        total_attempts=("username", "count"),
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max"),
    ).reset_index()
    stuffing_ips = ip_account[ip_account["unique_accounts"] >= ip_threshold]
    for _, row in stuffing_ips.iterrows():
        duration = (row["last_seen"] - row["first_seen"]).total_seconds()
        findings.append({
            "source_ip": row["source_ip"],
            "unique_accounts_targeted": int(row["unique_accounts"]),
            "total_attempts": int(row["total_attempts"]),
            "duration_seconds": int(duration),
            "attempts_per_minute": round(row["total_attempts"] / max(duration / 60, 1), 1),
            "type": "credential_stuffing",
            "severity": "CRITICAL" if row["unique_accounts"] > 100 else "HIGH",
        })
    return sorted(findings, key=lambda x: x["unique_accounts_targeted"], reverse=True)


def detect_password_spray(df, account_threshold=10):
    """Detect password spray attacks (one password, many accounts)."""
    failed = df[df["status"] == "failed"].copy()
    if failed.empty:
        return []
    findings = []
    ip_groups = failed.groupby("source_ip").agg(
        unique_accounts=("username", "nunique"),
        total_attempts=("username", "count"),
    ).reset_index()
    spray_candidates = ip_groups[
        (ip_groups["unique_accounts"] >= account_threshold) &
        (ip_groups["total_attempts"] <= ip_groups["unique_accounts"] * 3)
    ]
    for _, row in spray_candidates.iterrows():
        ratio = row["total_attempts"] / row["unique_accounts"]
        findings.append({
            "source_ip": row["source_ip"],
            "unique_accounts": int(row["unique_accounts"]),
            "total_attempts": int(row["total_attempts"]),
            "attempts_per_account": round(ratio, 1),
            "type": "password_spray",
            "severity": "HIGH",
        })
    return findings


def detect_distributed_attack(df, account_ip_threshold=5):
    """Detect distributed credential stuffing (many IPs per account)."""
    failed = df[df["status"] == "failed"]
    if failed.empty:
        return []
    account_ips = failed.groupby("username").agg(
        unique_ips=("source_ip", "nunique"),
        total_failures=("source_ip", "count"),
    ).reset_index()
    distributed = account_ips[account_ips["unique_ips"] >= account_ip_threshold]
    findings = []
    for _, row in distributed.iterrows():
        findings.append({
            "username": row["username"],
            "unique_source_ips": int(row["unique_ips"]),
            "total_failures": int(row["total_failures"]),
            "type": "distributed_attack",
            "severity": "HIGH",
        })
    return sorted(findings, key=lambda x: x["unique_source_ips"], reverse=True)


def analyze_success_after_failures(df, min_failures=5):
    """Find accounts with successful login after many failures (compromised)."""
    compromised = []
    for username, group in df.groupby("username"):
        group = group.sort_values("timestamp")
        failures = 0
        for _, row in group.iterrows():
            if row["status"] == "failed":
                failures += 1
            elif row["status"] == "success" and failures >= min_failures:
                compromised.append({
                    "username": username,
                    "failures_before_success": failures,
                    "success_ip": row.get("source_ip", ""),
                    "success_time": str(row["timestamp"]),
                    "severity": "CRITICAL",
                })
                break
    return compromised


def analyze_user_agent_patterns(df):
    """Detect automation by analyzing user-agent distribution."""
    failed = df[df["status"] == "failed"]
    if "user_agent" not in failed.columns or failed.empty:
        return []
    ua_counts = failed["user_agent"].value_counts()
    total = len(failed)
    suspicious = []
    for ua, count in ua_counts.items():
        pct = count / total * 100
        if pct > 30 and count > 50:
            suspicious.append({
                "user_agent": str(ua)[:200],
                "count": int(count),
                "percentage": round(pct, 1),
                "likely_automated": True,
            })
    return suspicious


def calculate_attack_metrics(df):
    """Calculate overall authentication attack metrics."""
    total = len(df)
    failures = len(df[df["status"] == "failed"])
    successes = len(df[df["status"] == "success"])
    return {
        "total_events": total,
        "total_failures": failures,
        "total_successes": successes,
        "failure_rate": round(failures / max(total, 1) * 100, 1),
        "unique_ips": int(df["source_ip"].nunique()),
        "unique_accounts": int(df["username"].nunique()),
        "time_range": f"{df['timestamp'].min()} to {df['timestamp'].max()}",
    }


def main():
    parser = argparse.ArgumentParser(description="Credential Stuffing Detection Agent")
    parser.add_argument("--log-file", required=True, help="Authentication log file")
    parser.add_argument("--output", default="credential_stuffing_report.json")
    parser.add_argument("--action", choices=[
        "stuffing", "spray", "distributed", "compromised", "full_hunt"
    ], default="full_hunt")
    args = parser.parse_args()

    df = load_auth_logs(args.log_file)
    report = {"generated_at": datetime.utcnow().isoformat(),
              "metrics": calculate_attack_metrics(df), "findings": {}}
    print(f"[+] Loaded {len(df)} auth events")

    if args.action in ("stuffing", "full_hunt"):
        findings = detect_credential_stuffing(df)
        report["findings"]["credential_stuffing"] = findings
        print(f"[+] Credential stuffing IPs: {len(findings)}")

    if args.action in ("spray", "full_hunt"):
        findings = detect_password_spray(df)
        report["findings"]["password_spray"] = findings
        print(f"[+] Password spray IPs: {len(findings)}")

    if args.action in ("distributed", "full_hunt"):
        findings = detect_distributed_attack(df)
        report["findings"]["distributed_attacks"] = findings
        print(f"[+] Distributed attack targets: {len(findings)}")

    if args.action in ("compromised", "full_hunt"):
        findings = analyze_success_after_failures(df)
        report["findings"]["compromised_accounts"] = findings
        print(f"[+] Potentially compromised accounts: {len(findings)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
