#!/usr/bin/env python3
"""Agent for detecting insider data exfiltration via DLP analysis."""

import os
import json
import argparse
from datetime import datetime

import pandas as pd
import numpy as np


def load_activity_logs(log_path):
    """Load file/cloud activity logs."""
    if log_path.endswith(".csv"):
        return pd.read_csv(log_path, parse_dates=["timestamp"])
    return pd.read_json(log_path, lines=True)


def detect_volume_anomalies(df, multiplier=3.0):
    """Detect users with data transfer volume exceeding baseline."""
    df["date"] = df["timestamp"].dt.date
    daily_volume = df.groupby(["user", "date"])["bytes_transferred"].sum().reset_index()
    user_baseline = daily_volume.groupby("user")["bytes_transferred"].agg(
        ["mean", "std"]).reset_index()
    user_baseline.columns = ["user", "avg_bytes", "std_bytes"]
    latest_date = df["date"].max()
    latest_day = daily_volume[daily_volume["date"] == latest_date]
    merged = latest_day.merge(user_baseline, on="user")
    threshold = merged["avg_bytes"] + (multiplier * merged["std_bytes"].fillna(0))
    anomalies = merged[merged["bytes_transferred"] > threshold]
    findings = []
    for _, row in anomalies.iterrows():
        findings.append({
            "user": row["user"],
            "today_bytes": int(row["bytes_transferred"]),
            "avg_bytes": int(row["avg_bytes"]),
            "multiplier": round(row["bytes_transferred"] / max(row["avg_bytes"], 1), 1),
            "severity": "CRITICAL" if row["bytes_transferred"] > row["avg_bytes"] * 5 else "HIGH",
        })
    return sorted(findings, key=lambda x: x["multiplier"], reverse=True)


def detect_off_hours_activity(df, start_hour=6, end_hour=22):
    """Detect file access during off-hours."""
    df["hour"] = df["timestamp"].dt.hour
    off_hours = df[(df["hour"] < start_hour) | (df["hour"] >= end_hour)]
    if off_hours.empty:
        return []
    user_counts = off_hours.groupby("user").agg(
        events=("timestamp", "count"),
        bytes_total=("bytes_transferred", "sum"),
        unique_files=("file_path", "nunique") if "file_path" in df.columns
        else ("filename", "nunique"),
    ).reset_index()
    findings = []
    for _, row in user_counts.iterrows():
        if row["events"] > 10:
            findings.append({
                "user": row["user"],
                "off_hours_events": int(row["events"]),
                "bytes_transferred": int(row["bytes_total"]),
                "unique_files": int(row["unique_files"]),
                "severity": "HIGH",
            })
    return sorted(findings, key=lambda x: x["off_hours_events"], reverse=True)


def detect_bulk_downloads(df, file_threshold=50, time_window="1h"):
    """Detect bulk file downloads in short time windows."""
    findings = []
    df_sorted = df.sort_values("timestamp")
    download_actions = ["download", "copy", "export"]
    action_col = "action" if "action" in df.columns else "event_type"
    downloads = df_sorted[df_sorted[action_col].str.lower().isin(download_actions)]
    if downloads.empty:
        return findings
    downloads = downloads.set_index("timestamp")
    for user, group in downloads.groupby("user"):
        rolling = group.resample(time_window).size()
        bursts = rolling[rolling >= file_threshold]
        if len(bursts) > 0:
            findings.append({
                "user": user,
                "max_downloads_per_hour": int(rolling.max()),
                "burst_periods": len(bursts),
                "total_downloads": len(group),
                "severity": "CRITICAL",
            })
    return findings


def detect_sensitive_file_access(df, sensitive_patterns=None):
    """Detect access to sensitive file types or directories."""
    if sensitive_patterns is None:
        sensitive_patterns = [
            r"\.pem$", r"\.key$", r"\.env$", r"credentials",
            r"password", r"\.kdbx$", r"\.pfx$", r"secret",
            r"financial", r"payroll", r"customer.*data",
        ]
    file_col = "file_path" if "file_path" in df.columns else "filename"
    findings = []
    import re
    for _, row in df.iterrows():
        filepath = str(row.get(file_col, ""))
        for pattern in sensitive_patterns:
            if re.search(pattern, filepath, re.IGNORECASE):
                findings.append({
                    "user": row.get("user", ""),
                    "file": filepath,
                    "pattern_matched": pattern,
                    "action": row.get("action", row.get("event_type", "")),
                    "timestamp": str(row.get("timestamp", "")),
                    "severity": "HIGH",
                })
                break
    return findings[:500]


def detect_usb_activity(df):
    """Detect USB device usage for data transfer."""
    usb_indicators = ["removable", "usb", "external"]
    dest_col = "destination" if "destination" in df.columns else "target"
    usb_events = df[df[dest_col].str.lower().str.contains(
        "|".join(usb_indicators), na=False)]
    if usb_events.empty:
        return []
    user_usb = usb_events.groupby("user").agg(
        events=("timestamp", "count"),
        bytes_total=("bytes_transferred", "sum"),
    ).reset_index()
    findings = []
    for _, row in user_usb.iterrows():
        findings.append({
            "user": row["user"],
            "usb_events": int(row["events"]),
            "bytes_to_usb": int(row["bytes_total"]),
            "severity": "HIGH",
        })
    return findings


def main():
    parser = argparse.ArgumentParser(description="Insider Data Exfiltration Detection Agent")
    parser.add_argument("--log-file", required=True, help="Activity log file")
    parser.add_argument("--output", default="dlp_exfiltration_report.json")
    parser.add_argument("--action", choices=[
        "volume", "off_hours", "bulk", "sensitive", "full_analysis"
    ], default="full_analysis")
    args = parser.parse_args()

    df = load_activity_logs(args.log_file)
    report = {"generated_at": datetime.utcnow().isoformat(), "total_events": len(df),
              "findings": {}}
    print(f"[+] Loaded {len(df)} activity events")

    if args.action in ("volume", "full_analysis"):
        findings = detect_volume_anomalies(df)
        report["findings"]["volume_anomalies"] = findings
        print(f"[+] Volume anomalies: {len(findings)}")

    if args.action in ("off_hours", "full_analysis"):
        findings = detect_off_hours_activity(df)
        report["findings"]["off_hours_activity"] = findings
        print(f"[+] Off-hours activity users: {len(findings)}")

    if args.action in ("bulk", "full_analysis"):
        findings = detect_bulk_downloads(df)
        report["findings"]["bulk_downloads"] = findings
        print(f"[+] Bulk download users: {len(findings)}")

    if args.action in ("sensitive", "full_analysis"):
        findings = detect_sensitive_file_access(df)
        report["findings"]["sensitive_access"] = findings
        print(f"[+] Sensitive file accesses: {len(findings)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
