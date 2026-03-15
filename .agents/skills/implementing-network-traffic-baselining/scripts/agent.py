#!/usr/bin/env python3
"""Network traffic baselining agent using pandas for NetFlow/IPFIX statistical analysis."""

import json
import math
import argparse
from datetime import datetime
from collections import defaultdict

import pandas as pd
import numpy as np


def load_netflow_csv(filepath):
    """Load NetFlow/IPFIX records from CSV export."""
    df = pd.read_csv(filepath, parse_dates=["timestamp"])
    required = {"timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "bytes", "packets"}
    missing = required - set(df.columns)
    if missing:
        alt_map = {"ts": "timestamp", "sa": "src_ip", "da": "dst_ip", "sp": "src_port",
                   "dp": "dst_port", "pr": "protocol", "ibyt": "bytes", "ipkt": "packets"}
        df.rename(columns={k: v for k, v in alt_map.items() if k in df.columns}, inplace=True)
    print(f"[+] Loaded {len(df)} flow records from {filepath}")
    return df


def compute_hourly_baseline(df):
    """Compute hourly traffic volume baseline."""
    df["hour"] = df["timestamp"].dt.hour
    hourly = df.groupby("hour").agg(
        total_bytes=("bytes", "sum"),
        total_packets=("packets", "sum"),
        flow_count=("bytes", "count"),
    ).reset_index()
    hourly["bytes_mean"] = hourly["total_bytes"] / max(df["timestamp"].dt.date.nunique(), 1)
    hourly["bytes_std"] = df.groupby("hour")["bytes"].std().values
    return hourly.to_dict(orient="records")


def compute_host_baselines(df):
    """Compute per-source-IP traffic baselines."""
    host_stats = df.groupby("src_ip").agg(
        total_bytes=("bytes", "sum"),
        total_packets=("packets", "sum"),
        flow_count=("bytes", "count"),
        unique_dst_ips=("dst_ip", "nunique"),
        unique_dst_ports=("dst_port", "nunique"),
        mean_bytes_per_flow=("bytes", "mean"),
        std_bytes_per_flow=("bytes", "std"),
    ).reset_index()
    host_stats = host_stats.fillna(0)
    return host_stats


def compute_protocol_baseline(df):
    """Compute protocol distribution baseline."""
    proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
    df["proto_name"] = df["protocol"].map(lambda x: proto_map.get(x, str(x)))
    proto_stats = df.groupby("proto_name").agg(
        flow_count=("bytes", "count"),
        total_bytes=("bytes", "sum"),
    ).reset_index()
    total = proto_stats["flow_count"].sum()
    proto_stats["percentage"] = (proto_stats["flow_count"] / total * 100).round(2)
    return proto_stats.to_dict(orient="records")


def detect_zscore_anomalies(df, host_baselines, threshold=3.0):
    """Detect anomalous hosts using z-score on bytes transferred."""
    mean_bytes = host_baselines["total_bytes"].mean()
    std_bytes = host_baselines["total_bytes"].std()
    if std_bytes == 0:
        return []
    host_baselines["zscore"] = ((host_baselines["total_bytes"] - mean_bytes) / std_bytes).round(4)
    anomalies = host_baselines[host_baselines["zscore"].abs() >= threshold]
    alerts = []
    for _, row in anomalies.iterrows():
        alerts.append({
            "detection": "Z-Score Traffic Anomaly",
            "src_ip": row["src_ip"],
            "total_bytes": int(row["total_bytes"]),
            "zscore": float(row["zscore"]),
            "threshold": threshold,
            "flow_count": int(row["flow_count"]),
            "unique_destinations": int(row["unique_dst_ips"]),
            "severity": "critical" if abs(row["zscore"]) >= 5.0 else "high",
        })
    return alerts


def detect_iqr_anomalies(df, host_baselines):
    """Detect outlier hosts using IQR method on bytes per flow."""
    q1 = host_baselines["mean_bytes_per_flow"].quantile(0.25)
    q3 = host_baselines["mean_bytes_per_flow"].quantile(0.75)
    iqr = q3 - q1
    lower = q1 - 1.5 * iqr
    upper = q3 + 1.5 * iqr
    outliers = host_baselines[
        (host_baselines["mean_bytes_per_flow"] < lower) | (host_baselines["mean_bytes_per_flow"] > upper)
    ]
    alerts = []
    for _, row in outliers.iterrows():
        alerts.append({
            "detection": "IQR Bytes-Per-Flow Outlier",
            "src_ip": row["src_ip"],
            "mean_bytes_per_flow": round(float(row["mean_bytes_per_flow"]), 2),
            "iqr_lower": round(float(lower), 2),
            "iqr_upper": round(float(upper), 2),
            "severity": "medium",
        })
    return alerts


def detect_port_scan_pattern(df, threshold=50):
    """Detect hosts connecting to an unusually high number of unique ports."""
    port_counts = df.groupby("src_ip")["dst_port"].nunique().reset_index()
    port_counts.columns = ["src_ip", "unique_ports"]
    scanners = port_counts[port_counts["unique_ports"] >= threshold]
    return [{"detection": "Port Scan Pattern", "src_ip": row["src_ip"],
             "unique_ports": int(row["unique_ports"]), "severity": "high"}
            for _, row in scanners.iterrows()]


def main():
    parser = argparse.ArgumentParser(description="Network Traffic Baselining Agent")
    parser.add_argument("--netflow-csv", required=True, help="Path to NetFlow/IPFIX CSV export")
    parser.add_argument("--zscore-threshold", type=float, default=3.0, help="Z-score anomaly threshold")
    parser.add_argument("--scan-threshold", type=int, default=50, help="Port scan unique ports threshold")
    parser.add_argument("--output", default="traffic_baseline_report.json", help="Output report path")
    args = parser.parse_args()

    df = load_netflow_csv(args.netflow_csv)
    hourly = compute_hourly_baseline(df)
    host_baselines = compute_host_baselines(df)
    protocol = compute_protocol_baseline(df)

    zscore_alerts = detect_zscore_anomalies(df, host_baselines, args.zscore_threshold)
    iqr_alerts = detect_iqr_anomalies(df, host_baselines)
    scan_alerts = detect_port_scan_pattern(df, args.scan_threshold)

    top_talkers = host_baselines.nlargest(10, "total_bytes")[["src_ip", "total_bytes", "flow_count"]].to_dict(orient="records")

    report = {
        "analysis_time": datetime.utcnow().isoformat() + "Z",
        "total_flows": len(df),
        "date_range": {"start": str(df["timestamp"].min()), "end": str(df["timestamp"].max())},
        "baselines": {
            "hourly_profile": hourly,
            "protocol_distribution": protocol,
            "top_talkers": top_talkers,
        },
        "anomalies": {
            "zscore_anomalies": zscore_alerts,
            "iqr_outliers": iqr_alerts,
            "port_scan_patterns": scan_alerts,
        },
        "total_anomalies": len(zscore_alerts) + len(iqr_alerts) + len(scan_alerts),
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Z-score anomalies: {len(zscore_alerts)}")
    print(f"[+] IQR outliers: {len(iqr_alerts)}")
    print(f"[+] Port scan patterns: {len(scan_alerts)}")
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
