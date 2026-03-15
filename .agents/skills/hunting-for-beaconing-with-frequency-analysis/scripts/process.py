#!/usr/bin/env python3
"""
Beaconing Frequency Analysis Script
Detects C2 beaconing patterns using statistical interval analysis,
jitter detection, and data size consistency scoring.
"""

import json
import csv
import argparse
import datetime
import math
from collections import defaultdict
from pathlib import Path


KNOWN_GOOD_DOMAINS = {
    "microsoft.com", "windowsupdate.com", "google.com", "googleapis.com",
    "gstatic.com", "amazonaws.com", "cloudflare.com", "akamai.net",
    "apple.com", "icloud.com", "adobe.com", "office365.com",
    "office.com", "live.com", "outlook.com", "github.com",
    "slack-edge.com", "teams.microsoft.com", "symantec.com",
    "crowdstrike.com", "sentinelone.com", "mcafee.com",
}

BEACON_THRESHOLDS = {
    "min_connections": 20,
    "max_cv": 0.25,
    "min_interval": 10,
    "max_interval": 86400,
    "max_data_cv": 0.30,
}


def parse_logs(input_path: str) -> list[dict]:
    """Parse connection logs from JSON, CSV, or Zeek format."""
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


def normalize_event(event: dict) -> dict:
    """Normalize field names across different log formats."""
    field_map = {
        "timestamp": ["ts", "timestamp", "_time", "@timestamp", "Timestamp"],
        "src_ip": ["id.orig_h", "src_ip", "source_ip", "LocalIP"],
        "dst_ip": ["id.resp_h", "dst_ip", "dest_ip", "RemoteIP", "DestinationIp"],
        "domain": ["query", "domain", "host", "RemoteUrl", "server_name", "dest"],
        "bytes_sent": ["orig_bytes", "bytes_out", "SentBytes"],
        "bytes_recv": ["resp_bytes", "bytes_in", "ReceivedBytes"],
        "dst_port": ["id.resp_p", "dst_port", "dest_port", "RemotePort"],
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
    """Check if domain matches known-good allowlist."""
    domain_lower = domain.lower()
    return any(domain_lower.endswith(good) for good in KNOWN_GOOD_DOMAINS)


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string for DGA detection."""
    if not text:
        return 0.0
    freq = defaultdict(int)
    for char in text:
        freq[char] += 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def analyze_beaconing(connections: list[dict]) -> list[dict]:
    """Perform statistical frequency analysis on connection pairs."""
    pairs = defaultdict(list)
    for conn in connections:
        src = conn.get("src_ip", "")
        dst = conn.get("domain", "") or conn.get("dst_ip", "")
        if not src or not dst or is_known_good(dst):
            continue
        try:
            ts = float(conn.get("timestamp", 0))
        except (ValueError, TypeError):
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
        })

    findings = []
    for (src, dst), conns in pairs.items():
        if len(conns) < BEACON_THRESHOLDS["min_connections"]:
            continue
        conns.sort(key=lambda x: x["timestamp"])
        intervals = [conns[i]["timestamp"] - conns[i - 1]["timestamp"]
                      for i in range(1, len(conns))
                      if conns[i]["timestamp"] - conns[i - 1]["timestamp"] > 0]
        if len(intervals) < 10:
            continue

        avg_interval = sum(intervals) / len(intervals)
        if not (BEACON_THRESHOLDS["min_interval"] <= avg_interval <= BEACON_THRESHOLDS["max_interval"]):
            continue

        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
        stdev = math.sqrt(variance)
        cv = stdev / avg_interval if avg_interval > 0 else float("inf")

        if cv > BEACON_THRESHOLDS["max_cv"]:
            continue

        bytes_list = [c["bytes_sent"] for c in conns if c["bytes_sent"] > 0]
        data_cv = 0.0
        if bytes_list:
            avg_bytes = sum(bytes_list) / len(bytes_list)
            if avg_bytes > 0:
                data_var = sum((x - avg_bytes) ** 2 for x in bytes_list) / len(bytes_list)
                data_cv = math.sqrt(data_var) / avg_bytes

        risk = 0
        indicators = []
        if cv < 0.05:
            risk += 40
            indicators.append(f"Very regular interval (CV={cv:.4f})")
        elif cv < 0.15:
            risk += 30
            indicators.append(f"Regular interval (CV={cv:.4f})")
        else:
            risk += 20
            indicators.append(f"Moderately regular interval (CV={cv:.4f})")

        if data_cv < 0.10 and bytes_list:
            risk += 15
            indicators.append(f"Consistent payload size (data_CV={data_cv:.4f})")

        if len(conns) > 500:
            risk += 10
            indicators.append(f"High connection count: {len(conns)}")

        domain_parts = dst.split(".")
        if domain_parts:
            entropy = calculate_entropy(domain_parts[0])
            if entropy > 3.5:
                risk += 15
                indicators.append(f"High domain entropy: {entropy:.2f} (possible DGA)")

        risk_level = ("CRITICAL" if risk >= 70 else "HIGH" if risk >= 50
                      else "MEDIUM" if risk >= 30 else "LOW")
        jitter_pct = (stdev / avg_interval * 100) if avg_interval > 0 else 0

        findings.append({
            "src_ip": src,
            "destination": dst,
            "connection_count": len(conns),
            "avg_interval_sec": round(avg_interval, 2),
            "stdev_interval": round(stdev, 2),
            "cv": round(cv, 4),
            "jitter_pct": round(jitter_pct, 1),
            "data_size_cv": round(data_cv, 4),
            "first_seen": datetime.datetime.fromtimestamp(conns[0]["timestamp"]).isoformat(),
            "last_seen": datetime.datetime.fromtimestamp(conns[-1]["timestamp"]).isoformat(),
            "risk_score": risk,
            "risk_level": risk_level,
            "indicators": indicators,
        })

    return sorted(findings, key=lambda x: x["risk_score"], reverse=True)


def run_hunt(input_path: str, output_dir: str) -> None:
    """Execute beaconing frequency analysis hunt."""
    print(f"[*] Beaconing Frequency Analysis Hunt - {datetime.datetime.now().isoformat()}")
    connections = parse_logs(input_path)
    normalized = [normalize_event(c) for c in connections]
    print(f"[*] Loaded {len(normalized)} connections")

    findings = analyze_beaconing(normalized)
    print(f"[*] Beacon detections: {len(findings)}")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    with open(output_path / "beacon_findings.json", "w", encoding="utf-8") as f:
        json.dump({
            "hunt_id": f"TH-BEACON-{datetime.date.today().isoformat()}",
            "total_connections": len(normalized),
            "findings_count": len(findings),
            "findings": findings,
        }, f, indent=2)

    with open(output_path / "beacon_report.md", "w", encoding="utf-8") as f:
        f.write(f"# Beaconing Frequency Analysis Report\n\n")
        f.write(f"**Date**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Connections Analyzed**: {len(normalized)}\n")
        f.write(f"**Findings**: {len(findings)}\n\n")
        for bf in findings[:20]:
            f.write(f"## [{bf['risk_level']}] {bf['src_ip']} -> {bf['destination']}\n")
            f.write(f"- Interval: {bf['avg_interval_sec']}s (CV: {bf['cv']})\n")
            f.write(f"- Jitter: ~{bf['jitter_pct']}%\n")
            f.write(f"- Connections: {bf['connection_count']}\n")
            f.write(f"- Indicators: {', '.join(bf['indicators'])}\n\n")

    print(f"[+] Results written to {output_dir}")


def main():
    parser = argparse.ArgumentParser(description="Beaconing Frequency Analysis")
    parser.add_argument("--input", "-i", required=True, help="Path to connection logs")
    parser.add_argument("--output", "-o", default="./beacon_hunt_output", help="Output directory")
    args = parser.parse_args()
    run_hunt(args.input, args.output)


if __name__ == "__main__":
    main()
