#!/usr/bin/env python3
"""
Data Exfiltration Detection Script
Analyzes network logs for unusual data transfer volumes, DNS tunneling,
cloud storage uploads, and protocol abuse indicators.
"""

import json
import csv
import argparse
import datetime
import math
from collections import defaultdict
from pathlib import Path

CLOUD_STORAGE_DOMAINS = {
    "drive.google.com", "docs.google.com", "storage.googleapis.com",
    "dropbox.com", "dl.dropboxusercontent.com",
    "box.com", "upload.box.com",
    "onedrive.live.com", "sharepoint.com",
    "mega.nz", "mega.co.nz",
    "wetransfer.com", "sendspace.com",
    "mediafire.com", "4shared.com",
    "pastebin.com", "paste.ee", "hastebin.com",
    "github.com", "gitlab.com", "bitbucket.org",
    "discord.com", "cdn.discordapp.com",
    "api.telegram.org", "slack.com",
}

LEGITIMATE_HIGH_VOLUME = {
    "windowsupdate.com", "microsoft.com", "windows.com",
    "googleapis.com", "gstatic.com",
    "amazonaws.com", "cloudfront.net",
    "apple.com", "icloud.com",
    "adobe.com", "akamai.net",
}


def parse_logs(input_path: str) -> list[dict]:
    path = Path(input_path)
    if path.suffix == ".json":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else data.get("events", [])
    elif path.suffix == ".csv":
        with open(path, "r", encoding="utf-8-sig") as f:
            return [dict(row) for row in csv.DictReader(f)]
    return []


def normalize_event(event: dict) -> dict:
    field_map = {
        "timestamp": ["ts", "timestamp", "_time", "@timestamp"],
        "src_ip": ["src_ip", "id.orig_h", "source_ip", "LocalIP"],
        "dst_ip": ["dst_ip", "id.resp_h", "dest_ip", "RemoteIP"],
        "domain": ["domain", "host", "query", "dest", "RemoteUrl"],
        "bytes_out": ["bytes_out", "orig_bytes", "SentBytes", "bytes_sent"],
        "bytes_in": ["bytes_in", "resp_bytes", "ReceivedBytes", "bytes_recv"],
        "method": ["method", "http_method", "Method"],
        "user": ["user", "User", "AccountName", "user.name"],
        "query_type": ["query_type", "qtype_name", "QueryType"],
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


def is_legitimate(domain: str) -> bool:
    domain = domain.lower()
    return any(domain.endswith(d) for d in LEGITIMATE_HIGH_VOLUME)


def is_cloud_storage(domain: str) -> bool:
    domain = domain.lower()
    return any(domain.endswith(d) or d in domain for d in CLOUD_STORAGE_DOMAINS)


def detect_volume_anomalies(events: list[dict]) -> list[dict]:
    host_data = defaultdict(lambda: {"bytes_out": 0, "destinations": set(), "count": 0})
    for e in events:
        src = e.get("src_ip", "")
        domain = e.get("domain", "") or e.get("dst_ip", "")
        if not src or is_legitimate(domain):
            continue
        try:
            bytes_out = int(e.get("bytes_out", 0) or 0)
        except ValueError:
            bytes_out = 0
        host_data[src]["bytes_out"] += bytes_out
        host_data[src]["destinations"].add(domain)
        host_data[src]["count"] += 1

    findings = []
    threshold_bytes = 100 * 1024 * 1024  # 100 MB

    for src, data in host_data.items():
        if data["bytes_out"] > threshold_bytes:
            mb = data["bytes_out"] / (1024 * 1024)
            risk = min(90, 30 + int(mb / 100) * 10)
            findings.append({
                "detection_type": "VOLUME_ANOMALY",
                "technique": "T1041",
                "src_ip": src,
                "bytes_out": data["bytes_out"],
                "mb_out": round(mb, 2),
                "unique_destinations": len(data["destinations"]),
                "connection_count": data["count"],
                "risk_score": risk,
                "risk_level": "CRITICAL" if risk >= 70 else "HIGH" if risk >= 50 else "MEDIUM",
                "indicators": [f"High outbound volume: {round(mb, 2)} MB to {len(data['destinations'])} destinations"],
            })

    return sorted(findings, key=lambda x: x["bytes_out"], reverse=True)


def detect_cloud_exfiltration(events: list[dict]) -> list[dict]:
    cloud_uploads = defaultdict(lambda: {"bytes_out": 0, "services": set(), "count": 0})
    for e in events:
        domain = e.get("domain", "")
        method = e.get("method", "").upper()
        if not is_cloud_storage(domain):
            continue
        if method not in ("POST", "PUT", "PATCH", ""):
            continue
        src = e.get("src_ip", "") or e.get("user", "")
        try:
            bytes_out = int(e.get("bytes_out", 0) or 0)
        except ValueError:
            bytes_out = 0
        cloud_uploads[src]["bytes_out"] += bytes_out
        cloud_uploads[src]["services"].add(domain)
        cloud_uploads[src]["count"] += 1

    findings = []
    for src, data in cloud_uploads.items():
        if data["bytes_out"] > 50 * 1024 * 1024:  # 50 MB
            mb = data["bytes_out"] / (1024 * 1024)
            findings.append({
                "detection_type": "CLOUD_EXFILTRATION",
                "technique": "T1567.002",
                "source": src,
                "bytes_out": data["bytes_out"],
                "mb_out": round(mb, 2),
                "cloud_services": list(data["services"]),
                "upload_count": data["count"],
                "risk_score": 60,
                "risk_level": "HIGH",
                "indicators": [f"Cloud upload: {round(mb, 2)} MB to {', '.join(data['services'])}"],
            })

    return sorted(findings, key=lambda x: x["bytes_out"], reverse=True)


def detect_dns_exfiltration(events: list[dict]) -> list[dict]:
    domain_stats = defaultdict(lambda: {"queries": 0, "unique_subs": set(), "total_len": 0})
    for e in events:
        domain = e.get("domain", "")
        if not domain or "." not in domain:
            continue
        parts = domain.split(".")
        if len(parts) < 3:
            continue
        base = ".".join(parts[-2:])
        sub = ".".join(parts[:-2])
        domain_stats[base]["queries"] += 1
        domain_stats[base]["unique_subs"].add(sub)
        domain_stats[base]["total_len"] += len(domain)

    findings = []
    for base, stats in domain_stats.items():
        if stats["queries"] < 50 or is_legitimate(base):
            continue
        avg_len = stats["total_len"] / stats["queries"]
        unique = len(stats["unique_subs"])
        risk = 0
        indicators = []
        if unique > 50:
            risk += 30
            indicators.append(f"High unique subdomains: {unique}")
        if avg_len > 40:
            risk += 25
            indicators.append(f"Long query avg: {avg_len:.1f}")
        if stats["queries"] > 500:
            risk += 15
            indicators.append(f"High volume: {stats['queries']} queries")
        if risk >= 30:
            findings.append({
                "detection_type": "DNS_EXFILTRATION",
                "technique": "T1048.003",
                "domain": base,
                "query_count": stats["queries"],
                "unique_subdomains": unique,
                "avg_query_length": round(avg_len, 1),
                "risk_score": risk,
                "risk_level": "CRITICAL" if risk >= 70 else "HIGH" if risk >= 50 else "MEDIUM",
                "indicators": indicators,
            })

    return sorted(findings, key=lambda x: x["risk_score"], reverse=True)


def run_hunt(input_path: str, output_dir: str) -> None:
    print(f"[*] Data Exfiltration Hunt - {datetime.datetime.now().isoformat()}")
    events = [normalize_event(e) for e in parse_logs(input_path)]
    print(f"[*] Loaded {len(events)} events")

    vol_findings = detect_volume_anomalies(events)
    cloud_findings = detect_cloud_exfiltration(events)
    dns_findings = detect_dns_exfiltration(events)
    all_findings = vol_findings + cloud_findings + dns_findings

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    with open(output_path / "exfil_findings.json", "w", encoding="utf-8") as f:
        json.dump({
            "hunt_id": f"TH-EXFIL-{datetime.date.today().isoformat()}",
            "total_events": len(events),
            "findings": all_findings,
        }, f, indent=2)

    with open(output_path / "hunt_report.md", "w", encoding="utf-8") as f:
        f.write(f"# Data Exfiltration Hunt Report\n\n")
        f.write(f"**Date**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Volume Anomalies**: {len(vol_findings)}\n")
        f.write(f"**Cloud Exfil**: {len(cloud_findings)}\n")
        f.write(f"**DNS Exfil**: {len(dns_findings)}\n\n")
        for finding in all_findings[:20]:
            f.write(f"### [{finding['risk_level']}] {finding['detection_type']}\n")
            f.write(f"- {', '.join(finding['indicators'])}\n\n")

    print(f"[+] {len(all_findings)} findings written to {output_dir}")


def main():
    parser = argparse.ArgumentParser(description="Data Exfiltration Detection")
    subparsers = parser.add_subparsers(dest="command")
    hunt_p = subparsers.add_parser("hunt")
    hunt_p.add_argument("--input", "-i", required=True)
    hunt_p.add_argument("--output", "-o", default="./exfil_output")
    subparsers.add_parser("queries")
    args = parser.parse_args()

    if args.command == "hunt":
        run_hunt(args.input, args.output)
    elif args.command == "queries":
        print("=== Data Exfiltration Queries ===\n")
        print("--- Volume Anomaly ---")
        print("index=proxy | stats sum(bytes_out) as total by src_ip\n| eval MB=round(total/1048576,2)\n| where MB > 100 | sort -MB")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
