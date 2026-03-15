#!/usr/bin/env python3
"""
DNS Tunneling Detection Script for Zeek Logs
Analyzes dns.log for tunneling indicators: query length, entropy,
unique subdomains, record types, and query volume.
"""

import json
import csv
import argparse
import datetime
import math
from collections import defaultdict, Counter
from pathlib import Path

ENTROPY_THRESHOLD = 3.5
QUERY_LENGTH_THRESHOLD = 50
SUBDOMAIN_LENGTH_THRESHOLD = 25
UNIQUE_SUBDOMAIN_THRESHOLD = 50
QUERY_COUNT_THRESHOLD = 100

SUSPICIOUS_RECORD_TYPES = {"TXT", "NULL", "CNAME", "MX", "KEY", "SRV"}


def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def parse_zeek_dns(input_path: str) -> list[dict]:
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


def detect_dns_tunneling(queries: list[dict]) -> list[dict]:
    domain_stats = defaultdict(lambda: {
        "queries": 0, "unique_subdomains": set(), "total_length": 0,
        "max_length": 0, "record_types": Counter(), "sources": set(),
        "subdomain_entropy_samples": [],
    })

    for q in queries:
        query = q.get("query", "")
        src = q.get("id.orig_h", q.get("src_ip", q.get("source_ip", "")))
        qtype = q.get("qtype_name", q.get("query_type", "A"))
        if not query or len(query.split(".")) < 3:
            continue

        parts = query.rstrip(".").split(".")
        base_domain = ".".join(parts[-2:])
        subdomain = ".".join(parts[:-2])

        stats = domain_stats[(src, base_domain)]
        stats["queries"] += 1
        stats["unique_subdomains"].add(subdomain)
        stats["total_length"] += len(query)
        stats["max_length"] = max(stats["max_length"], len(query))
        stats["record_types"][qtype] += 1
        stats["sources"].add(src)
        if len(stats["subdomain_entropy_samples"]) < 100:
            stats["subdomain_entropy_samples"].append(subdomain)

    findings = []
    for (src, base_domain), stats in domain_stats.items():
        if stats["queries"] < 20:
            continue

        avg_len = stats["total_length"] / stats["queries"]
        unique_subs = len(stats["unique_subdomains"])

        avg_entropy = 0.0
        if stats["subdomain_entropy_samples"]:
            entropies = [calculate_entropy(s) for s in stats["subdomain_entropy_samples"]]
            avg_entropy = sum(entropies) / len(entropies)

        risk = 0
        indicators = []

        if avg_len > QUERY_LENGTH_THRESHOLD:
            risk += 25
            indicators.append(f"High avg query length: {avg_len:.1f}")
        if unique_subs > UNIQUE_SUBDOMAIN_THRESHOLD:
            risk += 25
            indicators.append(f"High unique subdomains: {unique_subs}")
        if avg_entropy > ENTROPY_THRESHOLD:
            risk += 25
            indicators.append(f"High subdomain entropy: {avg_entropy:.2f}")
        if stats["queries"] > QUERY_COUNT_THRESHOLD:
            risk += 10
            indicators.append(f"High query volume: {stats['queries']}")

        suspicious_types = sum(stats["record_types"].get(rt, 0) for rt in SUSPICIOUS_RECORD_TYPES)
        if suspicious_types > stats["queries"] * 0.5:
            risk += 15
            indicators.append(f"Unusual record types: {dict(stats['record_types'])}")

        if risk < 30:
            continue

        risk_level = "CRITICAL" if risk >= 70 else "HIGH" if risk >= 50 else "MEDIUM"
        findings.append({
            "source_ip": src,
            "base_domain": base_domain,
            "query_count": stats["queries"],
            "unique_subdomains": unique_subs,
            "avg_query_length": round(avg_len, 1),
            "max_query_length": stats["max_length"],
            "avg_subdomain_entropy": round(avg_entropy, 3),
            "record_types": dict(stats["record_types"]),
            "risk_score": risk,
            "risk_level": risk_level,
            "indicators": indicators,
        })

    return sorted(findings, key=lambda x: x["risk_score"], reverse=True)


def run_hunt(input_path: str, output_dir: str) -> None:
    print(f"[*] DNS Tunneling Hunt - {datetime.datetime.now().isoformat()}")
    queries = parse_zeek_dns(input_path)
    print(f"[*] Loaded {len(queries)} DNS queries")
    findings = detect_dns_tunneling(queries)
    print(f"[!] DNS tunneling detections: {len(findings)}")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    with open(output_path / "dns_tunnel_findings.json", "w", encoding="utf-8") as f:
        json.dump({"hunt_id": f"TH-DNSTUNNEL-{datetime.date.today().isoformat()}",
                    "total_queries": len(queries), "findings": findings}, f, indent=2)
    print(f"[+] Results written to {output_dir}")


def main():
    parser = argparse.ArgumentParser(description="DNS Tunneling Detection")
    parser.add_argument("--input", "-i", required=True)
    parser.add_argument("--output", "-o", default="./dns_tunnel_hunt_output")
    args = parser.parse_args()
    run_hunt(args.input, args.output)


if __name__ == "__main__":
    main()
