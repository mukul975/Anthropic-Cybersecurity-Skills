#!/usr/bin/env python3
"""Detect DNS exfiltration from Zeek dns.log by analyzing entropy and query patterns."""

import argparse
import json
import math
import sys
from collections import defaultdict


SAFE_DOMAINS = {
    "in-addr.arpa", "ip6.arpa", "local", "localhost",
    "google.com", "googleapis.com", "gstatic.com",
    "microsoft.com", "windows.net", "windowsupdate.com",
    "apple.com", "icloud.com", "akamai.net", "cloudflare.com",
    "amazonaws.com", "azure.com",
}


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = defaultdict(int)
    for ch in data:
        freq[ch] += 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return round(entropy, 4)


def parse_zeek_dns_log(log_path: str) -> list:
    records = []
    field_names = []
    separator = "\t"
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#separator"):
                sep_value = line.split(" ", 1)[1] if " " in line else "\\x09"
                if sep_value == "\\x09":
                    separator = "\t"
                else:
                    separator = sep_value
                continue
            if line.startswith("#fields"):
                field_names = line.split(separator)[1:] if separator == "\t" else line.split("\t")[1:]
                field_names = [f.strip() for f in field_names]
                continue
            if line.startswith("#"):
                continue
            if not field_names:
                continue
            values = line.split(separator)
            if len(values) < len(field_names):
                continue
            record = {}
            for i, name in enumerate(field_names):
                record[name] = values[i] if i < len(values) else "-"
            records.append(record)
    return records


def extract_parent_domain(fqdn: str, levels: int = 2) -> str:
    parts = fqdn.rstrip(".").split(".")
    if len(parts) <= levels:
        return fqdn.rstrip(".")
    return ".".join(parts[-levels:])


def extract_subdomain(fqdn: str, levels: int = 2) -> str:
    parts = fqdn.rstrip(".").split(".")
    if len(parts) <= levels:
        return ""
    return ".".join(parts[:-levels])


def analyze_dns_log(log_path: str, entropy_threshold: float, subdomain_threshold: int,
                    label_length_threshold: int) -> dict:
    records = parse_zeek_dns_log(log_path)
    domain_stats = defaultdict(lambda: {
        "subdomains": set(),
        "entropies": [],
        "max_label_len": 0,
        "source_ips": set(),
        "query_count": 0,
        "qtypes": defaultdict(int),
        "sample_queries": [],
    })

    total_queries = 0
    for rec in records:
        query = rec.get("query", "-")
        if query == "-" or not query:
            continue
        total_queries += 1
        src_ip = rec.get("id.orig_h", "unknown")
        qtype = rec.get("qtype_name", "unknown")
        parent = extract_parent_domain(query)
        subdomain = extract_subdomain(query)

        if parent.lower() in SAFE_DOMAINS:
            continue

        stats = domain_stats[parent]
        stats["query_count"] += 1
        stats["source_ips"].add(src_ip)
        stats["qtypes"][qtype] += 1

        if subdomain:
            stats["subdomains"].add(subdomain)
            ent = shannon_entropy(subdomain)
            stats["entropies"].append(ent)
            labels = subdomain.split(".")
            for label in labels:
                if len(label) > stats["max_label_len"]:
                    stats["max_label_len"] = len(label)
            if len(stats["sample_queries"]) < 5:
                stats["sample_queries"].append(query)

    flagged = []
    for domain, stats in domain_stats.items():
        indicators = []
        avg_entropy = 0.0
        if stats["entropies"]:
            avg_entropy = round(sum(stats["entropies"]) / len(stats["entropies"]), 4)
        unique_count = len(stats["subdomains"])
        max_label = stats["max_label_len"]

        if avg_entropy >= entropy_threshold and unique_count >= 5:
            indicators.append("high_entropy")
        if max_label >= label_length_threshold:
            indicators.append("long_labels")
        if unique_count >= subdomain_threshold:
            indicators.append("high_subdomain_count")
        txt_ratio = stats["qtypes"].get("TXT", 0) / max(stats["query_count"], 1)
        if txt_ratio > 0.5 and stats["query_count"] > 20:
            indicators.append("high_txt_ratio")
        null_ratio = stats["qtypes"].get("NULL", 0) / max(stats["query_count"], 1)
        if null_ratio > 0.3:
            indicators.append("null_queries")

        if not indicators:
            continue

        risk_score = 0.0
        if "high_entropy" in indicators:
            risk_score += min(avg_entropy, 5.0)
        if "long_labels" in indicators:
            risk_score += min(max_label / 15.0, 3.0)
        if "high_subdomain_count" in indicators:
            risk_score += min(unique_count / 100.0, 3.0)
        if "high_txt_ratio" in indicators:
            risk_score += 1.5
        if "null_queries" in indicators:
            risk_score += 1.0
        risk_score = min(round(risk_score, 1), 10.0)

        flagged.append({
            "domain": domain,
            "unique_subdomains": unique_count,
            "avg_entropy": avg_entropy,
            "max_label_length": max_label,
            "query_count": stats["query_count"],
            "source_ips": sorted(stats["source_ips"]),
            "qtypes": dict(stats["qtypes"]),
            "risk_score": risk_score,
            "indicators": indicators,
            "sample_queries": stats["sample_queries"],
        })

    flagged.sort(key=lambda x: x["risk_score"], reverse=True)
    return {
        "analysis_summary": {
            "log_file": log_path,
            "total_queries_analyzed": total_queries,
            "unique_domains": len(domain_stats),
            "flagged_domains": len(flagged),
            "entropy_threshold": entropy_threshold,
            "subdomain_threshold": subdomain_threshold,
            "label_length_threshold": label_length_threshold,
        },
        "flagged_domains": flagged,
    }


def main():
    parser = argparse.ArgumentParser(description="DNS Exfiltration Detection from Zeek dns.log")
    parser.add_argument("--log-file", required=True, help="Path to Zeek dns.log file")
    parser.add_argument("--entropy-threshold", type=float, default=3.5,
                        help="Shannon entropy threshold for flagging (default: 3.5)")
    parser.add_argument("--subdomain-threshold", type=int, default=50,
                        help="Unique subdomain count threshold (default: 50)")
    parser.add_argument("--label-length-threshold", type=int, default=52,
                        help="DNS label length threshold for flagging (default: 52)")
    parser.add_argument("--output", type=str, default=None,
                        help="Output JSON file path")
    args = parser.parse_args()

    result = analyze_dns_log(args.log_file, args.entropy_threshold,
                             args.subdomain_threshold, args.label_length_threshold)
    report = json.dumps(result, indent=2)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
    print(report)


if __name__ == "__main__":
    main()
