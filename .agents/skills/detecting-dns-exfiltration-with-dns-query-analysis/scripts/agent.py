#!/usr/bin/env python3
"""DNS exfiltration detection agent using entropy analysis and query pattern anomalies.

Analyzes DNS query logs for tunneling indicators: high entropy subdomains,
excessive query length, abnormal TXT record usage, and volume spikes.
"""

import argparse
import json
import math
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime

KNOWN_TUNNEL_DOMAINS = {
    "dnscat2", "iodine", "dns2tcp", "heyoka", "ozyman",
    "tuns", "dnscapy", "dns-tunnel",
}

TXT_THRESHOLD = 0.3
ENTROPY_THRESHOLD = 3.5
SUBDOMAIN_LENGTH_THRESHOLD = 40
QUERY_RATE_THRESHOLD = 100


def calculate_entropy(text):
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def parse_dns_log(filepath, log_format="zeek"):
    queries = []
    with open(filepath, "r") as f:
        if log_format == "zeek":
            headers = None
            for line in f:
                if line.startswith("#fields"):
                    headers = line.strip().split("\t")[1:]
                    continue
                if line.startswith("#"):
                    continue
                if not headers:
                    continue
                fields = line.strip().split("\t")
                if len(fields) >= len(headers):
                    record = dict(zip(headers, fields))
                    queries.append({
                        "timestamp": record.get("ts", ""),
                        "source": record.get("id.orig_h", ""),
                        "query": record.get("query", ""),
                        "qtype": record.get("qtype_name", record.get("qtype", "")),
                        "rcode": record.get("rcode_name", ""),
                        "answers": record.get("answers", ""),
                    })
        else:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3:
                    queries.append({
                        "timestamp": parts[0],
                        "source": parts[1] if len(parts) > 3 else "",
                        "query": parts[-2] if len(parts) > 2 else parts[1],
                        "qtype": parts[-1] if len(parts) > 2 else "",
                    })
    return queries


def analyze_queries(queries):
    findings = []
    domain_stats = defaultdict(lambda: {"count": 0, "sources": set(),
                                         "entropies": [], "lengths": [],
                                         "txt_count": 0, "total": 0})
    for q in queries:
        query = q.get("query", "")
        if not query or query == "-":
            continue
        parts = query.rstrip(".").split(".")
        if len(parts) < 2:
            continue
        base_domain = ".".join(parts[-2:])
        subdomain = ".".join(parts[:-2])

        stats = domain_stats[base_domain]
        stats["count"] += 1
        stats["total"] += 1
        stats["sources"].add(q.get("source", ""))

        if subdomain:
            entropy = calculate_entropy(subdomain.replace(".", ""))
            stats["entropies"].append(entropy)
            stats["lengths"].append(len(subdomain))

            if entropy > ENTROPY_THRESHOLD and len(subdomain) > SUBDOMAIN_LENGTH_THRESHOLD:
                findings.append({
                    "type": "high_entropy_long_subdomain",
                    "query": query,
                    "subdomain": subdomain,
                    "entropy": round(entropy, 3),
                    "length": len(subdomain),
                    "source": q.get("source", ""),
                    "severity": "HIGH",
                })

        if q.get("qtype", "").upper() in ("TXT", "NULL", "CNAME"):
            stats["txt_count"] += 1

    for domain, stats in domain_stats.items():
        if stats["total"] > QUERY_RATE_THRESHOLD:
            avg_entropy = (sum(stats["entropies"]) / len(stats["entropies"])
                           if stats["entropies"] else 0)
            avg_length = (sum(stats["lengths"]) / len(stats["lengths"])
                          if stats["lengths"] else 0)
            txt_ratio = stats["txt_count"] / stats["total"]

            score = 0
            if avg_entropy > ENTROPY_THRESHOLD:
                score += 30
            if avg_length > 30:
                score += 20
            if txt_ratio > TXT_THRESHOLD:
                score += 25
            if stats["total"] > 500:
                score += 25

            if score >= 50:
                findings.append({
                    "type": "suspected_dns_tunnel",
                    "domain": domain,
                    "total_queries": stats["total"],
                    "avg_entropy": round(avg_entropy, 3),
                    "avg_subdomain_length": round(avg_length, 1),
                    "txt_ratio": round(txt_ratio, 3),
                    "tunnel_score": score,
                    "unique_sources": len(stats["sources"]),
                    "severity": "CRITICAL" if score >= 75 else "HIGH",
                })

    return findings


def main():
    parser = argparse.ArgumentParser(description="DNS Exfiltration Detector")
    parser.add_argument("--dns-log", required=True, help="DNS log file (Zeek or text)")
    parser.add_argument("--format", choices=["zeek", "text"], default="zeek")
    parser.add_argument("--entropy-threshold", type=float, default=ENTROPY_THRESHOLD)
    parser.add_argument("--length-threshold", type=int, default=SUBDOMAIN_LENGTH_THRESHOLD)
    args = parser.parse_args()

    global ENTROPY_THRESHOLD, SUBDOMAIN_LENGTH_THRESHOLD
    ENTROPY_THRESHOLD = args.entropy_threshold
    SUBDOMAIN_LENGTH_THRESHOLD = args.length_threshold

    queries = parse_dns_log(args.dns_log, args.format)
    findings = analyze_queries(queries)

    results = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "total_queries_analyzed": len(queries),
        "findings": findings,
        "total_findings": len(findings),
    }
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
