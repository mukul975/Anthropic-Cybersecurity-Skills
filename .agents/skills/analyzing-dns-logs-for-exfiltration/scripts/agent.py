#!/usr/bin/env python3
"""DNS exfiltration detection agent using entropy analysis and query pattern detection."""

import math
import os
import sys
import json
import csv
import datetime
from collections import Counter, defaultdict


def shannon_entropy(text):
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    counter = Counter(text.lower())
    length = len(text)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )
    return round(entropy, 4)


def extract_subdomain(fqdn):
    """Extract the subdomain portion from a fully qualified domain name."""
    parts = fqdn.rstrip(".").split(".")
    if len(parts) > 2:
        return ".".join(parts[:-2])
    return ""


def extract_registered_domain(fqdn):
    """Extract the registered domain (SLD + TLD) from an FQDN."""
    parts = fqdn.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return fqdn


def detect_tunneling(dns_records, subdomain_len_threshold=50, min_queries=20):
    """Detect DNS tunneling based on subdomain length anomalies."""
    domain_stats = defaultdict(lambda: {"queries": 0, "unique_queries": set(),
                                         "subdomain_lengths": [], "sources": set()})
    for record in dns_records:
        query = record.get("query", "")
        src = record.get("src_ip", "unknown")
        subdomain = extract_subdomain(query)
        reg_domain = extract_registered_domain(query)
        if len(subdomain) > subdomain_len_threshold:
            stats = domain_stats[reg_domain]
            stats["queries"] += 1
            stats["unique_queries"].add(query)
            stats["subdomain_lengths"].append(len(subdomain))
            stats["sources"].add(src)
    alerts = []
    for domain, stats in domain_stats.items():
        if stats["queries"] >= min_queries:
            avg_len = sum(stats["subdomain_lengths"]) / len(stats["subdomain_lengths"])
            max_len = max(stats["subdomain_lengths"])
            alerts.append({
                "domain": domain,
                "queries": stats["queries"],
                "unique_queries": len(stats["unique_queries"]),
                "avg_subdomain_length": round(avg_len, 1),
                "max_subdomain_length": max_len,
                "sources": list(stats["sources"]),
                "verdict": "CRITICAL - Likely DNS tunneling",
            })
    return sorted(alerts, key=lambda x: x["avg_subdomain_length"], reverse=True)


def detect_dga(dns_records, entropy_threshold=3.5, min_sld_length=12):
    """Detect Domain Generation Algorithm queries using entropy scoring."""
    suspicious = defaultdict(lambda: {"count": 0, "sources": set(), "entropies": []})
    for record in dns_records:
        query = record.get("query", "").rstrip(".")
        src = record.get("src_ip", "unknown")
        parts = query.split(".")
        if len(parts) < 2:
            continue
        sld = parts[-2]
        if len(sld) < min_sld_length:
            continue
        ent = shannon_entropy(sld)
        if ent > entropy_threshold:
            suspicious[query]["count"] += 1
            suspicious[query]["sources"].add(src)
            suspicious[query]["entropies"].append(ent)
    alerts = []
    for domain, data in suspicious.items():
        avg_entropy = sum(data["entropies"]) / len(data["entropies"])
        alerts.append({
            "domain": domain,
            "queries": data["count"],
            "avg_entropy": round(avg_entropy, 4),
            "sources": list(data["sources"]),
            "verdict": "HIGH - Possible DGA domain",
        })
    return sorted(alerts, key=lambda x: x["avg_entropy"], reverse=True)


def detect_volume_anomaly(dns_records, z_score_threshold=3.0):
    """Detect hosts with anomalously high DNS query volumes."""
    host_counts = defaultdict(int)
    for record in dns_records:
        src = record.get("src_ip", "unknown")
        host_counts[src] += 1
    if not host_counts:
        return []
    values = list(host_counts.values())
    mean_q = sum(values) / len(values)
    if len(values) < 2:
        return []
    variance = sum((x - mean_q) ** 2 for x in values) / (len(values) - 1)
    stdev_q = variance ** 0.5
    if stdev_q == 0:
        return []
    anomalies = []
    for host, count in host_counts.items():
        z = (count - mean_q) / stdev_q
        if z > z_score_threshold:
            anomalies.append({
                "src_ip": host,
                "queries": count,
                "z_score": round(z, 2),
                "mean": round(mean_q, 1),
                "verdict": "HIGH - Anomalous query volume",
            })
    return sorted(anomalies, key=lambda x: x["z_score"], reverse=True)


def detect_txt_abuse(dns_records, threshold=100):
    """Detect excessive TXT record queries (common tunneling method)."""
    txt_counts = defaultdict(lambda: {"count": 0, "unique_domains": set()})
    for record in dns_records:
        qtype = str(record.get("query_type", "")).upper()
        if qtype in ("TXT", "16"):
            src = record.get("src_ip", "unknown")
            txt_counts[src]["count"] += 1
            txt_counts[src]["unique_domains"].add(record.get("query", ""))
    alerts = []
    for src, data in txt_counts.items():
        if data["count"] > threshold:
            level = "CRITICAL" if data["count"] > 1000 else "HIGH" if data["count"] > 500 else "MEDIUM"
            alerts.append({
                "src_ip": src,
                "txt_queries": data["count"],
                "unique_domains": len(data["unique_domains"]),
                "verdict": f"{level} - Possible DNS tunneling via TXT records",
            })
    return sorted(alerts, key=lambda x: x["txt_queries"], reverse=True)


def estimate_exfil_volume(dns_records, target_domain):
    """Estimate data volume encoded in DNS queries to a specific domain."""
    total_encoded_bytes = 0
    query_count = 0
    for record in dns_records:
        query = record.get("query", "")
        if target_domain in query:
            subdomain = extract_subdomain(query)
            total_encoded_bytes += len(subdomain)
            query_count += 1
    decoded_bytes = int(total_encoded_bytes * 0.75)  # Base64 decode factor
    return {
        "target_domain": target_domain,
        "total_queries": query_count,
        "encoded_bytes": total_encoded_bytes,
        "estimated_decoded_bytes": decoded_bytes,
        "estimated_kb": round(decoded_bytes / 1024, 1),
        "estimated_mb": round(decoded_bytes / (1024 * 1024), 3),
    }


def parse_zeek_dns_log(log_path):
    """Parse a Zeek dns.log file into structured records."""
    records = []
    with open(log_path, "r") as f:
        for line in f:
            if line.startswith("#"):
                continue
            parts = line.strip().split("\t")
            if len(parts) >= 10:
                records.append({
                    "timestamp": parts[0],
                    "src_ip": parts[2],
                    "src_port": parts[3],
                    "dst_ip": parts[4],
                    "query": parts[9] if len(parts) > 9 else "",
                    "query_type": parts[13] if len(parts) > 13 else "",
                })
    return records


if __name__ == "__main__":
    print("=" * 60)
    print("DNS Exfiltration Detection Agent")
    print("Tunneling, DGA, volume anomaly, and TXT abuse detection")
    print("=" * 60)

    # Demo with synthetic DNS records
    demo_records = [
        {"query": f"{'a' * 60}.evil-tunnel.com", "src_ip": "192.168.1.105",
         "query_type": "TXT"} for _ in range(50)
    ] + [
        {"query": "x8kj2m9p4qw7nz3.xyz", "src_ip": "192.168.1.110",
         "query_type": "A"} for _ in range(5)
    ] + [
        {"query": "google.com", "src_ip": "192.168.1.50", "query_type": "A"}
        for _ in range(10)
    ]

    print("\n--- DNS Tunneling Detection ---")
    tunneling = detect_tunneling(demo_records, subdomain_len_threshold=30, min_queries=10)
    for t in tunneling:
        print(f"[!] {t['domain']}: {t['queries']} queries, "
              f"avg subdomain len={t['avg_subdomain_length']}")

    print("\n--- DGA Detection ---")
    dga = detect_dga(demo_records, entropy_threshold=3.0, min_sld_length=10)
    for d in dga[:5]:
        print(f"[!] {d['domain']}: entropy={d['avg_entropy']}")

    print("\n--- TXT Record Abuse ---")
    txt = detect_txt_abuse(demo_records, threshold=10)
    for t in txt:
        print(f"[!] {t['src_ip']}: {t['txt_queries']} TXT queries")

    print("\n--- Entropy Examples ---")
    examples = ["google", "x8kj2m9p4qw7n", "aGVsbG8gd29ybGQ"]
    for ex in examples:
        print(f"  '{ex}' -> entropy={shannon_entropy(ex)}")
