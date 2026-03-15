#!/usr/bin/env python3
"""Agent for detecting DNS tunneling via entropy and statistical analysis."""

import os
import json
import math
import argparse
from collections import Counter, defaultdict
from datetime import datetime

from scapy.all import rdpcap, DNS, DNSQR, DNSRR


def shannon_entropy(data):
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counter.values())


def extract_dns_queries(pcap_path):
    """Extract DNS queries from a PCAP file using scapy."""
    packets = rdpcap(pcap_path)
    queries = []
    for pkt in packets:
        if pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode().rstrip(".")
            qtype = pkt[DNSQR].qtype
            src_ip = pkt.src if hasattr(pkt, "src") else ""
            queries.append({
                "query": qname,
                "qtype": qtype,
                "src_ip": src_ip,
                "timestamp": float(pkt.time),
            })
    return queries


def analyze_entropy(queries, threshold=3.8):
    """Flag queries with high Shannon entropy in subdomain labels."""
    suspicious = []
    for q in queries:
        domain = q["query"]
        labels = domain.split(".")
        if len(labels) < 2:
            continue
        subdomain = ".".join(labels[:-2])
        if not subdomain:
            continue
        entropy = shannon_entropy(subdomain)
        if entropy > threshold:
            suspicious.append({
                "query": domain,
                "subdomain": subdomain,
                "entropy": round(entropy, 3),
                "length": len(subdomain),
                "src_ip": q.get("src_ip", ""),
            })
    return sorted(suspicious, key=lambda x: x["entropy"], reverse=True)


def analyze_query_lengths(queries, length_threshold=50):
    """Detect queries with unusually long domain names."""
    long_queries = []
    for q in queries:
        if len(q["query"]) > length_threshold:
            long_queries.append({
                "query": q["query"],
                "length": len(q["query"]),
                "src_ip": q.get("src_ip", ""),
            })
    return long_queries


def analyze_txt_records(pcap_path):
    """Detect high volume of TXT record queries to single domains."""
    packets = rdpcap(pcap_path)
    txt_counts = defaultdict(int)
    for pkt in packets:
        if pkt.haslayer(DNSQR) and pkt[DNSQR].qtype == 16:
            domain = pkt[DNSQR].qname.decode().rstrip(".")
            parent = ".".join(domain.split(".")[-2:])
            txt_counts[parent] += 1
    suspicious = [
        {"domain": d, "txt_query_count": c}
        for d, c in txt_counts.items() if c > 20
    ]
    return sorted(suspicious, key=lambda x: x["txt_query_count"], reverse=True)


def analyze_subdomain_cardinality(queries):
    """Detect domains with high unique subdomain count (tunneling indicator)."""
    parent_subdomains = defaultdict(set)
    for q in queries:
        labels = q["query"].split(".")
        if len(labels) >= 3:
            parent = ".".join(labels[-2:])
            subdomain = ".".join(labels[:-2])
            parent_subdomains[parent].add(subdomain)
    high_cardinality = []
    for parent, subs in parent_subdomains.items():
        if len(subs) > 50:
            high_cardinality.append({
                "parent_domain": parent,
                "unique_subdomains": len(subs),
                "sample_subdomains": list(subs)[:5],
            })
    return sorted(high_cardinality, key=lambda x: x["unique_subdomains"], reverse=True)


def analyze_character_distribution(queries):
    """Detect non-standard character frequency in query labels."""
    suspicious = []
    for q in queries:
        labels = q["query"].split(".")
        subdomain = ".".join(labels[:-2])
        if len(subdomain) < 10:
            continue
        alpha_count = sum(1 for c in subdomain if c.isalpha())
        digit_count = sum(1 for c in subdomain if c.isdigit())
        total = len(subdomain.replace(".", ""))
        if total == 0:
            continue
        digit_ratio = digit_count / total
        if digit_ratio > 0.4 or (alpha_count / total) < 0.5:
            suspicious.append({
                "query": q["query"],
                "digit_ratio": round(digit_ratio, 3),
                "subdomain_length": len(subdomain),
            })
    return suspicious


def main():
    parser = argparse.ArgumentParser(description="DNS Tunneling Detection Agent")
    parser.add_argument("--pcap", required=True, help="Path to PCAP file")
    parser.add_argument("--entropy-threshold", type=float, default=3.8)
    parser.add_argument("--output", default="dns_tunnel_report.json")
    parser.add_argument("--action", choices=[
        "entropy", "length", "txt", "cardinality", "full_analysis"
    ], default="full_analysis")
    args = parser.parse_args()

    report = {"pcap": args.pcap, "generated_at": datetime.utcnow().isoformat(),
              "findings": {}}

    queries = extract_dns_queries(args.pcap)
    report["total_queries"] = len(queries)
    print(f"[+] Extracted {len(queries)} DNS queries from {args.pcap}")

    if args.action in ("entropy", "full_analysis"):
        high_entropy = analyze_entropy(queries, args.entropy_threshold)
        report["findings"]["high_entropy"] = high_entropy
        print(f"[+] High entropy queries: {len(high_entropy)}")

    if args.action in ("length", "full_analysis"):
        long_q = analyze_query_lengths(queries)
        report["findings"]["long_queries"] = long_q
        print(f"[+] Long queries (>50 chars): {len(long_q)}")

    if args.action in ("txt", "full_analysis"):
        txt = analyze_txt_records(args.pcap)
        report["findings"]["txt_anomalies"] = txt
        print(f"[+] TXT record anomalies: {len(txt)}")

    if args.action in ("cardinality", "full_analysis"):
        cardinality = analyze_subdomain_cardinality(queries)
        report["findings"]["high_cardinality"] = cardinality
        print(f"[+] High cardinality domains: {len(cardinality)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
