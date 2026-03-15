#!/usr/bin/env python3
"""Network traffic analysis agent using tshark and pyshark for PCAP analysis."""

import json
import math
import subprocess
import argparse
import re
from datetime import datetime
from collections import defaultdict, Counter

try:
    import pyshark
    HAS_PYSHARK = True
except ImportError:
    HAS_PYSHARK = False


def get_protocol_stats(pcap_path):
    """Extract protocol hierarchy statistics using tshark."""
    result = subprocess.run(
        ["tshark", "-r", pcap_path, "-q", "-z", "io,phs"],
        capture_output=True, text=True, timeout=120
    )
    protocols = {}
    for line in result.stdout.splitlines():
        match = re.match(r"\s+([\w.]+)\s+frames:(\d+)\s+bytes:(\d+)", line)
        if match:
            protocols[match.group(1)] = {
                "frames": int(match.group(2)), "bytes": int(match.group(3))
            }
    return protocols


def get_conversations(pcap_path):
    """Extract IP conversations using tshark."""
    result = subprocess.run(
        ["tshark", "-r", pcap_path, "-q", "-z", "conv,ip"],
        capture_output=True, text=True, timeout=120
    )
    conversations = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 10 and "<->" in line:
            idx = parts.index("<->")
            conversations.append({
                "src": parts[idx - 1], "dst": parts[idx + 1],
                "frames_total": parts[idx + 2] if len(parts) > idx + 2 else "0",
            })
    return conversations


def get_top_talkers(pcap_path, top_n=20):
    """Identify top source and destination IPs by packet count."""
    result = subprocess.run(
        ["tshark", "-r", pcap_path, "-T", "fields", "-e", "ip.src", "-e", "ip.dst"],
        capture_output=True, text=True, timeout=120
    )
    src_counts = Counter()
    dst_counts = Counter()
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            src_counts[parts[0]] += 1
            dst_counts[parts[1]] += 1
    return {
        "top_sources": src_counts.most_common(top_n),
        "top_destinations": dst_counts.most_common(top_n),
    }


def extract_dns_queries(pcap_path):
    """Extract DNS queries from the capture."""
    result = subprocess.run(
        ["tshark", "-r", pcap_path, "-Y", "dns.qry.name", "-T", "fields",
         "-e", "dns.qry.name", "-e", "dns.qry.type", "-e", "ip.dst"],
        capture_output=True, text=True, timeout=120
    )
    queries = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if parts and parts[0]:
            queries.append({
                "query": parts[0],
                "type": parts[1] if len(parts) > 1 else "",
                "resolver": parts[2] if len(parts) > 2 else "",
            })
    return queries


def detect_dns_tunneling(dns_queries, entropy_threshold=3.5, length_threshold=40):
    """Detect DNS tunneling via high-entropy or long subdomain queries."""
    suspicious = []
    for q in dns_queries:
        domain = q["query"]
        subdomain = domain.split(".")[0] if "." in domain else domain
        if len(subdomain) < 5:
            continue
        entropy = _calculate_entropy(subdomain)
        if entropy > entropy_threshold or len(subdomain) > length_threshold:
            suspicious.append({
                "query": domain, "subdomain_length": len(subdomain),
                "entropy": round(entropy, 3),
                "severity": "high" if entropy > 4.0 else "medium",
                "indicator": "Possible DNS tunneling",
            })
    return suspicious


def _calculate_entropy(text):
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def extract_http_urls(pcap_path):
    """Extract HTTP request URIs from the capture."""
    result = subprocess.run(
        ["tshark", "-r", pcap_path, "-Y", "http.request", "-T", "fields",
         "-e", "http.host", "-e", "http.request.uri", "-e", "ip.dst"],
        capture_output=True, text=True, timeout=120
    )
    urls = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0]:
            urls.append({
                "host": parts[0],
                "uri": parts[1] if len(parts) > 1 else "/",
                "dst_ip": parts[2] if len(parts) > 2 else "",
                "full_url": f"http://{parts[0]}{parts[1] if len(parts) > 1 else '/'}",
            })
    return urls


def detect_port_scan(pcap_path, threshold=20):
    """Detect port scanning patterns (single source hitting many ports)."""
    result = subprocess.run(
        ["tshark", "-r", pcap_path, "-Y", "tcp.flags.syn==1 && tcp.flags.ack==0",
         "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.dstport"],
        capture_output=True, text=True, timeout=120
    )
    src_dst_ports = defaultdict(set)
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            key = f"{parts[0]}->{parts[1]}"
            src_dst_ports[key].add(parts[2])
    scans = []
    for pair, ports in src_dst_ports.items():
        if len(ports) >= threshold:
            src, dst = pair.split("->")
            scans.append({
                "source": src, "target": dst,
                "unique_ports": len(ports), "severity": "high",
                "indicator": f"Port scan: {len(ports)} unique ports probed",
            })
    return scans


def extract_unique_ips(pcap_path):
    """Extract all unique external IPs from the capture."""
    result = subprocess.run(
        ["tshark", "-r", pcap_path, "-T", "fields", "-e", "ip.src", "-e", "ip.dst"],
        capture_output=True, text=True, timeout=120
    )
    ips = set()
    for line in result.stdout.splitlines():
        for ip in line.split("\t"):
            ip = ip.strip()
            if ip and not ip.startswith(("10.", "192.168.", "172.16.", "127.")):
                ips.add(ip)
    return sorted(ips)


def generate_report(pcap_path, protocols, top_talkers, dns_queries, dns_tunneling,
                    urls, port_scans, external_ips):
    """Generate network traffic analysis report."""
    return {
        "report_time": datetime.utcnow().isoformat(),
        "pcap_file": pcap_path,
        "protocol_statistics": protocols,
        "top_talkers": top_talkers,
        "dns_queries_total": len(dns_queries),
        "dns_tunneling_alerts": dns_tunneling,
        "http_urls_extracted": len(urls),
        "http_urls_sample": urls[:20],
        "port_scan_detections": port_scans,
        "external_ips": external_ips,
        "ioc_summary": {
            "unique_external_ips": len(external_ips),
            "unique_domains": len({q["query"] for q in dns_queries}),
            "unique_urls": len(urls),
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Network Traffic Analysis Agent (tshark/pyshark)")
    parser.add_argument("--pcap", required=True, help="PCAP or PCAPNG file to analyze")
    parser.add_argument("--output", default="traffic_analysis_report.json")
    parser.add_argument("--top-n", type=int, default=20, help="Top N talkers to report")
    parser.add_argument("--scan-threshold", type=int, default=20, help="Port scan detection threshold")
    args = parser.parse_args()

    print(f"[*] Analyzing: {args.pcap}")
    protocols = get_protocol_stats(args.pcap)
    top_talkers = get_top_talkers(args.pcap, args.top_n)
    dns_queries = extract_dns_queries(args.pcap)
    dns_tunneling = detect_dns_tunneling(dns_queries)
    urls = extract_http_urls(args.pcap)
    port_scans = detect_port_scan(args.pcap, args.scan_threshold)
    external_ips = extract_unique_ips(args.pcap)

    report = generate_report(args.pcap, protocols, top_talkers, dns_queries,
                            dns_tunneling, urls, port_scans, external_ips)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Protocols: {len(protocols)} | DNS queries: {len(dns_queries)} | URLs: {len(urls)}")
    print(f"[+] Port scans: {len(port_scans)} | DNS tunneling alerts: {len(dns_tunneling)}")
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
