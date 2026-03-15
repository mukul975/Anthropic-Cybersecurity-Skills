#!/usr/bin/env python3
"""Agent for performing network packet capture analysis with scapy and tshark."""

import json
import argparse
import subprocess
from datetime import datetime
from collections import Counter

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


def analyze_pcap_scapy(pcap_file):
    """Analyze PCAP file using scapy for protocol statistics."""
    if not HAS_SCAPY:
        return {"error": "scapy not installed — pip install scapy"}
    packets = rdpcap(pcap_file)
    total = len(packets)
    protocols = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    src_ports = Counter()
    dst_ports = Counter()
    dns_queries = []
    for pkt in packets:
        if IP in pkt:
            src_ips[pkt[IP].src] += 1
            dst_ips[pkt[IP].dst] += 1
            if TCP in pkt:
                protocols["TCP"] += 1
                src_ports[pkt[TCP].sport] += 1
                dst_ports[pkt[TCP].dport] += 1
            elif UDP in pkt:
                protocols["UDP"] += 1
                if DNS in pkt and pkt.haslayer(DNSQR):
                    query = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
                    dns_queries.append(query)
            else:
                protocols[pkt[IP].proto] += 1
    return {
        "pcap_file": pcap_file, "total_packets": total,
        "protocols": dict(protocols),
        "top_src_ips": dict(src_ips.most_common(10)),
        "top_dst_ips": dict(dst_ips.most_common(10)),
        "top_dst_ports": dict(dst_ports.most_common(15)),
        "dns_queries": list(set(dns_queries))[:30],
        "unique_dns_queries": len(set(dns_queries)),
    }


def extract_http_requests(pcap_file):
    """Extract HTTP requests from PCAP using tshark."""
    cmd = ["tshark", "-r", pcap_file, "-Y", "http.request",
           "-T", "fields", "-e", "ip.src", "-e", "ip.dst",
           "-e", "http.request.method", "-e", "http.host",
           "-e", "http.request.uri", "-e", "http.user_agent"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        requests_list = []
        for line in result.stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) >= 4:
                requests_list.append({
                    "src": parts[0], "dst": parts[1],
                    "method": parts[2], "host": parts[3],
                    "uri": parts[4] if len(parts) > 4 else "",
                    "user_agent": parts[5][:200] if len(parts) > 5 else "",
                })
        return {"pcap_file": pcap_file, "http_requests": len(requests_list), "requests": requests_list[:50]}
    except FileNotFoundError:
        return {"error": "tshark not found — install Wireshark"}
    except Exception as e:
        return {"error": str(e)}


def detect_suspicious_traffic(pcap_file):
    """Detect suspicious network patterns in PCAP."""
    if not HAS_SCAPY:
        return {"error": "scapy not installed"}
    packets = rdpcap(pcap_file)
    findings = []
    syn_counts = Counter()
    large_dns = []
    unusual_ports = []
    high_ports = [4444, 5555, 6666, 8888, 9999, 1234, 31337, 12345, 6667, 6697]
    for pkt in packets:
        if IP not in pkt:
            continue
        if TCP in pkt:
            if pkt[TCP].flags == 0x02:
                syn_counts[pkt[IP].dst] += 1
            if pkt[TCP].dport in high_ports or pkt[TCP].sport in high_ports:
                unusual_ports.append({"src": pkt[IP].src, "dst": pkt[IP].dst,
                                      "port": pkt[TCP].dport, "sport": pkt[TCP].sport})
        if DNS in pkt and pkt.haslayer(DNSQR):
            query = pkt[DNSQR].qname.decode("utf-8", errors="replace")
            if len(query) > 60:
                large_dns.append({"query": query[:100], "length": len(query), "src": pkt[IP].src})
    port_scan_suspects = [{"target": ip, "syn_count": count} for ip, count in syn_counts.most_common(5) if count >= 20]
    if port_scan_suspects:
        findings.append({"type": "PORT_SCAN", "severity": "HIGH", "details": port_scan_suspects})
    if large_dns:
        findings.append({"type": "DNS_EXFILTRATION", "severity": "HIGH", "details": large_dns[:10]})
    if unusual_ports:
        findings.append({"type": "SUSPICIOUS_PORTS", "severity": "MEDIUM", "details": unusual_ports[:10]})
    return {
        "pcap_file": pcap_file,
        "findings": findings,
        "total_findings": len(findings),
        "severity": "HIGH" if any(f["severity"] == "HIGH" for f in findings) else "MEDIUM" if findings else "LOW",
    }


def conversation_analysis(pcap_file):
    """Analyze TCP/UDP conversations using tshark."""
    cmd = ["tshark", "-r", pcap_file, "-q", "-z", "conv,tcp"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return {"pcap_file": pcap_file, "tcp_conversations": result.stdout[:3000]}
    except Exception as e:
        return {"error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Network Packet Capture Analysis Agent")
    sub = parser.add_subparsers(dest="command")
    a = sub.add_parser("analyze", help="Protocol and IP statistics")
    a.add_argument("--pcap", required=True)
    h = sub.add_parser("http", help="Extract HTTP requests")
    h.add_argument("--pcap", required=True)
    s = sub.add_parser("suspicious", help="Detect suspicious traffic")
    s.add_argument("--pcap", required=True)
    c = sub.add_parser("conversations", help="TCP conversation analysis")
    c.add_argument("--pcap", required=True)
    args = parser.parse_args()
    if args.command == "analyze":
        result = analyze_pcap_scapy(args.pcap)
    elif args.command == "http":
        result = extract_http_requests(args.pcap)
    elif args.command == "suspicious":
        result = detect_suspicious_traffic(args.pcap)
    elif args.command == "conversations":
        result = conversation_analysis(args.pcap)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
