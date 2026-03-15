#!/usr/bin/env python3
"""Network packet analysis agent using Scapy for pcap parsing and anomaly detection."""

import json
import math
import argparse
from collections import defaultdict, Counter
from datetime import datetime

from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, ICMP, Raw


def load_pcap(filepath):
    """Load packets from a pcap/pcapng file."""
    packets = rdpcap(filepath)
    print(f"[+] Loaded {len(packets)} packets from {filepath}")
    return packets


def extract_packet_info(packets):
    """Extract structured info from each packet with IP layer."""
    records = []
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        info = {
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "proto": pkt[IP].proto,
            "ttl": pkt[IP].ttl,
            "length": len(pkt),
            "flags": str(pkt[IP].flags),
            "timestamp": float(pkt.time),
        }
        if pkt.haslayer(TCP):
            info["src_port"] = pkt[TCP].sport
            info["dst_port"] = pkt[TCP].dport
            info["tcp_flags"] = str(pkt[TCP].flags)
            info["protocol"] = "TCP"
        elif pkt.haslayer(UDP):
            info["src_port"] = pkt[UDP].sport
            info["dst_port"] = pkt[UDP].dport
            info["protocol"] = "UDP"
        elif pkt.haslayer(ICMP):
            info["icmp_type"] = pkt[ICMP].type
            info["icmp_code"] = pkt[ICMP].code
            info["protocol"] = "ICMP"
        else:
            info["protocol"] = str(pkt[IP].proto)
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            info["dns_query"] = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            info["dns_type"] = pkt[DNSQR].qtype
        records.append(info)
    return records


def compute_traffic_stats(records):
    """Compute overall traffic statistics."""
    src_ips = Counter(r["src_ip"] for r in records)
    dst_ips = Counter(r["dst_ip"] for r in records)
    protocols = Counter(r["protocol"] for r in records)
    dst_ports = Counter(r.get("dst_port", 0) for r in records if r.get("dst_port"))
    total_bytes = sum(r["length"] for r in records)
    return {
        "total_packets": len(records),
        "total_bytes": total_bytes,
        "unique_src_ips": len(src_ips),
        "unique_dst_ips": len(dst_ips),
        "top_src_ips": src_ips.most_common(10),
        "top_dst_ips": dst_ips.most_common(10),
        "protocol_distribution": dict(protocols),
        "top_dst_ports": dst_ports.most_common(10),
    }


def detect_syn_flood(records, threshold=100):
    """Detect SYN flood by counting SYN-only packets per destination IP."""
    syn_counts = defaultdict(int)
    synack_counts = defaultdict(int)
    for r in records:
        if r.get("tcp_flags") == "S":
            syn_counts[r["dst_ip"]] += 1
        elif r.get("tcp_flags") == "SA":
            synack_counts[r["dst_ip"]] += 1
    alerts = []
    for ip, count in syn_counts.items():
        ack_count = synack_counts.get(ip, 0)
        ratio = ack_count / count if count > 0 else 1.0
        if count >= threshold and ratio < 0.3:
            alerts.append({
                "detection": "SYN Flood",
                "target_ip": ip,
                "syn_count": count,
                "synack_count": ack_count,
                "synack_ratio": round(ratio, 4),
                "severity": "critical",
            })
    return alerts


def calculate_entropy(data):
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def detect_dns_tunneling(records, length_threshold=50, entropy_threshold=3.5):
    """Detect DNS tunneling via long/high-entropy query names."""
    alerts = []
    for r in records:
        query = r.get("dns_query", "")
        if not query:
            continue
        subdomain = query.split(".")[0] if "." in query else query
        if len(subdomain) >= length_threshold or calculate_entropy(subdomain) >= entropy_threshold:
            alerts.append({
                "detection": "DNS Tunneling Indicator",
                "query": query,
                "subdomain_length": len(subdomain),
                "entropy": round(calculate_entropy(subdomain), 4),
                "src_ip": r["src_ip"],
                "severity": "high",
            })
    return alerts


def detect_port_scan(records, threshold=20):
    """Detect port scanning by counting unique destination ports per source IP."""
    src_ports = defaultdict(set)
    for r in records:
        if r.get("tcp_flags") == "S" and r.get("dst_port"):
            src_ports[r["src_ip"]].add(r["dst_port"])
    alerts = []
    for ip, ports in src_ports.items():
        if len(ports) >= threshold:
            alerts.append({
                "detection": "Port Scan",
                "source_ip": ip,
                "unique_ports_probed": len(ports),
                "sample_ports": sorted(list(ports))[:20],
                "severity": "high",
            })
    return alerts


def main():
    parser = argparse.ArgumentParser(description="Network Packet Analysis Agent (Scapy)")
    parser.add_argument("--pcap", required=True, help="Path to pcap/pcapng file")
    parser.add_argument("--syn-threshold", type=int, default=100, help="SYN flood detection threshold")
    parser.add_argument("--dns-length", type=int, default=50, help="DNS tunneling subdomain length threshold")
    parser.add_argument("--scan-threshold", type=int, default=20, help="Port scan unique ports threshold")
    parser.add_argument("--output", default="packet_analysis_report.json", help="Output report path")
    args = parser.parse_args()

    packets = load_pcap(args.pcap)
    records = extract_packet_info(packets)
    print(f"[+] Extracted {len(records)} IP-layer records")

    stats = compute_traffic_stats(records)
    syn_alerts = detect_syn_flood(records, args.syn_threshold)
    dns_alerts = detect_dns_tunneling(records, args.dns_length)
    scan_alerts = detect_port_scan(records, args.scan_threshold)

    report = {
        "analysis_time": datetime.utcnow().isoformat() + "Z",
        "pcap_file": args.pcap,
        "traffic_stats": stats,
        "anomalies": {
            "syn_flood": syn_alerts,
            "dns_tunneling": dns_alerts,
            "port_scan": scan_alerts,
        },
        "total_anomalies": len(syn_alerts) + len(dns_alerts) + len(scan_alerts),
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] SYN flood alerts: {len(syn_alerts)}")
    print(f"[+] DNS tunneling indicators: {len(dns_alerts)}")
    print(f"[+] Port scan detections: {len(scan_alerts)}")
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
