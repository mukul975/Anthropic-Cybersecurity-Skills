#!/usr/bin/env python3
"""PCAP Forensic Analyzer - Analyzes packet captures for forensic investigation."""
import json, os, sys
from collections import defaultdict, Counter
from datetime import datetime
try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR
except ImportError:
    print("Install scapy: pip install scapy"); sys.exit(1)

def analyze_pcap(pcap_path: str, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    packets = rdpcap(pcap_path)
    convos = defaultdict(lambda: {"pkts": 0, "bytes": 0})
    dns_queries = []
    protocols = Counter()
    for pkt in packets:
        if IP in pkt:
            key = tuple(sorted([pkt[IP].src, pkt[IP].dst]))
            convos[key]["pkts"] += 1; convos[key]["bytes"] += len(pkt)
            if TCP in pkt: protocols[f"TCP/{pkt[TCP].dport}"] += 1
            elif UDP in pkt: protocols[f"UDP/{pkt[UDP].dport}"] += 1
        if DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
            dns_queries.append({"query": pkt[DNSQR].qname.decode(errors="replace").rstrip("."),
                                "src": pkt[IP].src if IP in pkt else ""})
    top_convos = sorted([{"src": k[0], "dst": k[1], **v} for k, v in convos.items()],
                        key=lambda x: x["bytes"], reverse=True)[:50]
    report = {"total_packets": len(packets), "conversations": top_convos,
              "dns_queries": dns_queries[:200], "protocols": dict(protocols.most_common(30))}
    out = os.path.join(output_dir, "pcap_analysis.json")
    with open(out, "w") as f: json.dump(report, f, indent=2)
    print(f"[*] Packets:{len(packets)} Convos:{len(convos)} DNS:{len(dns_queries)}")
    return out

if __name__ == "__main__":
    if len(sys.argv) < 3: print("Usage: process.py <pcap> <output>"); sys.exit(1)
    analyze_pcap(sys.argv[1], sys.argv[2])
