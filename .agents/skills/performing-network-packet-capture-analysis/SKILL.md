---
name: performing-network-packet-capture-analysis
description: Perform forensic analysis of network packet captures (PCAP/PCAPNG) using Wireshark, tshark, and tcpdump to reconstruct network communications, extract transferred files, identify malicious traffic, and establish evidence of data exfiltration or command-and-control activity.
domain: cybersecurity
subdomain: digital-forensics
tags: [pcap, wireshark, tshark, tcpdump, network-forensics, packet-capture, protocol-analysis, traffic-analysis, pcapng, network-evidence]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Network Packet Capture Analysis

## Overview

Network packet captures (PCAP/PCAPNG files) represent the ultimate source of truth about network activity and provide irrefutable evidence of communications between hosts. PCAP files log every packet transmitted over a network segment, making them vital for forensic investigations involving data exfiltration, command-and-control communications, lateral movement, malware delivery, and unauthorized access. Wireshark is the primary tool for interactive analysis, while tshark provides command-line capabilities for automated processing and scripting. Modern PCAPNG format supports additional metadata including interface descriptions, capture comments, precise timestamps, and per-packet annotations.

## Prerequisites

- Wireshark 4.x with protocol dissectors
- tshark command-line tool (included with Wireshark)
- tcpdump for capture and basic filtering
- Python 3.8+ with scapy and pyshark libraries
- Sufficient disk space for PCAP files (can be multi-GB)

## Capture Techniques

### tcpdump

```bash
# Capture all traffic on interface eth0
tcpdump -i eth0 -w capture.pcap

# Capture with rotation (100MB files, keep 10)
tcpdump -i eth0 -w capture_%Y%m%d_%H%M%S.pcap -C 100 -W 10

# Capture specific host traffic
tcpdump -i eth0 host 192.168.1.100 -w host_traffic.pcap

# Capture specific port traffic
tcpdump -i eth0 port 443 -w https_traffic.pcap

# Capture with BPF filter for suspicious ports
tcpdump -i eth0 'port 4444 or port 8080 or port 1337' -w suspicious.pcap
```

### Wireshark Display Filters

```
# HTTP traffic
http

# DNS queries
dns

# SMB file transfers
smb2

# Specific IP communication
ip.addr == 192.168.1.100

# Failed TCP connections
tcp.flags.syn == 1 && tcp.flags.ack == 0

# Large data transfers (potential exfiltration)
tcp.len > 1000

# Specific protocol by port
tcp.port == 4444

# TLS handshakes (SNI extraction)
tls.handshake.type == 1

# HTTP POST requests
http.request.method == "POST"

# DNS queries to suspicious TLDs
dns.qry.name contains ".xyz" or dns.qry.name contains ".top"

# Beaconing detection (regular intervals)
frame.time_delta_displayed > 55 && frame.time_delta_displayed < 65
```

### tshark Analysis Commands

```bash
# Extract HTTP URLs from capture
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri

# Extract DNS queries
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort -u

# Extract file transfers (HTTP objects)
tshark -r capture.pcap --export-objects http,exported_files/

# Extract SMB file transfers
tshark -r capture.pcap --export-objects smb,smb_files/

# Protocol hierarchy statistics
tshark -r capture.pcap -z io,phs

# Conversation statistics
tshark -r capture.pcap -z conv,tcp

# Extract TLS SNI (Server Name Indication)
tshark -r capture.pcap -Y "tls.handshake.type == 1" -T fields -e tls.handshake.extensions_server_name

# Top talkers by bytes
tshark -r capture.pcap -z endpoints,ip -q

# Extract credentials (FTP, HTTP Basic)
tshark -r capture.pcap -Y "ftp.request.command == USER || ftp.request.command == PASS || http.authorization" -T fields -e ftp.request.arg -e http.authorization
```

## Python PCAP Analysis

```python
from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw
import os
import sys
import json
from collections import defaultdict, Counter
from datetime import datetime


class PCAPForensicAnalyzer:
    """Forensic analysis of PCAP files using Scapy."""

    def __init__(self, pcap_path: str, output_dir: str):
        self.pcap_path = pcap_path
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.packets = rdpcap(pcap_path)

    def get_conversations(self) -> list:
        """Extract unique IP conversations with byte counts."""
        convos = defaultdict(lambda: {"packets": 0, "bytes": 0})
        for pkt in self.packets:
            if IP in pkt:
                key = tuple(sorted([pkt[IP].src, pkt[IP].dst]))
                convos[key]["packets"] += 1
                convos[key]["bytes"] += len(pkt)

        return [
            {"src": k[0], "dst": k[1], "packets": v["packets"], "bytes": v["bytes"]}
            for k, v in sorted(convos.items(), key=lambda x: x[1]["bytes"], reverse=True)
        ]

    def extract_dns_queries(self) -> list:
        """Extract all DNS queries from the capture."""
        queries = []
        for pkt in self.packets:
            if DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
                queries.append({
                    "query": pkt[DNSQR].qname.decode(errors="replace").rstrip("."),
                    "type": pkt[DNSQR].qtype,
                    "src": pkt[IP].src if IP in pkt else "unknown"
                })
        return queries

    def detect_beaconing(self, threshold_seconds: float = 5.0) -> list:
        """Detect potential beaconing activity based on regular intervals."""
        ip_timestamps = defaultdict(list)
        for pkt in self.packets:
            if IP in pkt and TCP in pkt:
                key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].dport)
                ip_timestamps[key].append(float(pkt.time))

        beacons = []
        for key, times in ip_timestamps.items():
            if len(times) < 5:
                continue
            deltas = [times[i+1] - times[i] for i in range(len(times)-1)]
            if deltas:
                avg_delta = sum(deltas) / len(deltas)
                variance = sum((d - avg_delta) ** 2 for d in deltas) / len(deltas)
                if variance < threshold_seconds and avg_delta > 1:
                    beacons.append({
                        "src": key[0], "dst": key[1], "port": key[2],
                        "avg_interval": round(avg_delta, 2),
                        "variance": round(variance, 4),
                        "connection_count": len(times)
                    })
        return sorted(beacons, key=lambda x: x["variance"])

    def get_protocol_distribution(self) -> dict:
        """Get protocol distribution statistics."""
        protocols = Counter()
        for pkt in self.packets:
            if TCP in pkt:
                protocols[f"TCP/{pkt[TCP].dport}"] += 1
            elif UDP in pkt:
                protocols[f"UDP/{pkt[UDP].dport}"] += 1
        return dict(protocols.most_common(50))

    def generate_report(self) -> str:
        """Generate comprehensive PCAP analysis report."""
        report = {
            "analysis_timestamp": datetime.now().isoformat(),
            "pcap_file": self.pcap_path,
            "total_packets": len(self.packets),
            "conversations": self.get_conversations()[:50],
            "dns_queries": self.extract_dns_queries()[:200],
            "potential_beacons": self.detect_beaconing(),
            "protocol_distribution": self.get_protocol_distribution()
        }

        report_path = os.path.join(self.output_dir, "pcap_forensic_report.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        print(f"[*] Total packets: {report['total_packets']}")
        print(f"[*] Conversations: {len(report['conversations'])}")
        print(f"[*] DNS queries: {len(report['dns_queries'])}")
        print(f"[*] Potential beacons: {len(report['potential_beacons'])}")
        return report_path


def main():
    if len(sys.argv) < 3:
        print("Usage: python process.py <pcap_file> <output_dir>")
        sys.exit(1)
    analyzer = PCAPForensicAnalyzer(sys.argv[1], sys.argv[2])
    analyzer.generate_report()


if __name__ == "__main__":
    main()
```

## References

- Wireshark Documentation: https://www.wireshark.org/docs/
- PCAP Analysis Mastery: https://insanecyber.com/mastering-pcap-review/
- SANS Network Forensics: https://www.sans.org/cyber-security-courses/network-forensics/
- Public PCAPs for Practice: https://www.netresec.com/?page=PcapFiles
