---
name: performing-network-forensics-with-wireshark
description: Capture and analyze network traffic using Wireshark and tshark to reconstruct network events from PCAP/PCAPNG files, extract transferred files and credentials, and identify command-and-control communications. Use when analyzing captured traffic with Wireshark and tshark to reconstruct data exfiltration, extract credentials, or find network indicators of compromise during malware analysis. Do not use for tcpdump-based multi-tool PCAP evidence workflows proving incident facts - use analyzing-network-traffic-with-wireshark.
domain: cybersecurity
subdomain: digital-forensics
tags:
- forensics
- network-forensics
- wireshark
- pcap
- packet-analysis
- traffic-analysis
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- RS.AN-03
- DE.AE-02
- RS.MA-01
mitre_attack:
- T1005
- T1074
- T1119
- T1070
- T1059
---

# Performing Network Forensics with Wireshark

## When to Use
- When analyzing captured network traffic (PCAP files) from a security incident
- For identifying command-and-control (C2) communications in captured traffic
- When reconstructing data exfiltration activities from packet captures
- During malware analysis to identify network indicators of compromise
- For extracting files, credentials, and artifacts transferred over the network

## Prerequisites
- Wireshark or tshark installed for packet analysis
- PCAP/PCAPNG files from network captures (tcpdump, Wireshark, network TAP)
- NetworkMiner for automated artifact extraction
- Sufficient RAM for large capture files (1GB+ PCAPs need 8GB+ RAM)
- Understanding of TCP/IP, HTTP, DNS, TLS protocols
- GeoIP databases for IP geolocation

## Workflow

### Step 0: Capture Live Traffic with tcpdump (When No PCAP Exists)

When you must collect the evidence yourself, use tcpdump for low-overhead capture with rotation and BPF pre-filtering to keep file sizes manageable during long collections.

```bash
# Capture all traffic on interface eth0
tcpdump -i eth0 -w capture.pcap

# Capture with rotation (100MB files, keep the 10 most recent)
tcpdump -i eth0 -w capture_%Y%m%d_%H%M%S.pcap -C 100 -W 10

# Capture only a specific host
tcpdump -i eth0 host 192.168.1.100 -w host_traffic.pcap

# Capture only a specific port
tcpdump -i eth0 port 443 -w https_traffic.pcap

# BPF pre-filter for known-suspicious ports (reduces capture volume)
tcpdump -i eth0 'port 4444 or port 8080 or port 1337' -w suspicious.pcap
```

### Step 1: Prepare and Validate the Capture File

```bash
# Install Wireshark and tshark
sudo apt-get install wireshark tshark

# Verify the PCAP file
capinfos /cases/case-2024-001/network/capture.pcap

# Output includes: file type, packet count, capture duration, data size
# Example output:
# File name:           capture.pcap
# File type:           Wireshark/tcpdump/... - pcap
# Number of packets:   1,245,678
# File size:           856 MB
# Data size:           823 MB
# Capture duration:    3600.123456 seconds
# First packet time:   2024-01-15 14:00:00.000000
# Last packet time:    2024-01-15 15:00:00.123456

# Hash the PCAP for integrity
sha256sum /cases/case-2024-001/network/capture.pcap \
   > /cases/case-2024-001/network/pcap_hash.txt

# Get a protocol hierarchy statistics overview
tshark -r /cases/case-2024-001/network/capture.pcap -q -z io,phs
```

### Step 2: Filter and Identify Suspicious Traffic

```bash
# Extract conversation statistics
tshark -r /cases/case-2024-001/network/capture.pcap -q -z conv,tcp

# Find top talkers by bytes transferred
tshark -r /cases/case-2024-001/network/capture.pcap -q -z endpoints,ip \
   | sort -t$'\t' -k3 -rn | head -20

# Filter for DNS queries (potential C2 or exfiltration)
tshark -r /cases/case-2024-001/network/capture.pcap \
   -Y "dns.qr == 0" \
   -T fields -e frame.time -e ip.src -e dns.qry.name \
   > /cases/case-2024-001/analysis/dns_queries.txt

# Find DNS queries to unusual TLDs or long domain names (DNS tunneling)
tshark -r /cases/case-2024-001/network/capture.pcap \
   -Y "dns.qr == 0 && dns.qry.name matches \"[a-z0-9]{30,}\"" \
   -T fields -e frame.time -e ip.src -e dns.qry.name \
   > /cases/case-2024-001/analysis/suspicious_dns.txt

# Filter HTTP traffic
tshark -r /cases/case-2024-001/network/capture.pcap \
   -Y "http.request" \
   -T fields -e frame.time -e ip.src -e ip.dst -e http.request.method \
   -e http.host -e http.request.uri -e http.user_agent \
   > /cases/case-2024-001/analysis/http_requests.txt

# Find connections to known malicious ports
tshark -r /cases/case-2024-001/network/capture.pcap \
   -Y "tcp.dstport == 4444 || tcp.dstport == 8080 || tcp.dstport == 1337 || tcp.dstport == 6667" \
   -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport \
   > /cases/case-2024-001/analysis/suspicious_ports.txt

# Detect beaconing patterns (regular interval connections)
tshark -r /cases/case-2024-001/network/capture.pcap \
   -Y "ip.dst == 185.0.0.1" \
   -T fields -e frame.time_epoch \
   > /tmp/beacon_times.txt
```

### Step 3: Extract Files and Objects from Traffic

```bash
# Export HTTP objects (files transferred over HTTP)
tshark -r /cases/case-2024-001/network/capture.pcap \
   --export-objects http,/cases/case-2024-001/analysis/http_objects/

# Export SMB objects
tshark -r /cases/case-2024-001/network/capture.pcap \
   --export-objects smb,/cases/case-2024-001/analysis/smb_objects/

# Export DICOM objects (medical imaging)
tshark -r /cases/case-2024-001/network/capture.pcap \
   --export-objects dicom,/cases/case-2024-001/analysis/dicom_objects/

# Export FTP data transfers
tshark -r /cases/case-2024-001/network/capture.pcap \
   -Y "ftp-data" \
   -T fields -e ftp-data.data \
   --export-objects ftp-data,/cases/case-2024-001/analysis/ftp_objects/

# Hash all extracted objects
find /cases/case-2024-001/analysis/http_objects/ -type f -exec sha256sum {} \; \
   > /cases/case-2024-001/analysis/extracted_file_hashes.txt

# Check extracted file hashes against VirusTotal
while read hash filepath; do
   echo "Checking $filepath ($hash)"
   curl -s "https://www.virustotal.com/api/v3/files/$hash" \
      -H "x-apikey: YOUR_API_KEY" | python3 -c "
import json,sys
data=json.load(sys.stdin)
if 'data' in data:
   stats=data['data']['attributes']['last_analysis_stats']
   print(f'  Malicious: {stats[\"malicious\"]}, Undetected: {stats[\"undetected\"]}')
else:
   print('  Not found on VT')
"
done < /cases/case-2024-001/analysis/extracted_file_hashes.txt
```

### Step 4: Reconstruct TCP Streams and Sessions

```bash
# Follow a specific TCP stream (stream index 42)
tshark -r /cases/case-2024-001/network/capture.pcap \
   -q -z "follow,tcp,ascii,42" \
   > /cases/case-2024-001/analysis/stream_42.txt

# Extract all HTTP request-response pairs for a suspicious host
tshark -r /cases/case-2024-001/network/capture.pcap \
   -Y "http && ip.addr == 185.0.0.1" \
   -T fields -e frame.time -e http.request.method -e http.host \
   -e http.request.uri -e http.response.code -e http.content_length \
   > /cases/case-2024-001/analysis/suspicious_http.txt

# Extract TLS/SSL certificate information
tshark -r /cases/case-2024-001/network/capture.pcap \
   -Y "tls.handshake.type == 11" \
   -T fields -e ip.dst -e tls.handshake.certificate \
   > /cases/case-2024-001/analysis/tls_certs.txt

# Extract TLS SNI (Server Name Indication) values
tshark -r /cases/case-2024-001/network/capture.pcap \
   -Y "tls.handshake.extensions_server_name" \
   -T fields -e frame.time -e ip.src -e ip.dst \
   -e tls.handshake.extensions_server_name \
   > /cases/case-2024-001/analysis/tls_sni.txt

# Extract credentials from unencrypted protocols
tshark -r /cases/case-2024-001/network/capture.pcap \
   -Y "ftp.request.command == \"USER\" || ftp.request.command == \"PASS\"" \
   -T fields -e frame.time -e ip.src -e ftp.request.command -e ftp.request.arg

tshark -r /cases/case-2024-001/network/capture.pcap \
   -Y "http.authorization" \
   -T fields -e frame.time -e ip.src -e http.host -e http.authorization
```

### Step 5: Use NetworkMiner for Automated Analysis

```bash
# Install NetworkMiner (Mono required on Linux)
sudo apt-get install mono-complete
wget https://www.netresec.com/?download=NetworkMiner -O NetworkMiner.zip
unzip NetworkMiner.zip -d /opt/NetworkMiner/

# Run NetworkMiner
mono /opt/NetworkMiner/NetworkMiner.exe /cases/case-2024-001/network/capture.pcap

# NetworkMiner automatically extracts:
# - Host inventory (OS fingerprinting, open ports)
# - Files transferred over HTTP, FTP, SMB, TFTP
# - Images from web traffic
# - Credentials (plaintext and NTLM hashes)
# - DNS records
# - Session parameters
# - Anomalies and alerts
```

### Step 6: Programmatic Analysis with Scapy

For scripted, repeatable analysis -- extracting conversations, DNS queries, protocol distribution, and variance-based beaconing detection in one pass -- use Scapy. The variance test flags destinations contacted at near-constant intervals (low jitter), a strong beaconing signal that GUI inspection can miss.

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

### Step 7: Generate Network Forensics Report

```bash
# Compile findings
cat << 'EOF' > /cases/case-2024-001/analysis/network_forensics_report.txt
NETWORK FORENSICS ANALYSIS REPORT
===================================
Case: 2024-001
Capture File: capture.pcap (856 MB, 1,245,678 packets)
Capture Period: 2024-01-15 14:00 to 15:00 UTC
Analyst: [Examiner Name]

TRAFFIC OVERVIEW:
  Total packets: 1,245,678
  Unique source IPs: 45
  Unique destination IPs: 234
  Protocols: TCP (78%), UDP (18%), ICMP (2%), Other (2%)

C2 COMMUNICATION:
  Destination: 185.0.0.1:443
  Beaconing interval: ~60 seconds
  Total connections: 58
  Data transferred: 4.2 MB outbound, 12.3 MB inbound
  TLS SNI: update-service.malware-c2.com

EXFILTRATION:
  Method: HTTPS POST to 185.0.0.1
  Volume: 4.2 MB over 45 minutes
  Files: 3 ZIP archives extracted from HTTP objects

DNS TUNNELING:
  Suspicious queries to: data.evil-dns.com
  Average subdomain length: 45 characters
  Query count: 1,234 (normal baseline: 50)
EOF
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| PCAP/PCAPNG | Packet capture file formats storing raw network traffic |
| TCP stream | Complete bidirectional communication between two endpoints |
| Deep packet inspection | Analysis of packet payload content beyond header information |
| Beaconing | Regular-interval callbacks from malware to C2 servers |
| DNS tunneling | Encoding data within DNS queries for covert exfiltration |
| TLS/SNI | Server Name Indication revealing the target hostname in encrypted connections |
| Network flow | Summary of communication between endpoints (IPs, ports, bytes, duration) |
| Protocol hierarchy | Statistical breakdown of protocols present in a capture |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Wireshark | GUI-based packet analyzer with deep protocol dissection |
| tshark | Command-line version of Wireshark for scripted analysis |
| NetworkMiner | Automated network forensic analysis and file extraction |
| tcpdump | Command-line packet capture utility |
| zeek (Bro) | Network security monitor generating structured connection logs |
| ngrep | Network grep for pattern matching in packet content |
| capinfos | PCAP file statistics and metadata utility |
| mergecap | Merge multiple PCAP files into a single capture |

## Common Scenarios

**Scenario 1: Malware C2 Communication Analysis**
Load PCAP in Wireshark, identify beaconing patterns to external IPs, examine TLS certificates for self-signed or unusual issuers, extract HTTP POST data containing encoded commands, correlate C2 IPs with threat intelligence feeds.

**Scenario 2: Data Exfiltration Detection**
Analyze traffic statistics for unusually large outbound transfers, examine DNS query lengths for DNS tunneling indicators, track FTP and HTTP file uploads to external servers, reconstruct exfiltrated files from packet data.

**Scenario 3: Lateral Movement in Enterprise Network**
Filter for SMB, RDP, WMI, and PSExec traffic between internal hosts, identify credential usage patterns across multiple systems, trace the propagation path of the attacker through the network, correlate with Windows Event Log authentication events.

**Scenario 4: Web Application Attack Reconstruction**
Filter HTTP traffic to the web server, identify SQL injection, XSS, and directory traversal attempts, follow the TCP stream of the successful exploit, extract uploaded webshells or payloads, document the attack chain for the incident report.

## Output Format

```
Network Forensics Summary:
  Capture: capture.pcap
  Duration: 1 hour (14:00-15:00 UTC, 2024-01-15)
  Packets: 1,245,678 | Size: 856 MB

  Top Suspicious Connections:
    192.168.1.50 -> 185.0.0.1:443   (C2, 58 connections, 4.2MB out)
    192.168.1.50 -> 10.0.0.25:445   (SMB lateral movement)
    192.168.1.50 -> 10.0.0.30:3389  (RDP lateral movement)

  Extracted Artifacts:
    Files:        23 (3 malicious per VT)
    Credentials:  2 plaintext FTP logins
    DNS Queries:  1,234 suspicious (possible tunneling)
    TLS Certs:    5 self-signed certificates

  IOCs Identified:
    IPs:     185.0.0.1, 203.0.113.50
    Domains: update-service.malware-c2.com, data.evil-dns.com
    Hashes:  3 file hashes flagged as malware
```
