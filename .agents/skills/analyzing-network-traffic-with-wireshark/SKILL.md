---
name: analyzing-network-traffic-with-wireshark
description: >
  Captures and analyzes network packet data using Wireshark and tshark to identify
  malicious traffic patterns, diagnose protocol issues, extract artifacts, and
  support incident response investigations on authorized network segments.
domain: cybersecurity
subdomain: network-security
tags: [network-security, wireshark, packet-analysis, traffic-analysis, pcap]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Analyzing Network Traffic with Wireshark

## When to Use

- Investigating suspected network intrusions by examining packet-level evidence of command-and-control traffic, data exfiltration, or lateral movement
- Diagnosing network performance issues such as retransmissions, fragmentation, or DNS resolution failures
- Analyzing malware communication patterns by capturing traffic from sandboxed or isolated hosts
- Validating firewall and IDS rules by confirming what traffic is actually traversing network segments
- Extracting files, credentials, or indicators of compromise from captured network sessions

**Do not use** to capture traffic on networks without authorization, to intercept private communications without legal authority, or as a substitute for full-featured SIEM platforms in production monitoring.

## Prerequisites

- Wireshark 4.0+ and tshark command-line utility installed
- Root/sudo privileges or membership in the `wireshark` group for live packet capture
- Network interface access (physical NIC, span port, or network tap) to the monitored segment
- Sufficient disk space for packet capture files (estimate 1 GB per minute on busy gigabit links)
- Familiarity with TCP/IP protocols, HTTP, DNS, TLS, and SMB at the packet level

## Workflow

### Step 1: Configure Capture Environment

Set up the capture interface and filters to target relevant traffic:

```bash
# List available interfaces
tshark -D

# Start capture on eth0 with a capture filter to limit scope
tshark -i eth0 -f "host 10.10.5.23 and (port 80 or port 443 or port 445)" -w /tmp/capture.pcapng

# Capture with ring buffer to manage disk usage (10 files, 100MB each)
tshark -i eth0 -b filesize:102400 -b files:10 -w /tmp/rolling_capture.pcapng

# Capture on multiple interfaces simultaneously
tshark -i eth0 -i eth1 -w /tmp/multi_interface.pcapng
```

For Wireshark GUI, set capture filter in the Capture Options dialog before starting.

### Step 2: Apply Display Filters for Targeted Analysis

```bash
# Filter HTTP traffic containing suspicious user agents
tshark -r capture.pcapng -Y "http.user_agent contains \"curl\" or http.user_agent contains \"Wget\""

# Find DNS queries to suspicious TLDs
tshark -r capture.pcapng -Y "dns.qry.name contains \".xyz\" or dns.qry.name contains \".top\" or dns.qry.name contains \".tk\""

# Identify TCP retransmissions indicating network issues
tshark -r capture.pcapng -Y "tcp.analysis.retransmission"

# Filter SMB traffic for lateral movement detection
tshark -r capture.pcapng -Y "smb2.cmd == 5 or smb2.cmd == 3" -T fields -e ip.src -e ip.dst -e smb2.filename

# Find cleartext credential transmission
tshark -r capture.pcapng -Y "ftp.request.command == \"PASS\" or http.authbasic"

# Detect beaconing patterns (regular interval connections)
tshark -r capture.pcapng -Y "ip.dst == 203.0.113.50" -T fields -e frame.time_relative -e ip.src -e tcp.dstport
```

### Step 3: Protocol-Specific Deep Analysis

```bash
# Follow a TCP stream to reconstruct a conversation
tshark -r capture.pcapng -q -z follow,tcp,ascii,0

# Analyze HTTP request/response pairs
tshark -r capture.pcapng -Y "http" -T fields -e frame.time -e ip.src -e ip.dst -e http.request.method -e http.request.uri -e http.response.code

# Extract DNS query/response statistics
tshark -r capture.pcapng -q -z dns,tree

# Analyze TLS handshakes for weak cipher suites
tshark -r capture.pcapng -Y "tls.handshake.type == 2" -T fields -e ip.src -e ip.dst -e tls.handshake.ciphersuite

# SMB file access enumeration
tshark -r capture.pcapng -Y "smb2" -T fields -e frame.time -e ip.src -e ip.dst -e smb2.filename -e smb2.cmd
```

### Step 4: Extract Artifacts and IOCs

```bash
# Export HTTP objects (files transferred over HTTP)
tshark -r capture.pcapng --export-objects http,/tmp/http_objects/

# Export SMB objects (files transferred over SMB)
tshark -r capture.pcapng --export-objects smb,/tmp/smb_objects/

# Extract all unique destination IPs for threat intelligence lookup
tshark -r capture.pcapng -T fields -e ip.dst | sort -u > unique_dest_ips.txt

# Extract SSL/TLS certificate information
tshark -r capture.pcapng -Y "tls.handshake.type == 11" -T fields -e x509sat.uTF8String -e x509ce.dNSName

# Extract all URLs accessed
tshark -r capture.pcapng -Y "http.request" -T fields -e http.host -e http.request.uri | sort -u > urls.txt

# Hash extracted files for IOC matching
find /tmp/http_objects/ -type f -exec sha256sum {} \; > extracted_file_hashes.txt
```

### Step 5: Statistical Analysis and Anomaly Detection

```bash
# Protocol hierarchy statistics
tshark -r capture.pcapng -q -z io,phs

# Conversation statistics sorted by bytes
tshark -r capture.pcapng -q -z conv,tcp -z conv,udp

# Identify top talkers
tshark -r capture.pcapng -q -z endpoints,ip

# IO graph data (packets per second)
tshark -r capture.pcapng -q -z io,stat,1,"COUNT(frame) frame"

# Detect port scanning patterns
tshark -r capture.pcapng -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" -T fields -e ip.src -e tcp.dstport | sort | uniq -c | sort -rn | head -20
```

### Step 6: Generate Reports and Export Evidence

```bash
# Export filtered packets to a new PCAP for evidence preservation
tshark -r capture.pcapng -Y "ip.addr == 10.10.5.23 and tcp.port == 4444" -w evidence_c2_traffic.pcapng

# Generate packet summary in CSV format
tshark -r capture.pcapng -T fields -E header=y -E separator=, -e frame.number -e frame.time -e ip.src -e ip.dst -e ip.proto -e tcp.srcport -e tcp.dstport -e frame.len > traffic_summary.csv

# Create PDML (XML) output for programmatic analysis
tshark -r capture.pcapng -T pdml > capture_analysis.xml

# Calculate capture file hash for chain of custody
sha256sum capture.pcapng > capture_hash.txt
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Capture Filter (BPF)** | Berkeley Packet Filter syntax applied at capture time to limit which packets are recorded, reducing file size and improving performance |
| **Display Filter** | Wireshark-specific filter syntax applied to already-captured packets for focused analysis without altering the capture file |
| **PCAPNG** | Next-generation packet capture format supporting multiple interfaces, name resolution, annotations, and metadata in a single file |
| **TCP Stream** | Reassembled sequence of TCP segments representing a complete bidirectional conversation between two endpoints |
| **Protocol Dissector** | Wireshark module that decodes a specific protocol's fields and structure, enabling deep inspection of packet contents |
| **IO Graph** | Time-series visualization of packet or byte rates over the capture duration, useful for identifying traffic spikes or beaconing |

## Tools & Systems

- **Wireshark 4.0+**: GUI-based packet analyzer with protocol dissectors for 3,000+ protocols, stream reassembly, and export capabilities
- **tshark**: Command-line version of Wireshark for headless capture, batch processing, and scripted analysis pipelines
- **tcpdump**: Lightweight packet capture tool for quick captures on remote systems without GUI dependencies
- **mergecap**: Wireshark utility for combining multiple capture files into a single PCAP for unified analysis
- **editcap**: Wireshark utility for splitting, filtering, and converting between capture file formats

## Common Scenarios

### Scenario: Investigating Suspected Data Exfiltration via DNS Tunneling

**Context**: The SOC team detected unusually high DNS query volumes from a workstation (10.10.3.45) to an external domain. The SIEM alert flagged DNS queries averaging 200 per minute compared to the baseline of 15. A packet capture was initiated from the network tap on the workstation's VLAN.

**Approach**:
1. Capture traffic from the workstation's subnet using `tshark -i eth2 -f "host 10.10.3.45 and port 53" -w dns_exfil_investigation.pcapng`
2. Analyze DNS query patterns: `tshark -r dns_exfil_investigation.pcapng -Y "dns.qry.name contains \"suspect-domain.xyz\"" -T fields -e frame.time -e dns.qry.name`
3. Examine subdomain labels for encoded data (long base64-like subdomains indicate tunneling): `tshark -r dns_exfil_investigation.pcapng -Y "dns.qry.type == 16" -T fields -e dns.qry.name -e dns.txt`
4. Calculate data volume by summing query name lengths to estimate exfiltration bandwidth
5. Extract unique query names and decode base64 subdomains to recover exfiltrated content
6. Export evidence packets to a separate PCAP and generate SHA-256 hash for chain of custody

**Pitfalls**:
- Capturing unfiltered traffic on a busy network and running out of disk space before collecting relevant data
- Using display filters instead of capture filters, resulting in massive files that are slow to process
- Overlooking encrypted DNS (DoH/DoT) traffic that bypasses traditional DNS capture on port 53
- Failing to establish packet capture hash and chain of custody documentation for forensic evidence

## Output Format

```
## Traffic Analysis Report

**Case ID**: IR-2024-0847
**Capture File**: dns_exfil_investigation.pcapng
**SHA-256**: a3f2b8c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
**Duration**: 2024-03-15 14:00:00 to 14:45:00 UTC
**Source Interface**: eth2 (VLAN 30 span port)

### Findings

**1. DNS Tunneling Confirmed**
- Source: 10.10.3.45
- Destination DNS: 8.8.8.8 (forwarded to ns1.suspect-domain.xyz)
- Query volume: 9,247 queries in 45 minutes (205/min vs 15/min baseline)
- Average subdomain label length: 63 characters (base64-encoded data)
- Estimated data exfiltrated: ~2.3 MB via TXT record responses

**2. Indicators of Compromise**
- Domain: suspect-domain.xyz (registered 3 days prior)
- Nameserver: ns1.suspect-domain.xyz (203.0.113.50)
- Query pattern: TXT record requests with base64-encoded subdomains
- Response pattern: TXT records containing base64-encoded payloads
```
