---
name: analyzing-network-traffic-for-incidents
description: >
  Analyzes network traffic captures and flow data to identify adversary activity during
  security incidents, including command-and-control communications, lateral movement,
  data exfiltration, and exploitation attempts. Uses Wireshark, Zeek, and NetFlow
  analysis techniques. Activates for requests involving network traffic analysis,
  packet capture investigation, PCAP analysis, network forensics, C2 traffic detection,
  or exfiltration detection.
domain: cybersecurity
subdomain: incident-response
tags: [network-forensics, PCAP-analysis, Wireshark, Zeek, traffic-analysis]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Analyzing Network Traffic for Incidents

## When to Use

- SIEM alerts on anomalous network traffic patterns requiring deeper investigation
- C2 beaconing is suspected and needs confirmation through packet-level analysis
- Data exfiltration volume or destination must be quantified from network evidence
- Lateral movement between systems needs to be traced through network connections
- An IDS/IPS alert requires packet-level validation to confirm or dismiss

**Do not use** for host-based forensic analysis (process execution, file system artifacts); use endpoint forensics tools instead.

## Prerequisites

- Full packet capture (PCAP) infrastructure or on-demand capture capability (network tap, SPAN port)
- Wireshark installed on the analysis workstation with appropriate display filters knowledge
- Zeek (formerly Bro) deployed for network metadata generation (conn.log, dns.log, http.log, ssl.log)
- NetFlow/IPFIX collection from network devices for traffic flow analysis
- Network architecture diagram showing VLAN layout, firewall placement, and monitoring points
- Threat intelligence feeds for correlating observed network indicators

## Workflow

### Step 1: Capture or Acquire Network Traffic

Obtain the relevant traffic data for the investigation:

**Live Capture (if incident is active):**
```bash
# Capture on specific interface filtering by host
tcpdump -i eth0 -w capture.pcap host 10.1.5.42

# Capture C2 traffic to specific external IP
tcpdump -i eth0 -w c2_traffic.pcap host 185.220.101.42

# Capture with rotation (1GB files, keep 10)
tcpdump -i eth0 -w capture_%Y%m%d%H%M.pcap -C 1000 -W 10
```

**From Existing Infrastructure:**
- Export PCAP from full packet capture appliance (Arkime/Moloch, ExtraHop, Corelight)
- Pull Zeek logs from the Zeek cluster for the investigation timeframe
- Export NetFlow data from network devices for high-level traffic analysis

### Step 2: Identify C2 Communications

Detect command-and-control traffic patterns:

**Beaconing Detection (Zeek conn.log):**
```bash
# Extract connections to external IPs with regular intervals
cat conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes \
  | awk '$4 ~ /^185\.220/' | sort -t. -k1,1n -k2,2n
```

**Wireshark Beacon Analysis:**
```
# Filter for traffic to suspected C2 IP
ip.addr == 185.220.101.42

# Filter HTTPS traffic to non-standard ports
tcp.port != 443 && ssl

# Filter DNS queries for suspicious domains
dns.qry.name contains "evil" or dns.qry.name matches "^[a-z0-9]{32}\."

# Filter HTTP POST (common C2 check-in method)
http.request.method == "POST" && ip.dst == 185.220.101.42
```

Beaconing characteristics to identify:
- Regular time intervals between connections (e.g., every 60 seconds with 10-15% jitter)
- Consistent packet sizes in requests and responses
- HTTPS to external IPs not associated with legitimate CDNs or services
- DNS queries with high entropy subdomains (DNS tunneling indicator)

### Step 3: Analyze Lateral Movement Traffic

Trace adversary movement between internal systems:

```
Key protocols for lateral movement detection:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SMB (TCP 445):     PsExec, file share access, ransomware propagation
RDP (TCP 3389):    Remote desktop sessions
WinRM (TCP 5985):  PowerShell remoting
WMI (TCP 135):     Remote command execution
SSH (TCP 22):      Linux lateral movement
DCE/RPC (TCP 135): DCOM-based lateral movement
```

**Wireshark Filters for Lateral Movement:**
```
# SMB lateral movement
smb2 && ip.src == 10.1.5.42 && ip.dst != 10.1.5.42

# RDP connections from compromised host
tcp.dstport == 3389 && ip.src == 10.1.5.42

# Kerberos ticket requests (potential pass-the-ticket)
kerberos.msg_type == 12 && ip.src == 10.1.5.42

# NTLM authentication (potential pass-the-hash)
ntlmssp.auth.username && ip.src == 10.1.5.42
```

### Step 4: Detect Data Exfiltration

Identify unauthorized data transfers leaving the network:

```
# Identify large outbound transfers in Zeek conn.log
cat conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p orig_bytes \
  | awk '$5 > 100000000' | sort -t$'\t' -k5 -rn

# DNS tunneling detection (high volume of TXT queries)
cat dns.log | zeek-cut query qtype | grep TXT | cut -f1 \
  | rev | cut -d. -f1,2 | rev | sort | uniq -c | sort -rn | head

# Unusual protocol usage (ICMP tunneling, DNS over HTTPS)
cat conn.log | zeek-cut proto id.resp_p orig_bytes | awk '$1 == "icmp" && $3 > 1000'
```

**Wireshark Exfiltration Filters:**
```
# Large HTTP POST uploads
http.request.method == "POST" && tcp.len > 10000

# FTP data transfers
ftp-data && ip.src == 10.0.0.0/8

# DNS with large TXT responses (tunneling)
dns.resp.type == 16 && dns.resp.len > 200
```

### Step 5: Extract and Correlate IOCs

Pull network-based indicators from traffic analysis:

- External IP addresses contacted by compromised hosts
- Domains resolved via DNS during the incident timeframe
- URLs accessed via HTTP/HTTPS (if SSL inspection is in place)
- TLS certificate details (subject, issuer, serial number, JA3/JA3S hashes)
- User-Agent strings from HTTP requests
- File transfers captured in PCAP (extract using Wireshark Export Objects)

### Step 6: Document Network Forensic Findings

Compile analysis into a structured report with evidence references:

- Reference specific PCAP files, frame numbers, and timestamps for each finding
- Include packet captures of key evidence as screenshots or exported PDFs
- Map network activity to the incident timeline
- Correlate network findings with host-based evidence from endpoint forensics

## Key Concepts

| Term | Definition |
|------|------------|
| **PCAP (Packet Capture)** | File format storing raw network packets captured from a network interface for offline analysis |
| **Beaconing** | Regular, periodic network connections from a compromised host to a C2 server, identifiable by consistent timing intervals |
| **JA3/JA3S** | TLS client and server fingerprinting method based on the ClientHello and ServerHello parameters; unique per application |
| **NetFlow/IPFIX** | Network traffic metadata (source, destination, ports, bytes, duration) collected by routers and switches without full packet capture |
| **DNS Tunneling** | Technique encoding data in DNS queries and responses to exfiltrate data or maintain C2 through DNS protocol |
| **Network Tap** | Hardware device that creates an exact copy of network traffic for monitoring without impacting network performance |
| **Zeek Logs** | Structured metadata logs generated by the Zeek network analysis framework covering connections, DNS, HTTP, SSL, and more |

## Tools & Systems

- **Wireshark**: Open-source packet analyzer for deep inspection of network protocols at the packet level
- **Zeek (formerly Bro)**: Network analysis framework generating structured metadata logs from live or captured traffic
- **Arkime (formerly Moloch)**: Open-source full packet capture and search platform for large-scale network forensics
- **NetworkMiner**: Network forensic analysis tool for extracting files, images, and credentials from PCAP files
- **RITA (Real Intelligence Threat Analytics)**: Open-source beacon detection and DNS tunneling analysis tool for Zeek logs

## Common Scenarios

### Scenario: Confirming C2 Beaconing and Quantifying Exfiltration

**Context**: EDR detects a suspicious process on a workstation but cannot determine the volume of data exfiltrated. Network team provides PCAP from the full packet capture appliance covering the incident timeframe.

**Approach**:
1. Filter PCAP to traffic from the compromised host IP to external destinations
2. Identify the C2 channel by analyzing connection timing patterns (beacon detection)
3. Extract TLS certificate and JA3 hash from the C2 connection for IOC generation
4. Calculate total bytes transferred to C2 infrastructure over the incident duration
5. Check for additional exfiltration channels (DNS tunneling, cloud storage uploads)
6. Extract any unencrypted files transferred using Wireshark Export Objects feature

**Pitfalls**:
- Analyzing only HTTP traffic when C2 is operating over HTTPS without SSL inspection
- Missing DNS tunneling because the data volume per query is small (but total over time is significant)
- Not correlating network timestamps with endpoint timestamps (timezone mismatches)
- Overlooking legitimate cloud services abused for exfiltration (OneDrive, Google Drive, Dropbox)

## Output Format

```
NETWORK TRAFFIC ANALYSIS REPORT
=================================
Incident:         INC-2025-1547
Analyst:          [Name]
Capture Source:   Arkime full packet capture
Analysis Period:  2025-11-15 14:00 UTC - 2025-11-15 18:00 UTC
Total PCAP Size:  4.7 GB

C2 COMMUNICATIONS
Source:           10.1.5.42 (WKSTN-042)
Destination:      185.220.101.42:443 (HTTPS)
Beacon Interval:  60 seconds ± 12% jitter
Sessions:         237 connections over 4 hours
JA3 Hash:         a0e9f5d64349fb13191bc781f81f42e1
TLS Certificate:  CN=update.evil[.]com (self-signed)
Total Data Sent:  147 MB (outbound)
Total Data Recv:  2.3 MB (inbound - commands)

LATERAL MOVEMENT
10.1.5.42 → 10.1.10.15 (SMB, TCP 445) - 14:35 UTC
10.1.5.42 → 10.1.10.20 (RDP, TCP 3389) - 14:42 UTC
10.1.5.42 → 10.1.1.5  (LDAP, TCP 389) - 15:10 UTC

EXFILTRATION SUMMARY
Protocol:         HTTPS to C2 server
Volume:           147 MB outbound
Duration:         14:23 UTC - 18:00 UTC
Files Extracted:  [list if recoverable from unencrypted channels]

DNS ANALYSIS
Suspicious Queries: 0 DNS tunneling indicators
DGA Detection:      0 algorithmically generated domains

EVIDENCE REFERENCES
PCAP File:        INC-2025-1547_capture.pcap (SHA-256: ...)
Zeek Logs:        /logs/zeek/2025-11-15/ (conn.log, ssl.log, dns.log)
```
