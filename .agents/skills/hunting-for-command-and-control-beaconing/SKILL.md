---
name: hunting-for-command-and-control-beaconing
description: Detect C2 beaconing patterns in network traffic using frequency analysis, jitter detection, and domain reputation to identify compromised endpoints communicating with adversary infrastructure.
domain: cybersecurity
subdomain: threat-hunting
tags: [threat-hunting, mitre-attack, c2, beaconing, network-analysis, proactive-detection]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Hunting for Command and Control Beaconing

## When to Use

- When proactively hunting for compromised systems in the network
- After threat intel indicates C2 frameworks targeting your industry
- When investigating periodic outbound connections to suspicious domains
- During incident response to identify active C2 channels
- When DNS query logs show unusual patterns to specific domains

## Prerequisites

- Network proxy/firewall logs with full URL and timing data
- DNS query logs (passive DNS, DNS server logs, or Sysmon Event ID 22)
- Zeek/Bro network connection logs or NetFlow data
- SIEM with statistical analysis capabilities (Splunk, Elastic)
- Threat intelligence feeds for domain/IP reputation

## Workflow

1. **Identify Beaconing Characteristics**: Define what constitutes beaconing (regular intervals, small payload sizes, consistent destinations, jitter patterns).
2. **Collect Network Telemetry**: Aggregate proxy logs, DNS queries, and connection metadata for analysis.
3. **Apply Frequency Analysis**: Identify connections with regular intervals using statistical methods (standard deviation, coefficient of variation).
4. **Filter Known-Good Traffic**: Exclude legitimate periodic traffic (Windows Update, AV updates, heartbeat services, NTP).
5. **Analyze Domain/IP Reputation**: Check identified beaconing destinations against threat intel, WHOIS data, and certificate transparency logs.
6. **Investigate Endpoint Context**: Correlate beaconing activity with process creation, user context, and file system changes on source endpoints.
7. **Confirm and Respond**: Validate C2 activity, block communication, and initiate incident response.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1071 | Application Layer Protocol (HTTP/HTTPS/DNS C2) |
| T1071.001 | Web Protocols (HTTP/S beaconing) |
| T1071.004 | DNS (DNS tunneling C2) |
| T1573 | Encrypted Channel |
| T1572 | Protocol Tunneling |
| T1568 | Dynamic Resolution (DGA, fast-flux) |
| T1132 | Data Encoding in C2 |
| T1095 | Non-Application Layer Protocol |
| Beacon Interval | Time between C2 check-ins |
| Jitter | Random variation in beacon interval |
| DGA | Domain Generation Algorithm |
| Fast-Flux | Rapidly changing DNS resolution |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| RITA (Real Intelligence Threat Analytics) | Automated beacon detection in Zeek logs |
| Splunk | Statistical beacon analysis with SPL |
| Elastic Security | ML-based anomaly detection for beaconing |
| Zeek/Bro | Network connection metadata collection |
| Suricata | Network IDS with JA3/JA4 fingerprinting |
| VirusTotal | Domain and IP reputation checking |
| PassiveDNS | Historical DNS resolution data |
| Flare | C2 profile detection |

## Common Scenarios

1. **Cobalt Strike Beacon**: HTTP/HTTPS beaconing with configurable sleep time and jitter to malleable C2 profiles.
2. **DNS Tunneling C2**: Data exfiltration and command receipt via encoded DNS TXT/CNAME queries to attacker-controlled domains.
3. **Sliver C2 over HTTPS**: Modern C2 framework using HTTPS with configurable beacon intervals and domain fronting.
4. **DGA-based C2**: Malware generating random domains daily, with adversary registering upcoming domains for C2.
5. **Legitimate Service Abuse**: C2 over legitimate cloud services (Azure, AWS, Slack, Discord, Telegram).

## Output Format

```
Hunt ID: TH-C2-[DATE]-[SEQ]
Source IP: [Internal IP]
Source Host: [Hostname]
Destination: [Domain/IP]
Protocol: [HTTP/HTTPS/DNS/Custom]
Beacon Interval: [Average seconds]
Jitter: [Percentage]
Connection Count: [Total connections]
Data Volume: [Bytes sent/received]
First Seen: [Timestamp]
Last Seen: [Timestamp]
Domain Age: [Days]
TI Match: [Yes/No - source]
Risk Level: [Critical/High/Medium/Low]
```
