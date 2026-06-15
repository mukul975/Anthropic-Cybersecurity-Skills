---
name: implementing-network-traffic-analysis-with-arkime
description: Deploy and query Arkime (formerly Moloch) for full packet capture network
  traffic analysis. Uses the Arkime API v3 to search sessions, download PCAPs, analyze
  connection patterns, detect beaconing behavior, and identify suspicious network
  flows. Monitors DNS queries, HTTP traffic, and TLS certificate anomalies across
  captured traffic.
domain: cybersecurity
subdomain: network-security
tags:
- network-security
- arkime
- full-packet-capture
- nta
- pcap-analysis
- network-forensics
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
mitre_attack:
- T1046
- T1040
- T1557
- T1071
- T1095
---


# Implementing Network Traffic Analysis with Arkime


## When to Use

- When deploying or configuring implementing network traffic analysis with arkime capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Prerequisites

- Familiarity with network security concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install requests`
2. Configure Arkime viewer URL and credentials.
3. Run the agent to query Arkime sessions and analyze traffic:
   - Search sessions by IP, port, protocol, or expression
   - Download PCAP data for forensic analysis
   - Detect C2 beaconing via connection interval analysis
   - Identify DNS tunneling through query length statistics
   - Flag connections to known-bad TLS certificate issuers

```bash
python scripts/agent.py --arkime-url https://arkime.local:8005 --user admin --password secret --output arkime_report.json
```

## Examples

### Beaconing Detection
```
Source: 10.1.2.50 -> 185.220.101.34:443
Sessions: 288 over 24 hours
Avg interval: 300s, Jitter: 4.2%
Verdict: HIGH confidence C2 beaconing (jitter < 5%)
```
