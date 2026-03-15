---
name: implementing-network-traffic-analysis-with-arkime
description: >-
  Deploy and query Arkime (formerly Moloch) for full packet capture network
  traffic analysis. Uses the Arkime API v3 to search sessions, download PCAPs,
  analyze connection patterns, detect beaconing behavior, and identify suspicious
  network flows. Monitors DNS queries, HTTP traffic, and TLS certificate anomalies
  across captured traffic.
domain: cybersecurity
subdomain: network-security
tags: [implementing, network, traffic, analysis]
version: "1.0"
author: mahipal
license: Apache-2.0
---

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
