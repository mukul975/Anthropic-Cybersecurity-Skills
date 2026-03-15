---
name: analyzing-threat-landscape-with-misp
description: >-
  Analyze the threat landscape using MISP (Malware Information Sharing Platform)
  by querying event statistics, attribute distributions, threat actor galaxy
  clusters, and tag trends over time. Uses PyMISP to pull event data, compute
  IOC type breakdowns, identify top threat actors and malware families, and
  generate threat landscape reports with temporal trends.
domain: cybersecurity
subdomain: threat-intelligence
tags: [analyzing, threat, landscape, with]
version: "1.0"
author: mahipal
license: Apache-2.0
---

## Instructions

1. Install dependencies: `pip install pymisp`
2. Configure MISP URL and API key.
3. Run the agent to generate threat landscape analysis:
   - Pull event statistics by threat level and date range
   - Analyze attribute type distributions (IP, domain, hash, URL)
   - Identify top MITRE ATT&CK techniques from event tags
   - Track threat actor activity via galaxy clusters
   - Generate temporal trend analysis of IOC submissions

```bash
python scripts/agent.py --misp-url https://misp.local --api-key YOUR_KEY --days 90 --output landscape_report.json
```

## Examples

### Threat Landscape Summary
```
Period: Last 90 days
Events analyzed: 1,247
Top threat level: High (43%)
Top attribute type: ip-dst (31%), domain (22%), sha256 (18%)
Top MITRE technique: T1566 Phishing (89 events)
Top threat actor: APT28 (34 events)
```
