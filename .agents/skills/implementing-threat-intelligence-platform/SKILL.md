---
name: implementing-threat-intelligence-platform
description: >-
  Build a MISP-backed threat intelligence platform that ingests IOCs from multiple feeds,
  correlates events with galaxy clusters, and enriches indicators via VirusTotal and AbuseIPDB.
  Uses PyMISP to create events, add attributes with IDS flags, tag with MITRE ATT&CK techniques,
  and export STIX 2.1 bundles for downstream SIEM consumption.
domain: cybersecurity
subdomain: threat-intelligence
tags: [implementing, threat, intelligence, platform]
version: "1.0"
author: mahipal
license: Apache-2.0
---

## Instructions

1. Install dependencies: `pip install pymisp requests stix2`
2. Deploy MISP instance and generate an API key from Administration > Auth Keys.
3. Use PyMISP to connect and create threat intelligence events:
   - Create events with threat level, distribution, and analysis status
   - Add attributes (ip-dst, domain, sha256, url) with to_ids flags
   - Tag events with MITRE ATT&CK technique identifiers
   - Correlate events across organizations
4. Ingest from external feeds: URLhaus, Feodo Tracker, MalwareBazaar.
5. Enrich IOCs via VirusTotal and AbuseIPDB APIs.
6. Export correlated events as STIX 2.1 bundles.

```bash
python scripts/agent.py --misp-url https://misp.local --misp-key <api_key> --ingest-feeds --output misp_report.json
```

## Examples

### Create MISP Event with IOCs
```python
from pymisp import PyMISP, MISPEvent, MISPAttribute
misp = PyMISP("https://misp.local", "api_key")
event = MISPEvent()
event.info = "Phishing Campaign - 2024-Q1"
event.threat_level_id = 2
event.add_attribute("ip-dst", "185.143.223.47", to_ids=True)
misp.add_event(event)
```
