---
name: building-threat-intelligence-feed-integration
description: >
  Builds automated threat intelligence feed integration pipelines connecting STIX/TAXII feeds,
  open-source threat intel, and commercial TI platforms into SIEM and security tools for real-time
  IOC matching and alerting. Use when SOC teams need to operationalize threat intelligence by
  automating feed ingestion, normalization, scoring, and distribution to detection systems.
domain: cybersecurity
subdomain: soc-operations
tags: [soc, threat-intelligence, stix, taxii, misp, feeds, ioc, siem-integration]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Building Threat Intelligence Feed Integration

## When to Use

Use this skill when:
- SOC teams need automated ingestion of threat intelligence feeds into SIEM platforms
- Multiple TI sources require normalization into a common format (STIX 2.1)
- Detection systems need real-time IOC matching against network and endpoint telemetry
- TI feed quality assessment and deduplication processes need to be established

**Do not use** for manual IOC lookup — use dedicated enrichment tools (VirusTotal, AbuseIPDB) for ad-hoc queries.

## Prerequisites

- MISP instance or Threat Intelligence Platform (TIP) for feed aggregation
- STIX/TAXII client library (`taxii2-client`, `stix2` Python packages)
- SIEM platform (Splunk ES, Elastic Security, or Sentinel) with TI framework configured
- API keys for commercial and open-source feeds (AlienVault OTX, Abuse.ch, CISA AIS)
- Python 3.8+ for feed processing automation

## Workflow

### Step 1: Identify and Catalog Intelligence Sources

Map available feeds by type, format, and update frequency:

| Feed Source | Format | IOC Types | Update Freq | Cost |
|-------------|--------|-----------|-------------|------|
| AlienVault OTX | STIX/JSON | IP, Domain, Hash, URL | Real-time | Free |
| Abuse.ch URLhaus | CSV/JSON | URL, Domain | Every 5 min | Free |
| Abuse.ch MalwareBazaar | JSON API | File Hash | Real-time | Free |
| CISA AIS | STIX/TAXII 2.1 | All types | Daily | Free (US Gov) |
| CrowdStrike Intel | STIX/JSON | All types + Actor TTP | Real-time | Commercial |
| Mandiant Advantage | STIX 2.1 | All types + Reports | Real-time | Commercial |

### Step 2: Ingest STIX/TAXII Feeds

Connect to a TAXII 2.1 server and download indicators:

```python
from taxii2client.v21 import Server, Collection
from stix2 import parse

# Connect to TAXII server (example: CISA AIS)
server = Server(
    "https://taxii.cisa.gov/taxii2/",
    user="your_username",
    password="your_password"
)

# List available collections
for api_root in server.api_roots:
    print(f"API Root: {api_root.title}")
    for collection in api_root.collections:
        print(f"  Collection: {collection.title} (ID: {collection.id})")

# Fetch indicators from a collection
collection = Collection(
    "https://taxii.cisa.gov/taxii2/collections/COLLECTION_ID/",
    user="your_username",
    password="your_password"
)

# Get indicators added in last 24 hours
from datetime import datetime, timedelta
added_after = (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

response = collection.get_objects(added_after=added_after, type=["indicator"])
for obj in response.get("objects", []):
    indicator = parse(obj)
    print(f"Type: {indicator.type}")
    print(f"Pattern: {indicator.pattern}")
    print(f"Valid Until: {indicator.valid_until}")
    print(f"Confidence: {indicator.confidence}")
    print("---")
```

### Step 3: Ingest Open-Source Feeds

**Abuse.ch URLhaus Feed:**

```python
import requests
import csv
from io import StringIO

# Download URLhaus recent URLs
response = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/")
reader = csv.reader(StringIO(response.text), delimiter=',')

indicators = []
for row in reader:
    if row[0].startswith("#"):
        continue
    indicators.append({
        "id": row[0],
        "dateadded": row[1],
        "url": row[2],
        "url_status": row[3],
        "threat": row[5],
        "tags": row[6]
    })

print(f"Ingested {len(indicators)} URLs from URLhaus")

# Filter for active threats only
active = [i for i in indicators if i["url_status"] == "online"]
print(f"Active threats: {len(active)}")
```

**AlienVault OTX Pulse Feed:**

```python
from OTXv2 import OTXv2, IndicatorTypes

otx = OTXv2("YOUR_OTX_API_KEY")

# Get subscribed pulses (last 24 hours)
pulses = otx.getall(modified_since="2024-03-14T00:00:00")

for pulse in pulses:
    print(f"Pulse: {pulse['name']}")
    print(f"Tags: {pulse['tags']}")
    for indicator in pulse["indicators"]:
        print(f"  IOC: {indicator['indicator']} ({indicator['type']})")
```

**Abuse.ch Feodo Tracker (C2 IPs):**

```python
response = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json")
c2_data = response.json()

for entry in c2_data:
    print(f"IP: {entry['ip_address']}:{entry['port']}")
    print(f"Malware: {entry['malware']}")
    print(f"First Seen: {entry['first_seen']}")
    print(f"Last Online: {entry['last_online']}")
```

### Step 4: Normalize and Deduplicate

Convert all feeds to STIX 2.1 format for standardization:

```python
from stix2 import Indicator, Bundle
import hashlib

def create_stix_indicator(ioc_value, ioc_type, source, confidence=50):
    """Convert raw IOC to STIX 2.1 indicator"""
    pattern_map = {
        "ipv4": f"[ipv4-addr:value = '{ioc_value}']",
        "domain": f"[domain-name:value = '{ioc_value}']",
        "url": f"[url:value = '{ioc_value}']",
        "sha256": f"[file:hashes.'SHA-256' = '{ioc_value}']",
        "md5": f"[file:hashes.MD5 = '{ioc_value}']",
    }

    return Indicator(
        name=f"{ioc_type}: {ioc_value}",
        pattern=pattern_map[ioc_type],
        pattern_type="stix",
        valid_from="2024-03-15T00:00:00Z",
        confidence=confidence,
        labels=[source],
        custom_properties={"x_source_feed": source}
    )

# Deduplicate across sources
seen_iocs = set()
unique_indicators = []

for ioc in all_collected_iocs:
    ioc_hash = hashlib.sha256(f"{ioc['type']}:{ioc['value']}".encode()).hexdigest()
    if ioc_hash not in seen_iocs:
        seen_iocs.add(ioc_hash)
        unique_indicators.append(
            create_stix_indicator(ioc["value"], ioc["type"], ioc["source"])
        )

bundle = Bundle(objects=unique_indicators)
print(f"Unique indicators: {len(unique_indicators)}")
```

### Step 5: Push to SIEM Threat Intelligence Framework

**Push to Splunk ES Threat Intelligence:**

```python
import requests

splunk_url = "https://splunk.company.com:8089"
headers = {"Authorization": f"Bearer {splunk_token}"}

for indicator in unique_indicators:
    # Extract IOC value from STIX pattern
    ioc_value = indicator.pattern.split("'")[1]

    # Upload to Splunk ES threat intel collection
    data = {
        "ip": ioc_value,
        "description": indicator.name,
        "weight": indicator.confidence // 10,
        "threat_key": indicator.id,
        "source_feed": indicator.get("x_source_feed", "unknown")
    }

    requests.post(
        f"{splunk_url}/services/data/threat_intel/item/ip_intel",
        headers=headers, data=data, verify=False
    )
```

**Push to MISP for centralized management:**

```python
from pymisp import PyMISP, MISPEvent, MISPAttribute

misp = PyMISP("https://misp.company.com", "YOUR_MISP_API_KEY")

# Create event for feed batch
event = MISPEvent()
event.info = f"TI Feed Import - {datetime.now().strftime('%Y-%m-%d')}"
event.threat_level_id = 2  # Medium
event.analysis = 2  # Completed

# Add indicators as attributes
for ioc in unique_indicators:
    attr = MISPAttribute()
    attr.type = "ip-dst" if "ipv4" in ioc.pattern else "domain"
    attr.value = ioc.pattern.split("'")[1]
    attr.to_ids = True
    attr.comment = f"Source: {ioc.get('x_source_feed', 'mixed')}"
    event.add_attribute(**attr)

result = misp.add_event(event)
print(f"MISP Event created: {result['Event']['id']}")
```

### Step 6: Monitor Feed Health and Quality

Track feed effectiveness metrics:

```spl
index=threat_intel sourcetype="threat_intel_manager"
| stats count AS total_iocs,
        dc(threat_key) AS unique_iocs,
        dc(source_feed) AS feed_count
  by source_feed
| join source_feed [
    search index=notable source="Threat Intelligence"
    | stats count AS matches by source_feed
  ]
| eval match_rate = round(matches / unique_iocs * 100, 2)
| sort - match_rate
| table source_feed, unique_iocs, matches, match_rate
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **STIX 2.1** | Structured Threat Information Expression — standardized JSON format for sharing threat intelligence objects |
| **TAXII** | Trusted Automated eXchange of Indicator Information — transport protocol for sharing STIX data via REST API |
| **TIP** | Threat Intelligence Platform — centralized system for aggregating, scoring, and distributing threat intelligence |
| **IOC Scoring** | Process of assigning confidence values to indicators based on source reliability and corroboration |
| **Feed Deduplication** | Removing duplicate IOCs across multiple sources while preserving multi-source attribution |
| **IOC Expiration** | Time-to-live policy removing aged indicators (IP: 30 days, Domain: 90 days, Hash: 1 year) |

## Tools & Systems

- **MISP**: Open-source threat intelligence platform for feed aggregation, correlation, and sharing
- **AlienVault OTX**: Free threat intelligence sharing platform with community pulse feeds
- **Abuse.ch**: Suite of free threat feeds (URLhaus, MalwareBazaar, Feodo Tracker, ThreatFox)
- **OpenCTI**: Open-source cyber threat intelligence platform supporting STIX 2.1 native storage
- **TAXII2 Client**: Python library for connecting to STIX/TAXII 2.1 servers for automated indicator retrieval

## Common Scenarios

- **New Feed Onboarding**: Evaluate feed quality, map fields to STIX, configure automated ingestion pipeline
- **Multi-SIEM Distribution**: Push normalized IOCs from MISP to Splunk, Elastic, and Sentinel simultaneously
- **False Positive Reduction**: Score IOCs by source count and age, expire stale indicators automatically
- **Feed Quality Audit**: Compare detection match rates across feeds to identify highest-value sources
- **Incident IOC Sharing**: Package investigation IOCs as STIX bundle and share with ISACs via TAXII

## Output Format

```
THREAT INTEL FEED STATUS — Daily Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Date:         2024-03-15
Total IOCs:   45,892 active indicators

Feed Health:
  Feed                  IOCs    Matches  Match Rate  Status
  Abuse.ch URLhaus      12,340  47       0.38%       HEALTHY
  AlienVault OTX        18,567  23       0.12%       HEALTHY
  Abuse.ch Feodo        1,203   12       1.00%       HEALTHY
  CISA AIS              8,945   8        0.09%       HEALTHY
  CrowdStrike Intel     4,837   31       0.64%       HEALTHY

Actions Today:
  New IOCs ingested:    1,247
  IOCs expired:         892
  Duplicates removed:   156
  SIEM matches:         121 notable events generated
  False positives:      3 (CDN IPs removed from feed)
```
