---
name: collecting-threat-intelligence-with-misp
description: MISP (Malware Information Sharing Platform) is an open-source threat intelligence platform for gathering, sharing, storing, and correlating Indicators of Compromise (IOCs) of targeted attacks, threat 
domain: cybersecurity
subdomain: threat-intelligence
tags: [threat-intelligence, cti, ioc, mitre-attack, stix, misp, taxii, threat-sharing]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Collecting Threat Intelligence with MISP

## Overview

MISP (Malware Information Sharing Platform) is an open-source threat intelligence platform for gathering, sharing, storing, and correlating Indicators of Compromise (IOCs) of targeted attacks, threat intelligence, financial fraud information, vulnerability information, or counter-terrorism information. This skill covers deploying MISP, configuring threat feeds, using the PyMISP API for programmatic access, and building automated collection pipelines that aggregate IOCs from multiple community and commercial sources.

## Prerequisites

- Python 3.9+ with `pymisp` library installed
- Docker and Docker Compose for MISP deployment
- Understanding of STIX 2.1 and TAXII 2.1 protocols
- Familiarity with IOC types: hashes, IP addresses, domains, URLs, email addresses
- Network access to MISP community feeds (circl.lu, botvrij.eu)

## Key Concepts

### MISP Architecture

MISP operates on an event-based model where threat intelligence is organized into events containing attributes (IOCs), objects (structured groupings of attributes), galaxies (threat actor/malware clusters linked to MITRE ATT&CK), and tags for classification. Synchronization between MISP instances uses a pull/push model over HTTPS with API key authentication.

### Feed Types

- **MISP Feeds**: Native JSON/CSV feeds from MISP community (CIRCL OSINT, botvrij.eu)
- **Freetext Feeds**: Unstructured text feeds parsed for IOCs (abuse.ch, Feodo Tracker)
- **TAXII Feeds**: STIX/TAXII 2.1 compatible feeds from commercial and government sources
- **CSV Feeds**: Structured CSV feeds with configurable column mapping

### PyMISP API

PyMISP is the official Python library to access MISP platforms via their REST API. It supports fetching events, adding/updating events and attributes, uploading samples, and searching across the entire MISP dataset. Authentication uses an API key passed in the `Authorization` header.

## Practical Steps

### Step 1: Deploy MISP with Docker

```bash
git clone https://github.com/MISP/misp-docker.git
cd misp-docker
cp template.env .env
# Edit .env to set MISP_BASEURL, MISP_ADMIN_EMAIL, MISP_ADMIN_PASSPHRASE
docker compose up -d
```

### Step 2: Configure Default Feeds

Enable built-in MISP feeds via the web UI or API:

```python
from pymisp import PyMISP

misp = PyMISP('https://misp.local', 'YOUR_API_KEY', ssl=False)

# List available feeds
feeds = misp.feeds()
for feed in feeds:
    print(f"{feed['Feed']['id']}: {feed['Feed']['name']} - Enabled: {feed['Feed']['enabled']}")

# Enable CIRCL OSINT Feed
misp.enable_feed(feed_id=1)
misp.cache_feed(feed_id=1)
misp.fetch_feed(feed_id=1)
```

### Step 3: Add Custom Threat Feeds

```python
# Add abuse.ch URLhaus feed
feed_data = {
    'name': 'URLhaus Recent URLs',
    'provider': 'abuse.ch',
    'url': 'https://urlhaus.abuse.ch/downloads/csv_recent/',
    'source_format': 'csv',
    'input_source': 'network',
    'publish': False,
    'enabled': True,
    'headers': '',
    'distribution': 0,
    'sharing_group_id': 0,
    'tag_id': 0,
    'default': False,
    'lookup_visible': True
}
result = misp.add_feed(feed_data)
print(f"Feed added: {result}")
```

### Step 4: Programmatic Event Search and Retrieval

```python
from pymisp import PyMISP, MISPEvent
from datetime import datetime, timedelta

misp = PyMISP('https://misp.local', 'YOUR_API_KEY', ssl=False)

# Search for events from the last 7 days
result = misp.search(
    controller='events',
    date_from=(datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d'),
    type_attribute='ip-dst',
    to_ids=True,
    pythonify=True
)

for event in result:
    print(f"Event {event.id}: {event.info}")
    for attr in event.attributes:
        if attr.type == 'ip-dst' and attr.to_ids:
            print(f"  IOC: {attr.value} (category: {attr.category})")
```

### Step 5: Export IOCs for Downstream Tools

```python
# Export as STIX 2.1 bundle
stix_output = misp.search(
    controller='events',
    return_format='stix2',
    tags=['tlp:white'],
    published=True
)

# Export IDS-flagged attributes as Suricata rules
suricata_rules = misp.search(
    controller='attributes',
    return_format='suricata',
    to_ids=True,
    type_attribute=['ip-dst', 'domain', 'url']
)

# Export as CSV for SIEM ingestion
csv_output = misp.search(
    controller='attributes',
    return_format='csv',
    type_attribute='ip-dst',
    to_ids=True
)
```

## Validation Criteria

- MISP instance is deployed and accessible via HTTPS
- At least 3 community feeds are enabled and fetching data successfully
- PyMISP script can authenticate, search events, and retrieve IOCs
- Events contain properly tagged and categorized attributes
- Export to STIX 2.1 produces valid STIX bundles
- Automated feed fetch runs on schedule (cron or MISP scheduler)

## References

- [MISP Project Official Site](https://www.misp-project.org/)
- [PyMISP Documentation](https://pymisp.readthedocs.io/)
- [MISP GitHub Repository](https://github.com/MISP/MISP)
- [MISP OpenAPI Specification](https://www.misp-project.org/openapi/)
- [CIRCL OSINT Feed](https://www.circl.lu/doc/misp/feed-osint/)
