---
name: implementing-stix-taxii-feed-integration
description: STIX (Structured Threat Information eXpression) and TAXII (Trusted Automated eXchange of Intelligence Information) are OASIS open standards for representing and transporting cyber threat intelligence.
domain: cybersecurity
subdomain: threat-intelligence
tags: [threat-intelligence, cti, ioc, mitre-attack, stix, taxii, feed-integration, oasis]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Implementing STIX/TAXII Feed Integration

## Overview

STIX (Structured Threat Information eXpression) and TAXII (Trusted Automated eXchange of Intelligence Information) are OASIS open standards for representing and transporting cyber threat intelligence. This skill covers implementing a STIX/TAXII 2.1 feed consumer and producer using Python, configuring TAXII server discovery, collection management, polling for new intelligence, parsing STIX 2.1 objects, and integrating feeds into SIEM and TIP platforms.

## Prerequisites

- Python 3.9+ with `taxii2-client`, `stix2`, `cti-taxii-client` libraries
- Understanding of STIX 2.1 data model (SDOs, SCOs, SROs)
- Understanding of TAXII 2.1 protocol (discovery, API roots, collections)
- Network access to TAXII servers (MITRE ATT&CK TAXII, Anomali STAXX)
- Optional: medallion for running a local TAXII 2.1 server

## Key Concepts

### TAXII 2.1 Architecture

TAXII defines a RESTful API with three service types:
- **Discovery**: Returns information about available API roots
- **API Root**: Contains collections and serves as the main interaction point
- **Collection**: A logical grouping of STIX objects accessible via GET/POST

### STIX 2.1 Object Model

STIX objects are categorized as:
- **SDOs (STIX Domain Objects)**: Indicator, Malware, Threat Actor, Campaign, Attack Pattern, Tool, Infrastructure, Vulnerability, Identity, Location, Note, Opinion, Report, Grouping
- **SCOs (STIX Cyber Observables)**: IPv4-Addr, Domain-Name, URL, File, Email-Addr, Process, Network-Traffic, Artifact
- **SROs (STIX Relationship Objects)**: Relationship, Sighting
- **Meta Objects**: Marking Definition (TLP), Language Content, Extension Definition

### STIX Bundle

A Bundle is a collection of STIX objects transmitted together. Bundles have a unique ID and contain an array of objects. TAXII collections serve bundles in response to GET requests.

## Practical Steps

### Step 1: TAXII Server Discovery

```python
from taxii2client.v21 import Server, Collection, as_pages

# Connect to MITRE ATT&CK TAXII server
server = Server("https://cti-taxii.mitre.org/taxii2/", user="", password="")

print(f"Title: {server.title}")
print(f"Description: {server.description}")

# List API roots
for api_root in server.api_roots:
    print(f"\nAPI Root: {api_root.title}")
    print(f"  URL: {api_root.url}")

    # List collections
    for collection in api_root.collections:
        print(f"  Collection: {collection.title} (ID: {collection.id})")
        print(f"    Can Read: {collection.can_read}")
        print(f"    Can Write: {collection.can_write}")
```

### Step 2: Fetch STIX Objects from Collection

```python
from taxii2client.v21 import Collection, as_pages
import json

# Connect to Enterprise ATT&CK collection
ENTERPRISE_ATTACK_ID = "95ecc380-afe9-11e4-9b6c-751b66dd541e"
collection = Collection(
    f"https://cti-taxii.mitre.org/stix/collections/{ENTERPRISE_ATTACK_ID}/",
    user="",
    password="",
)

print(f"Collection: {collection.title}")

# Fetch all objects (paginated)
all_objects = []
for envelope in as_pages(collection.get_objects, per_request=50):
    objects = envelope.get("objects", [])
    all_objects.extend(objects)
    print(f"  Fetched {len(objects)} objects (total: {len(all_objects)})")

print(f"\nTotal objects retrieved: {len(all_objects)}")

# Categorize by type
type_counts = {}
for obj in all_objects:
    obj_type = obj.get("type", "unknown")
    type_counts[obj_type] = type_counts.get(obj_type, 0) + 1

for obj_type, count in sorted(type_counts.items()):
    print(f"  {obj_type}: {count}")
```

### Step 3: Parse STIX 2.1 Objects with stix2 Library

```python
from stix2 import parse, Filter, MemoryStore

# Load objects into a MemoryStore for querying
store = MemoryStore(stix_data=all_objects)

# Query for all indicators
indicators = store.query([Filter("type", "=", "indicator")])
print(f"Indicators: {len(indicators)}")

for ind in indicators[:5]:
    print(f"  {ind.name}: {ind.pattern}")

# Query for malware
malware_list = store.query([Filter("type", "=", "malware")])
print(f"\nMalware families: {len(malware_list)}")

# Query for threat actors
actors = store.query([Filter("type", "=", "intrusion-set")])
print(f"Threat actors: {len(actors)}")

# Find relationships for a specific object
def get_related(store, source_id):
    relationships = store.query([
        Filter("type", "=", "relationship"),
        Filter("source_ref", "=", source_id),
    ])
    return relationships

# Example: Get all techniques used by APT28
apt28 = store.query([
    Filter("type", "=", "intrusion-set"),
    Filter("name", "=", "APT28"),
])
if apt28:
    rels = get_related(store, apt28[0].id)
    for rel in rels:
        target = store.get(rel.target_ref)
        if target:
            print(f"  {rel.relationship_type} -> {target.name} ({target.type})")
```

### Step 4: Implement Custom TAXII Consumer

```python
from taxii2client.v21 import Collection, as_pages
from stix2 import parse, Bundle
from datetime import datetime, timedelta
import json

class TAXIIConsumer:
    """Consume STIX/TAXII 2.1 feeds and extract IOCs."""

    def __init__(self, collection_url, user="", password=""):
        self.collection = Collection(collection_url, user=user, password=password)
        self.last_poll = None

    def poll_new_objects(self, added_after=None):
        """Poll for objects added after a specific timestamp."""
        if added_after is None:
            added_after = (
                self.last_poll or
                (datetime.utcnow() - timedelta(days=1)).strftime(
                    "%Y-%m-%dT%H:%M:%S.000Z"
                )
            )

        all_objects = []
        kwargs = {"added_after": added_after}

        for envelope in as_pages(
            self.collection.get_objects, per_request=100, **kwargs
        ):
            objects = envelope.get("objects", [])
            all_objects.extend(objects)

        self.last_poll = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
        return all_objects

    def extract_indicators(self, objects):
        """Extract actionable indicators from STIX objects."""
        indicators = []
        for obj in objects:
            if obj.get("type") == "indicator":
                indicators.append({
                    "id": obj.get("id"),
                    "name": obj.get("name", ""),
                    "pattern": obj.get("pattern", ""),
                    "pattern_type": obj.get("pattern_type", ""),
                    "valid_from": obj.get("valid_from", ""),
                    "valid_until": obj.get("valid_until", ""),
                    "indicator_types": obj.get("indicator_types", []),
                    "confidence": obj.get("confidence", 0),
                    "labels": obj.get("labels", []),
                })
        return indicators

    def extract_observables(self, objects):
        """Extract STIX Cyber Observables."""
        observables = []
        observable_types = {
            "ipv4-addr", "ipv6-addr", "domain-name", "url",
            "file", "email-addr", "network-traffic",
        }
        for obj in objects:
            if obj.get("type") in observable_types:
                observables.append({
                    "type": obj["type"],
                    "value": obj.get("value", ""),
                    "id": obj.get("id"),
                })
        return observables


# Usage
consumer = TAXIIConsumer(
    f"https://cti-taxii.mitre.org/stix/collections/{ENTERPRISE_ATTACK_ID}/"
)
new_objects = consumer.poll_new_objects()
indicators = consumer.extract_indicators(new_objects)
print(f"New indicators: {len(indicators)}")
```

### Step 5: Set Up Local TAXII Server with Medallion

```python
# medallion configuration (medallion.conf)
TAXII_CONFIG = {
    "backend": {
        "module_class": "MemoryBackend",
    },
    "users": {
        "admin": "admin_password",
        "readonly": "readonly_password",
    },
    "taxii": {
        "max_content_length": 10485760,
    },
}

# Run medallion server:
# pip install medallion
# python -m medallion --config medallion.conf --port 5000

# Add objects to local TAXII server
import requests

def push_to_taxii(server_url, collection_id, stix_bundle, user, password):
    """Push STIX bundle to a TAXII 2.1 collection."""
    url = f"{server_url}/collections/{collection_id}/objects/"
    headers = {
        "Content-Type": "application/stix+json;version=2.1",
        "Accept": "application/taxii+json;version=2.1",
    }
    response = requests.post(
        url,
        json=stix_bundle,
        headers=headers,
        auth=(user, password),
        timeout=30,
    )
    return response.json()
```

## Validation Criteria

- TAXII server discovery returns valid API roots and collections
- STIX objects fetched and parsed correctly from TAXII collections
- Indicators extracted with valid STIX patterns
- Pagination handled correctly for large collections
- Consumer tracks polling state for incremental updates
- Local TAXII server accepts and serves STIX bundles

## References

- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [TAXII 2.1 Specification](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html)
- [taxii2-client PyPI](https://pypi.org/project/taxii2-client/)
- [stix2 Python Library](https://stix2.readthedocs.io/)
- [MITRE ATT&CK TAXII Server](https://cti-taxii.mitre.org/taxii2/)
- [Medallion TAXII Server](https://github.com/oasis-open/cti-taxii-server)
