---
name: processing-stix-taxii-feeds
description: >
  Processes STIX 2.1 threat intelligence bundles delivered via TAXII 2.1 servers, normalizing
  objects into platform-native schemas and routing them to appropriate consuming systems. Use when
  onboarding new TAXII collection endpoints, automating bi-directional intelligence sharing with
  ISACs, or building pipeline validation for malformed STIX bundles. Activates for requests
  involving OASIS STIX, TAXII server configuration, MISP TAXII, or Cortex XSOAR feed integrations.
domain: cybersecurity
subdomain: threat-intelligence
tags: [STIX-2.1, TAXII-2.1, OASIS, MISP, CTI, IOC, threat-intelligence, NIST-SP-800-150]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Processing STIX/TAXII Feeds

## When to Use

Use this skill when:
- Onboarding a new TAXII 2.1 collection from a government feed (CISA AIS, FS-ISAC) or commercial provider
- Validating that ingested STIX bundles conform to the OASIS STIX 2.1 specification before import
- Building automated pipelines that parse STIX relationship objects to reconstruct campaign context

**Do not use** this skill for proprietary vendor feed formats (Recorded Future JSON, CrowdStrike IOC lists) that require vendor-specific parsers rather than STIX processing.

## Prerequisites

- Python 3.9+ with `stix2` library (pip install stix2) and `taxii2-client` library
- Network access to TAXII 2.1 server endpoint with valid credentials
- Target TIP or SIEM with import API (MISP, OpenCTI, or Splunk ES)

## Workflow

### Step 1: Discover TAXII Server Collections

```python
from taxii2client.v21 import Server, as_pages

server = Server("https://cti.example.com/taxii/",
                user="apiuser", password="apikey")
api_root = server.api_roots[0]
for collection in api_root.collections:
    print(collection.id, collection.title, collection.can_read)
```

Select collections relevant to your threat profile. CISA AIS provides collections segmented by sector (financial, energy, healthcare).

### Step 2: Fetch STIX Bundles with Pagination

```python
from taxii2client.v21 import Collection
from datetime import datetime, timedelta, timezone

collection = Collection(
    "https://cti.example.com/taxii/api1/collections/<id>/objects/",
    user="apiuser", password="apikey")

# Fetch only objects added in the last 24 hours
added_after = datetime.now(timezone.utc) - timedelta(hours=24)
for bundle_page in as_pages(collection.get_objects,
                             added_after=added_after, per_request=100):
    process_bundle(bundle_page)
```

### Step 3: Parse and Validate STIX Objects

```python
import stix2

def process_bundle(bundle_dict):
    bundle = stix2.parse(bundle_dict, allow_custom=True)
    for obj in bundle.objects:
        if obj.type == "indicator":
            validate_indicator(obj)
        elif obj.type == "threat-actor":
            upsert_threat_actor(obj)
        elif obj.type == "relationship":
            link_objects(obj)

def validate_indicator(indicator):
    required = ["id", "type", "spec_version", "created",
                "modified", "pattern", "pattern_type", "valid_from"]
    for field in required:
        if not hasattr(indicator, field):
            raise ValueError(f"Missing required field: {field}")
    # Check confidence range
    if hasattr(indicator, "confidence"):
        assert 0 <= indicator.confidence <= 100
```

### Step 4: Route Objects to Consuming Platforms

Map STIX object types to destination systems:
- `indicator` objects → SIEM lookup tables and firewall blocklists
- `malware` objects → EDR threat intelligence library
- `threat-actor` / `campaign` objects → TIP for analyst context
- `course-of-action` objects → Security team wiki or SOAR playbook triggers

Use TLP marking definitions to enforce sharing restrictions:
```python
for marking in obj.get("object_marking_refs", []):
    if "tlp-red" in marking:
        route_to_restricted_platform_only(obj)
```

### Step 5: Publish Back to TAXII (Bi-directional Sharing)

```python
# Add validated local intelligence back to shared collection
new_indicator = stix2.Indicator(
    name="Malicious C2 Domain",
    pattern="[domain-name:value = 'evil-c2.example.com']",
    pattern_type="stix",
    valid_from="2025-01-15T00:00:00Z",
    confidence=80,
    labels=["malicious-activity"],
    object_marking_refs=["marking-definition--34098fce-860f-479c-ae..."]  # TLP:GREEN
)
collection.add_objects(stix2.Bundle(new_indicator))
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **STIX Bundle** | Top-level STIX container object (type: "bundle") holding any number of STIX Domain Objects (SDOs) and STIX Relationship Objects (SROs) |
| **SDO** | STIX Domain Object — core intelligence types: indicator, threat-actor, malware, campaign, attack-pattern, course-of-action |
| **SRO** | STIX Relationship Object — links two SDOs with a labeled relationship (e.g., "uses", "attributed-to", "indicates") |
| **Pattern Language** | STIX pattern syntax for indicator conditions: `[network-traffic:dst_port = 443 AND ipv4-addr:value = '10.0.0.1']` |
| **Marking Definition** | STIX object encoding TLP or statement restrictions on intelligence sharing |
| **added_after** | TAXII 2.1 filter parameter (RFC 3339 timestamp) for incremental polling of new objects |

## Tools & Systems

- **stix2 (Python)**: Official OASIS Python library for creating, parsing, and validating STIX 2.0/2.1 objects
- **taxii2-client (Python)**: Client library for TAXII 2.0/2.1 server discovery, collection enumeration, and object retrieval
- **MISP**: Open-source TIP with native TAXII 2.1 server and client; MISP-TAXII-Server plugin for publishing MISP events
- **OpenCTI**: CTI platform with built-in TAXII 2.1 connector; supports STIX 2.1 import/export natively
- **Cabby**: Legacy Python TAXII 1.x client for older government feeds still on TAXII 1.1

## Common Pitfalls

- **Ignoring `spec_version` field**: STIX 2.0 and 2.1 have incompatible schemas (2.1 adds `confidence`, `object_marking_refs` at bundle level). Always check `spec_version` before parsing.
- **No pagination handling**: TAXII servers cap responses at 100–1000 objects per request. Missing pagination (via `next` link header) causes silent data loss.
- **Clock skew on `added_after`**: Server and client time misalignment causes missed objects at interval boundaries. Use UTC exclusively and add 5-minute overlap windows.
- **Storing raw STIX blobs without indexing**: Storing bundles as opaque JSON prevents querying by indicator type or campaign. Parse into relational or graph database.
- **Sharing TLP:RED content inadvertently**: Automated pipelines must filter marking definitions before routing to any shared platform or SIEM with broad analyst access.
