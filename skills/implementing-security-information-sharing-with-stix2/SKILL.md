---
name: implementing-security-information-sharing-with-stix2
description: 'Create, validate, and share STIX 2.1 threat intelligence objects using
  the stix2 Python library. Covers indicators, malware, campaigns, relationships,
  bundles, and TAXII 2.1 publishing.

  '
domain: cybersecurity
subdomain: threat-intelligence
tags:
- stix
- taxii
- threat-sharing
- intelligence-exchange
version: '1.0'
author: mahipal
license: Apache-2.0
d3fend_techniques:
- File Metadata Consistency Validation
- Application Protocol Command Analysis
- Identifier Analysis
- Content Format Conversion
- Message Analysis
nist_csf:
- ID.RA-01
- ID.RA-05
- DE.CM-01
- DE.AE-02
mitre_attack:
- T1591
- T1592
- T1593
- T1589
- T1027
---

# Implementing Security Information Sharing with STIX 2.1

Build and share structured threat intelligence using STIX 2.1 objects
with the stix2 Python library and TAXII 2.1 transport protocol.

## When to Use

- Building a threat intelligence platform that exchanges IOCs with partner organizations
- Automating ingestion and export of indicators from MISP, OpenCTI, or other TIP platforms
- Creating machine-readable intelligence reports for ISAC/ISAO sharing communities
- Publishing threat data to a TAXII 2.1 server for downstream consumption by SIEMs and SOARs
- Converting unstructured threat reports into standardized STIX 2.1 bundles
- Enriching detection rules with context by linking indicators to malware, campaigns, and threat actors

**Do not use** for sharing simple IP blocklists or CSV-based IOC feeds that do not require relationship context; plain-text feeds with simpler formats like CSV or OpenIOC may be more efficient in those cases.

## Prerequisites

- Python 3.8+ with `stix2` library (`pip install stix2`)
- `taxii2-client` for consuming TAXII feeds (`pip install taxii2-client`)
- A TAXII 2.1 server endpoint for publishing (e.g., OpenTAXII, Medallion, or MISP TAXII service)
- Familiarity with STIX 2.1 SDO types: Indicator, Malware, Threat Actor, Campaign, Attack Pattern, Identity
- Familiarity with STIX 2.1 SRO types: Relationship, Sighting
- Optional: OpenCTI or MISP instance for end-to-end integration testing

## Workflow

### Step 1: Install Dependencies

```bash
pip install stix2 taxii2-client requests
```

### Step 2: Create STIX 2.1 Domain Objects (SDOs)

Create core intelligence objects that describe threats, actors, and campaigns:

```python
from stix2 import (
    Indicator, Malware, ThreatActor, Campaign,
    AttackPattern, Identity, Relationship, Bundle,
    ExternalReference
)
from datetime import datetime

# Create a producer identity
producer = Identity(
    name="ACME Threat Intel Team",
    identity_class="organization",
    sectors=["technology"],
    contact_information="threatintel@acme.example.com"
)

# Create a malware object
emotet_malware = Malware(
    name="Emotet",
    description="Banking trojan turned modular botnet loader. "
                "Distributed via malspam with macro-enabled Office documents.",
    malware_types=["trojan", "bot"],
    is_family=True,
    created_by_ref=producer.id
)

# Create an attack pattern referencing MITRE ATT&CK
spearphishing_pattern = AttackPattern(
    name="Spearphishing Attachment",
    description="Adversaries send spearphishing emails with a malicious attachment.",
    external_references=[
        ExternalReference(
            source_name="mitre-attack",
            external_id="T1566.001",
            url="https://attack.mitre.org/techniques/T1566/001/"
        )
    ],
    created_by_ref=producer.id
)

# Create a threat actor
threat_actor = ThreatActor(
    name="Mummy Spider",
    description="Cybercriminal group operating the Emotet botnet infrastructure.",
    threat_actor_types=["crime-syndicate"],
    aliases=["TA542", "Gold Crestwood"],
    primary_motivation="personal-gain",
    created_by_ref=producer.id
)

# Create a campaign
campaign = Campaign(
    name="Emotet Q1 2026 Resurgence",
    description="Renewed Emotet distribution campaign using thread-hijacked "
                "reply-chain emails with OneNote lure attachments.",
    first_seen="2026-01-15T00:00:00Z",
    created_by_ref=producer.id
)

print(f"Created malware SDO: {emotet_malware.id}")
print(f"Created threat actor SDO: {threat_actor.id}")
print(f"Created campaign SDO: {campaign.id}")
```

### Step 3: Create STIX Indicators with Patterns

Define detection patterns using the STIX Patterning Language:

```python
# File hash indicator
hash_indicator = Indicator(
    name="Emotet dropper hash",
    description="SHA-256 hash of Emotet first-stage dropper observed in Jan 2026 campaign.",
    indicator_types=["malicious-activity"],
    pattern_type="stix",
    pattern="[file:hashes.'SHA-256' = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2']",
    valid_from="2026-01-15T00:00:00Z",
    created_by_ref=producer.id
)

# Network indicator for C2 domain
c2_indicator = Indicator(
    name="Emotet C2 domain",
    description="Command and control domain observed in Emotet tier-1 botnet infrastructure.",
    indicator_types=["malicious-activity"],
    pattern_type="stix",
    pattern="[domain-name:value = 'malicious-c2.example.com']",
    valid_from="2026-01-20T00:00:00Z",
    created_by_ref=producer.id
)

# Compound pattern: process spawning with suspicious command line
process_indicator = Indicator(
    name="Emotet PowerShell download cradle",
    description="PowerShell execution pattern used by Emotet to download next-stage payload.",
    indicator_types=["malicious-activity"],
    pattern_type="stix",
    pattern=(
        "[process:command_line MATCHES 'powershell.*-enc.*' "
        "AND process:parent_ref.name = 'winword.exe']"
    ),
    valid_from="2026-01-15T00:00:00Z",
    created_by_ref=producer.id
)

# Email subject indicator
email_indicator = Indicator(
    name="Emotet phishing subject line pattern",
    description="Subject line pattern seen in thread-hijacked Emotet phishing emails.",
    indicator_types=["malicious-activity"],
    pattern_type="stix",
    pattern="[email-message:subject MATCHES '^RE:.*Invoice.*[0-9]{6}']",
    valid_from="2026-01-15T00:00:00Z",
    created_by_ref=producer.id
)

print(f"Created {4} indicator objects")
```

### Step 4: Build Relationships Between Objects

Link SDOs together using Relationship objects to express how threats are connected:

```python
# Malware uses attack pattern
rel_malware_attack = Relationship(
    relationship_type="uses",
    source_ref=emotet_malware.id,
    target_ref=spearphishing_pattern.id,
    description="Emotet is distributed via spearphishing attachments.",
    created_by_ref=producer.id
)

# Threat actor uses malware
rel_actor_malware = Relationship(
    relationship_type="uses",
    source_ref=threat_actor.id,
    target_ref=emotet_malware.id,
    description="Mummy Spider operates the Emotet malware infrastructure.",
    created_by_ref=producer.id
)

# Indicator indicates malware
rel_indicator_malware = Relationship(
    relationship_type="indicates",
    source_ref=hash_indicator.id,
    target_ref=emotet_malware.id,
    description="File hash indicator for Emotet dropper binary.",
    created_by_ref=producer.id
)

# Campaign uses malware
rel_campaign_malware = Relationship(
    relationship_type="uses",
    source_ref=campaign.id,
    target_ref=emotet_malware.id,
    created_by_ref=producer.id
)

# Threat actor attributed to campaign
rel_actor_campaign = Relationship(
    relationship_type="attributed-to",
    source_ref=campaign.id,
    target_ref=threat_actor.id,
    created_by_ref=producer.id
)

print(f"Created {5} relationship objects linking threat intelligence")
```

### Step 5: Assemble and Serialize a STIX Bundle

Package all objects into a bundle for sharing:

```python
import json

bundle = Bundle(
    objects=[
        producer,
        emotet_malware,
        spearphishing_pattern,
        threat_actor,
        campaign,
        hash_indicator,
        c2_indicator,
        process_indicator,
        email_indicator,
        rel_malware_attack,
        rel_actor_malware,
        rel_indicator_malware,
        rel_campaign_malware,
        rel_actor_campaign,
    ]
)

# Serialize to JSON
bundle_json = bundle.serialize(pretty=True)

# Write bundle to file for sharing
with open("emotet_campaign_bundle.json", "w") as f:
    f.write(bundle_json)

print(f"Bundle {bundle.id} contains {len(bundle.objects)} objects")
print(f"Written to emotet_campaign_bundle.json")

# Validate the bundle by re-parsing
from stix2 import parse
parsed = parse(bundle_json, allow_custom=False)
print(f"Bundle validation passed: {len(parsed.objects)} objects parsed successfully")
```

### Step 6: Consume Intelligence from a TAXII 2.1 Server

Retrieve published threat intelligence from a TAXII feed:

```python
from taxii2client.v21 import Server, Collection, as_pages
import json

# Connect to a TAXII 2.1 server
taxii_server = Server(
    "https://taxii.example.com/taxii2/",
    user="readonly",
    password="readonly_password"
)

# Discover API roots and collections
api_root = taxii_server.api_roots[0]
print(f"API Root: {api_root.title}")

for collection in api_root.collections:
    print(f"  Collection: {collection.title} (ID: {collection.id})")

# Fetch indicators from a specific collection
target_collection = Collection(
    f"https://taxii.example.com/taxii2/collections/{api_root.collections[0].id}/",
    user="readonly",
    password="readonly_password"
)

# Retrieve objects with filtering
response = target_collection.get_objects(
    added_after="2026-01-01T00:00:00Z",
    type=["indicator", "malware"]
)

stix_data = json.loads(response.text)
print(f"Retrieved {len(stix_data.get('objects', []))} objects from TAXII server")

# Process each retrieved object
for obj in stix_data.get("objects", []):
    if obj["type"] == "indicator":
        print(f"  Indicator: {obj['name']} | Pattern: {obj['pattern'][:60]}...")
    elif obj["type"] == "malware":
        print(f"  Malware: {obj['name']} | Family: {obj.get('is_family', False)}")
```

### Step 7: Publish Intelligence to a TAXII 2.1 Server

Push your STIX bundle to a writable TAXII collection:

```python
import requests
import json

TAXII_URL = "https://taxii.example.com/taxii2/collections/COLLECTION_ID/objects/"
TAXII_USER = "publisher"
TAXII_PASS = "publisher_password"

headers = {
    "Content-Type": "application/taxii+json;version=2.1",
    "Accept": "application/taxii+json;version=2.1"
}

# Read the bundle we created earlier
with open("emotet_campaign_bundle.json", "r") as f:
    bundle_data = f.read()

response = requests.post(
    TAXII_URL,
    headers=headers,
    auth=(TAXII_USER, TAXII_PASS),
    data=bundle_data,
    timeout=30
)

if response.status_code in (200, 201, 202):
    status = response.json()
    print(f"Published successfully. Status ID: {status.get('id')}")
    print(f"  Total count: {status.get('total_count')}")
    print(f"  Success count: {status.get('success_count')}")
    print(f"  Failure count: {status.get('failure_count')}")
else:
    print(f"Publishing failed: {response.status_code} - {response.text}")
```

### Step 8: Validate and Lint STIX Objects

Ensure objects comply with the STIX 2.1 specification:

```python
from stix2 import parse, exceptions
import json

def validate_stix_bundle(bundle_path):
    """Validate all objects in a STIX bundle against the 2.1 spec."""
    with open(bundle_path, "r") as f:
        raw = json.load(f)

    errors = []
    valid_count = 0

    for obj in raw.get("objects", []):
        try:
            parsed = parse(json.dumps(obj), allow_custom=False)
            valid_count += 1
        except (exceptions.InvalidValueError, exceptions.MissingPropertiesError) as e:
            errors.append({
                "object_id": obj.get("id", "unknown"),
                "object_type": obj.get("type", "unknown"),
                "error": str(e)
            })

    print(f"Validation results: {valid_count} valid, {len(errors)} errors")
    for err in errors:
        print(f"  ERROR in {err['object_type']} ({err['object_id']}): {err['error']}")

    return len(errors) == 0

validate_stix_bundle("emotet_campaign_bundle.json")
```

## Verification

- Confirm all STIX objects serialize to valid JSON and include required properties (`type`, `id`, `created`, `modified`)
- Verify relationship `source_ref` and `target_ref` point to existing object IDs within the bundle
- Validate indicator patterns parse correctly using the STIX patterning grammar
- Test TAXII publishing returns a success status with `success_count` matching the number of objects sent
- Re-retrieve published objects from the TAXII server and confirm they round-trip without data loss
- Check that consuming systems (SIEM, SOAR, TIP) can ingest the bundle and create corresponding detection rules or enrichment data
- Run `stix2-validator` CLI tool against exported bundles: `stix2_validator emotet_campaign_bundle.json`
