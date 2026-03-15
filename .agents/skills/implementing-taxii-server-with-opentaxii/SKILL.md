---
name: implementing-taxii-server-with-opentaxii
description: Deploy and configure an OpenTAXII server to share and consume STIX-formatted cyber threat intelligence using the TAXII 2.1 protocol for automated indicator exchange between organizations.
domain: cybersecurity
subdomain: threat-intelligence
tags: [taxii, stix, opentaxii, threat-sharing, cti, indicator-exchange, taxii-server, automation]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Implementing TAXII Server with OpenTAXII

## Overview

TAXII (Trusted Automated eXchange of Intelligence Information) is an OASIS standard protocol for exchanging cyber threat intelligence over HTTPS. OpenTAXII is an open-source TAXII server implementation by EclecticIQ that supports TAXII 1.x, while the OASIS cti-taxii-server provides a TAXII 2.1 reference implementation. This skill covers deploying a TAXII server, configuring collections for threat intelligence feeds, publishing STIX 2.1 bundles, and integrating with SIEM/SOAR platforms for automated indicator ingestion.

## Prerequisites

- Python 3.9+ with `medallion`, `stix2`, `taxii2-client`, `opentaxii`, `cabby` libraries
- Docker and Docker Compose for containerized deployment
- Understanding of STIX 2.1 objects (Indicator, Malware, Attack Pattern, Relationship)
- Familiarity with REST APIs and HTTPS configuration
- TLS certificates for production deployment

## Key Concepts

### TAXII 2.1 Architecture

TAXII 2.1 defines three services: Discovery (find available API roots), API Root (entry point for collections), and Collections (repositories of CTI objects). Collections support two access models: the Collection endpoint allows consumers to poll for objects, and the Status endpoint tracks the result of add operations. TAXII uses HTTP content negotiation with `application/taxii+json;version=2.1`.

### Sharing Models

TAXII supports hub-and-spoke (central server distributes to consumers), peer-to-peer (bidirectional sharing between partners), and source-subscriber (producer publishes, consumers subscribe) models. Each collection can have read-only, write-only, or read-write access controls.

### STIX 2.1 Content

TAXII transports STIX 2.1 bundles containing Structured Threat Information objects: Indicators (detection patterns), Observed Data, Malware, Attack Patterns, Threat Actors, Intrusion Sets, Campaigns, Relationships, and Sightings. Each object has a unique STIX ID, creation/modification timestamps, and optional TLP marking definitions.

## Practical Steps

### Step 1: Deploy TAXII 2.1 Server with Medallion

```python
# Install medallion (OASIS reference implementation)
# pip install medallion

# medallion_config.json
import json

config = {
    "backend": {
        "module_class": "MemoryBackend",
        "filename": "taxii_data.json"
    },
    "users": {
        "admin": "admin_password_change_me",
        "analyst": "analyst_password_change_me",
        "readonly": "readonly_password_change_me"
    },
    "taxii": {
        "max_content_length": 10485760
    }
}

# Create initial data store
taxii_data = {
    "discovery": {
        "title": "Threat Intelligence TAXII Server",
        "description": "TAXII 2.1 server for sharing CTI indicators",
        "contact": "soc@organization.com",
        "default": "https://taxii.organization.com/api/",
        "api_roots": ["https://taxii.organization.com/api/"]
    },
    "api_roots": {
        "api": {
            "title": "Threat Intelligence API Root",
            "description": "Primary API root for threat intelligence sharing",
            "versions": ["application/taxii+json;version=2.1"],
            "max_content_length": 10485760,
            "collections": {
                "malware-iocs": {
                    "id": "91a7b528-80eb-42ed-a74d-c6fbd5a26116",
                    "title": "Malware IOCs",
                    "description": "Indicators of compromise from malware analysis",
                    "can_read": True,
                    "can_write": True,
                    "media_types": ["application/stix+json;version=2.1"]
                },
                "apt-intelligence": {
                    "id": "52892447-4d7e-4f70-b94a-5460e242dd23",
                    "title": "APT Intelligence",
                    "description": "Advanced persistent threat group intelligence",
                    "can_read": True,
                    "can_write": True,
                    "media_types": ["application/stix+json;version=2.1"]
                },
                "phishing-indicators": {
                    "id": "64993447-4d7e-4f70-b94a-5460e242ee34",
                    "title": "Phishing Indicators",
                    "description": "Phishing URLs, domains, and email indicators",
                    "can_read": True,
                    "can_write": True,
                    "media_types": ["application/stix+json;version=2.1"]
                }
            }
        }
    }
}

with open("medallion_config.json", "w") as f:
    json.dump(config, f, indent=2)
with open("taxii_data.json", "w") as f:
    json.dump(taxii_data, f, indent=2)
print("[+] TAXII server configuration created")
```

### Step 2: Docker Deployment

```yaml
# docker-compose.yml
version: '3.8'
services:
  taxii-server:
    image: python:3.11-slim
    container_name: taxii-server
    working_dir: /app
    volumes:
      - ./medallion_config.json:/app/medallion_config.json
      - ./taxii_data.json:/app/taxii_data.json
      - ./certs:/app/certs
    ports:
      - "6100:6100"
    command: >
      bash -c "pip install medallion &&
      medallion --host 0.0.0.0 --port 6100
      --config /app/medallion_config.json"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:6100/taxii2/"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### Step 3: Publish STIX 2.1 Objects to Collections

```python
from stix2 import Indicator, Malware, Relationship, Bundle, TLP_WHITE
from taxii2client.v21 import Server, Collection, as_pages
import json
from datetime import datetime

class TAXIIPublisher:
    def __init__(self, server_url, username, password):
        self.server = Server(
            server_url,
            user=username,
            password=password,
        )

    def list_collections(self):
        """List all available collections."""
        api_root = self.server.api_roots[0]
        for collection in api_root.collections:
            print(f"  [{collection.id}] {collection.title} "
                  f"(read={collection.can_read}, write={collection.can_write})")
        return api_root.collections

    def publish_indicators(self, collection_id, indicators):
        """Publish STIX indicators to a TAXII collection."""
        api_root = self.server.api_roots[0]
        collection = Collection(
            f"{api_root.url}collections/{collection_id}/",
            user=self.server._user,
            password=self.server._password,
        )
        bundle = Bundle(objects=indicators)
        response = collection.add_objects(bundle.serialize())
        print(f"[+] Published {len(indicators)} objects to {collection_id}")
        print(f"    Status: {response.status}")
        return response

    def create_malware_indicators(self):
        """Create sample STIX malware indicators."""
        malware = Malware(
            name="SUNBURST",
            description="Backdoor used in SolarWinds supply chain attack (2020). "
                        "Trojanized SolarWinds.Orion.Core.BusinessLayer.dll module.",
            malware_types=["backdoor", "trojan"],
            is_family=True,
            object_marking_refs=[TLP_WHITE],
        )

        indicator_hash = Indicator(
            name="SUNBURST SHA-256 Hash",
            description="SHA-256 hash of trojanized SolarWinds Orion DLL",
            pattern="[file:hashes.'SHA-256' = "
                    "'32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77']",
            pattern_type="stix",
            valid_from=datetime(2020, 12, 13),
            indicator_types=["malicious-activity"],
            object_marking_refs=[TLP_WHITE],
        )

        indicator_domain = Indicator(
            name="SUNBURST C2 Domain Pattern",
            description="DGA domain pattern used by SUNBURST for C2",
            pattern="[domain-name:value MATCHES "
                    "'^[a-z0-9]{4,}\\.appsync-api\\..*\\.avsvmcloud\\.com$']",
            pattern_type="stix",
            valid_from=datetime(2020, 12, 13),
            indicator_types=["malicious-activity"],
            object_marking_refs=[TLP_WHITE],
        )

        rel = Relationship(
            relationship_type="indicates",
            source_ref=indicator_hash.id,
            target_ref=malware.id,
        )

        return [malware, indicator_hash, indicator_domain, rel]

publisher = TAXIIPublisher(
    "https://taxii.organization.com/taxii2/",
    "admin", "admin_password_change_me"
)
collections = publisher.list_collections()
indicators = publisher.create_malware_indicators()
publisher.publish_indicators("91a7b528-80eb-42ed-a74d-c6fbd5a26116", indicators)
```

### Step 4: Consume Intelligence from TAXII Collections

```python
from taxii2client.v21 import Server, Collection, as_pages
import json

class TAXIIConsumer:
    def __init__(self, server_url, username, password):
        self.server = Server(server_url, user=username, password=password)

    def poll_collection(self, collection_id, added_after=None):
        """Poll a collection for new STIX objects."""
        api_root = self.server.api_roots[0]
        collection = Collection(
            f"{api_root.url}collections/{collection_id}/",
            user=self.server._user,
            password=self.server._password,
        )

        kwargs = {}
        if added_after:
            kwargs["added_after"] = added_after

        all_objects = []
        for bundle in as_pages(collection.get_objects, per_request=50, **kwargs):
            objects = json.loads(bundle).get("objects", [])
            all_objects.extend(objects)

        indicators = [o for o in all_objects if o.get("type") == "indicator"]
        malware = [o for o in all_objects if o.get("type") == "malware"]
        relationships = [o for o in all_objects if o.get("type") == "relationship"]

        print(f"[+] Polled {len(all_objects)} objects: "
              f"{len(indicators)} indicators, {len(malware)} malware, "
              f"{len(relationships)} relationships")
        return all_objects

    def extract_iocs_for_siem(self, stix_objects):
        """Extract IOCs from STIX objects for SIEM ingestion."""
        iocs = []
        for obj in stix_objects:
            if obj.get("type") == "indicator":
                pattern = obj.get("pattern", "")
                iocs.append({
                    "id": obj.get("id"),
                    "name": obj.get("name", ""),
                    "pattern": pattern,
                    "valid_from": obj.get("valid_from", ""),
                    "indicator_types": obj.get("indicator_types", []),
                    "confidence": obj.get("confidence", 0),
                })
        return iocs

consumer = TAXIIConsumer(
    "https://taxii.organization.com/taxii2/",
    "analyst", "analyst_password_change_me"
)
objects = consumer.poll_collection("91a7b528-80eb-42ed-a74d-c6fbd5a26116")
iocs = consumer.extract_iocs_for_siem(objects)
```

### Step 5: Integrate with SIEM/SOAR

```python
import requests

def push_to_splunk(iocs, splunk_url, hec_token):
    """Push extracted IOCs to Splunk via HEC."""
    headers = {"Authorization": f"Splunk {hec_token}"}
    for ioc in iocs:
        event = {
            "event": ioc,
            "sourcetype": "stix:indicator",
            "source": "taxii-server",
            "index": "threat_intel",
        }
        resp = requests.post(
            f"{splunk_url}/services/collector/event",
            headers=headers,
            json=event,
            verify=False,
        )
        if resp.status_code != 200:
            print(f"[-] Splunk HEC error: {resp.text}")
    print(f"[+] Pushed {len(iocs)} IOCs to Splunk")

def push_to_elasticsearch(iocs, es_url, index="threat-intel"):
    """Push IOCs to Elasticsearch."""
    for ioc in iocs:
        resp = requests.post(
            f"{es_url}/{index}/_doc",
            json=ioc,
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code not in (200, 201):
            print(f"[-] ES error: {resp.text}")
    print(f"[+] Indexed {len(iocs)} IOCs in Elasticsearch")
```

## Validation Criteria

- TAXII 2.1 server deployed and accessible via HTTPS
- Collections created with appropriate read/write permissions
- STIX 2.1 bundles published successfully to collections
- Consumer can poll and retrieve objects with filtering
- IOCs extracted and forwarded to SIEM platform
- Authentication and authorization enforced correctly

## References

- [TAXII 2.1 Specification](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html)
- [OASIS CTI Documentation](https://oasis-open.github.io/cti-documentation/)
- [EclecticIQ OpenTAXII](https://www.eclecticiq.com/open-source)
- [cti-taxii-server (Medallion)](https://github.com/oasis-open/cti-taxii-server)
- [taxii2-client Python Library](https://github.com/oasis-open/cti-taxii-client)
- [Kraven Security: STIX/TAXII Complete Guide](https://kravensecurity.com/stix-and-taxii-a-full-guide/)
