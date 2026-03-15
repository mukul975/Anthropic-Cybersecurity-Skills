---
name: building-threat-feed-aggregation-with-misp
description: Deploy MISP (Malware Information Sharing Platform) to aggregate, correlate, and distribute threat intelligence feeds from multiple sources for centralized IOC management and automated SIEM integration.
domain: cybersecurity
subdomain: threat-intelligence
tags: [misp, threat-feed, aggregation, indicator, sharing, correlation, siem-integration, threat-intelligence]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Building Threat Feed Aggregation with MISP

## Overview

MISP is the leading open-source threat intelligence platform for collecting, storing, distributing, and sharing cybersecurity indicators and threat intelligence. It aggregates feeds from OSINT sources, commercial providers, and sharing communities into a unified platform with automatic correlation, STIX/TAXII export, and direct integration with SIEMs and security tools. This skill covers deploying MISP via Docker, configuring feeds from sources like abuse.ch, AlienVault OTX, and CIRCL, setting up automated feed synchronization, and integrating with Splunk, Elasticsearch, and SOAR platforms.

## Prerequisites

- Docker and Docker Compose for deployment
- Python 3.9+ with `pymisp` library for API interaction
- Linux server with 8GB+ RAM for production deployment
- Understanding of IOC types and threat intelligence lifecycle
- Network access to external feed URLs

## Key Concepts

### MISP Architecture

MISP stores threat intelligence as Events containing Attributes (IOCs) organized by type and category. Events can have Tags (MITRE ATT&CK, TLP marking, sector tags), Galaxies (threat actor profiles, malware families, attack patterns), and Objects (structured groupings of related attributes). Events are correlated automatically across the instance.

### Feed Types

MISP supports three feed formats: MISP format (native JSON events), CSV (comma-separated IOCs), and freetext (unstructured text with automatic IOC extraction). Feeds can be remote (fetched from URLs) or local (uploaded files). MISP ships with 80+ default OSINT feeds including abuse.ch URLhaus, Botvrij, CIRCL OSINT, and malware traffic analysis.

### Sharing and Synchronization

MISP instances can synchronize with other MISP instances via push/pull mechanisms. Sharing groups control distribution (organization only, this community, connected communities, all communities). The TAXII server module enables integration with STIX/TAXII consumers.

## Practical Steps

### Step 1: Deploy MISP with Docker

```yaml
# docker-compose.yml for MISP deployment
version: '3.8'
services:
  misp:
    image: coolacid/misp-docker:core-latest
    container_name: misp
    restart: unless-stopped
    ports:
      - "443:443"
      - "80:80"
    environment:
      - MYSQL_HOST=misp-db
      - MYSQL_DATABASE=misp
      - MYSQL_USER=misp
      - MYSQL_PASSWORD=misp_db_password_change_me
      - MISP_ADMIN_EMAIL=admin@organization.com
      - MISP_ADMIN_PASSPHRASE=admin_password_change_me
      - MISP_BASEURL=https://misp.organization.com
      - POSTFIX_RELAY_HOST=smtp.organization.com
      - TIMEZONE=UTC
    volumes:
      - misp-data:/var/www/MISP/app/files
      - misp-config:/var/www/MISP/app/Config
    depends_on:
      - misp-db
      - misp-redis

  misp-db:
    image: mysql:8.0
    container_name: misp-db
    restart: unless-stopped
    environment:
      - MYSQL_DATABASE=misp
      - MYSQL_USER=misp
      - MYSQL_PASSWORD=misp_db_password_change_me
      - MYSQL_ROOT_PASSWORD=root_password_change_me
    volumes:
      - misp-db-data:/var/lib/mysql

  misp-redis:
    image: redis:7
    container_name: misp-redis
    restart: unless-stopped

volumes:
  misp-data:
  misp-config:
  misp-db-data:
```

### Step 2: Configure Feeds via PyMISP API

```python
from pymisp import PyMISP, MISPFeed
import json

class MISPFeedManager:
    def __init__(self, misp_url, misp_key, verify_ssl=False):
        self.misp = PyMISP(misp_url, misp_key, verify_ssl)
        print(f"[+] Connected to MISP: {misp_url}")

    def list_feeds(self):
        """List all configured feeds."""
        feeds = self.misp.feeds()
        enabled = [f for f in feeds if f.get("Feed", {}).get("enabled")]
        disabled = [f for f in feeds if not f.get("Feed", {}).get("enabled")]
        print(f"[+] Feeds: {len(enabled)} enabled, {len(disabled)} disabled")
        return feeds

    def enable_default_feeds(self):
        """Enable recommended default OSINT feeds."""
        recommended_feeds = [
            "CIRCL OSINT Feed",
            "Botvrij.eu - Indicators of Compromise",
            "abuse.ch URLhaus Host file",
            "abuse.ch Feodo Tracker",
            "abuse.ch SSL Blacklist",
            "malwaredomainlist",
            "CyberCure - IP Feed",
        ]

        feeds = self.misp.feeds()
        enabled_count = 0
        for feed in feeds:
            feed_data = feed.get("Feed", {})
            if feed_data.get("name") in recommended_feeds:
                if not feed_data.get("enabled"):
                    self.misp.enable_feed(feed_data["id"])
                    self.misp.enable_feed_cache(feed_data["id"])
                    enabled_count += 1
                    print(f"  [+] Enabled: {feed_data['name']}")

        print(f"[+] Enabled {enabled_count} feeds")

    def add_custom_feed(self, name, url, provider, feed_format="csv",
                        input_source="network", enabled=True):
        """Add a custom threat intelligence feed."""
        feed = MISPFeed()
        feed.name = name
        feed.provider = provider
        feed.url = url
        feed.source_format = feed_format
        feed.input_source = input_source
        feed.enabled = enabled
        feed.caching_enabled = True
        feed.publish = False
        feed.distribution = "3"  # All communities

        result = self.misp.add_feed(feed)
        if "Feed" in result:
            feed_id = result["Feed"]["id"]
            print(f"[+] Added feed: {name} (ID: {feed_id})")
            return feed_id
        else:
            print(f"[-] Error adding feed: {result}")
            return None

    def fetch_all_feeds(self):
        """Trigger fetch for all enabled feeds."""
        feeds = self.misp.feeds()
        for feed in feeds:
            feed_data = feed.get("Feed", {})
            if feed_data.get("enabled"):
                self.misp.fetch_feed(feed_data["id"])
                print(f"  [*] Fetching: {feed_data['name']}")
        print("[+] Feed fetch triggered for all enabled feeds")

manager = MISPFeedManager(
    "https://misp.organization.com",
    "YOUR_MISP_API_KEY",
)
manager.enable_default_feeds()
manager.add_custom_feed(
    name="Abuse.ch MalwareBazaar Recent",
    url="https://bazaar.abuse.ch/export/csv/recent/",
    provider="abuse.ch",
    feed_format="csv",
)
manager.fetch_all_feeds()
```

### Step 3: Search and Correlate Indicators

```python
def search_indicators(misp, value=None, type_attribute=None, tags=None, last_days=30):
    """Search MISP for indicators with correlation."""
    from datetime import datetime, timedelta
    date_from = (datetime.now() - timedelta(days=last_days)).strftime("%Y-%m-%d")

    search_params = {
        "date_from": date_from,
        "published": True,
        "enforceWarninglist": True,
    }
    if value:
        search_params["value"] = value
    if type_attribute:
        search_params["type_attribute"] = type_attribute
    if tags:
        search_params["tags"] = tags

    results = misp.search("attributes", **search_params)
    attributes = results.get("Attribute", [])
    print(f"[+] Search returned {len(attributes)} attributes")

    # Group by event for context
    events = {}
    for attr in attributes:
        event_id = attr.get("event_id", "")
        if event_id not in events:
            events[event_id] = {"attributes": [], "tags": set()}
        events[event_id]["attributes"].append({
            "type": attr.get("type", ""),
            "value": attr.get("value", ""),
            "category": attr.get("category", ""),
            "timestamp": attr.get("timestamp", ""),
        })
        for tag in attr.get("Tag", []):
            events[event_id]["tags"].add(tag.get("name", ""))

    return {"attributes": attributes, "events": events}

# Search for specific IOC
misp = manager.misp
results = search_indicators(misp, value="203.0.113.1")
results_by_type = search_indicators(misp, type_attribute="ip-dst", last_days=7)
results_by_tag = search_indicators(misp, tags=["tlp:white", "type:OSINT"])
```

### Step 4: Export to SIEM (Splunk / Elasticsearch)

```python
import requests
from datetime import datetime, timedelta

class MISPSIEMExporter:
    def __init__(self, misp_client):
        self.misp = misp_client

    def export_to_splunk(self, splunk_url, hec_token, days=7):
        """Export recent MISP indicators to Splunk via HEC."""
        date_from = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        results = self.misp.search("attributes", date_from=date_from,
                                    published=True, enforceWarninglist=True)
        attributes = results.get("Attribute", [])

        headers = {"Authorization": f"Splunk {hec_token}"}
        exported = 0
        for attr in attributes:
            event = {
                "event": {
                    "ioc_type": attr.get("type", ""),
                    "ioc_value": attr.get("value", ""),
                    "category": attr.get("category", ""),
                    "event_id": attr.get("event_id", ""),
                    "timestamp": attr.get("timestamp", ""),
                    "tags": [t.get("name", "") for t in attr.get("Tag", [])],
                },
                "sourcetype": "misp:attribute",
                "source": "misp",
                "index": "threat_intel",
            }
            resp = requests.post(
                f"{splunk_url}/services/collector/event",
                headers=headers, json=event, verify=False,
            )
            if resp.status_code == 200:
                exported += 1

        print(f"[+] Exported {exported}/{len(attributes)} indicators to Splunk")

    def export_ioc_list(self, output_file, ioc_types=None, days=30):
        """Export flat IOC list for firewall/proxy blocklists."""
        ioc_types = ioc_types or ["ip-dst", "domain", "hostname", "url"]
        date_from = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")

        all_iocs = []
        for ioc_type in ioc_types:
            results = self.misp.search(
                "attributes", type_attribute=ioc_type,
                date_from=date_from, published=True,
                enforceWarninglist=True,
            )
            for attr in results.get("Attribute", []):
                all_iocs.append(attr.get("value", ""))

        unique_iocs = sorted(set(all_iocs))
        with open(output_file, "w") as f:
            for ioc in unique_iocs:
                f.write(f"{ioc}\n")

        print(f"[+] Exported {len(unique_iocs)} unique IOCs to {output_file}")

exporter = MISPSIEMExporter(misp)
exporter.export_ioc_list("blocklist_ips.txt", ioc_types=["ip-dst"], days=7)
```

## Validation Criteria

- MISP deployed and accessible via web interface and API
- Default OSINT feeds enabled and fetching data
- Custom feeds added and ingesting indicators
- Indicators searchable with correlation across events
- IOCs exported to SIEM (Splunk/Elasticsearch) successfully
- Blocklists generated for firewall/proxy integration

## References

- [MISP Project](https://www.misp-project.org/)
- [MISP GitHub Repository](https://github.com/MISP/MISP)
- [MISP Default Feeds](https://www.misp-project.org/feeds/)
- [PyMISP Documentation](https://pymisp.readthedocs.io/)
- [Kraven Security: MISP Using Feeds](https://kravensecurity.com/threat-intelligence-with-misp-part-4-using-feeds/)
- [Cosive: What is MISP](https://www.cosive.com/blog/what-is-misp-the-ultimate-introduction)
