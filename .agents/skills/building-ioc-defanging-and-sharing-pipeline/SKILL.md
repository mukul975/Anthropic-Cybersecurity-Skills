---
name: building-ioc-defanging-and-sharing-pipeline
description: Build an automated pipeline to defang indicators of compromise (URLs, IPs, domains, emails) for safe sharing and distribute them in STIX format through TAXII feeds and threat intelligence platforms.
domain: cybersecurity
subdomain: threat-intelligence
tags: [ioc, defanging, threat-sharing, stix, pipeline, indicator, automation, threat-intelligence]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Building IOC Defanging and Sharing Pipeline

## Overview

IOC defanging modifies potentially malicious indicators (URLs, IP addresses, domains, email addresses) to prevent accidental clicks or execution while preserving readability for analysis and sharing. This skill covers building an automated pipeline that ingests raw IOCs from multiple sources, normalizes and deduplicates them, applies defanging for safe human consumption, converts them to STIX 2.1 format for machine consumption, and distributes through TAXII servers, MISP instances, and email reports.

## Prerequisites

- Python 3.9+ with `defang`, `ioc-fanger`, `stix2`, `requests`, `validators` libraries
- MISP instance or TAXII server for automated sharing
- Understanding of IOC types: IPv4/IPv6, domains, URLs, email addresses, file hashes
- Familiarity with STIX 2.1 Indicator patterns and TLP marking definitions
- Access to threat intelligence feeds for IOC ingestion

## Key Concepts

### IOC Defanging Standards

Defanging replaces active protocol and domain components to prevent execution: `http://` becomes `hxxp://`, `https://` becomes `hxxps://`, dots in domains/IPs become `[.]`, `@` in emails becomes `[@]`. This is critical for sharing IOCs in reports, emails, Slack channels, and paste sites where auto-linking could trigger network connections to malicious infrastructure.

### IOC Normalization

Raw IOCs from different sources come in inconsistent formats. Normalization involves converting to lowercase, removing trailing slashes and whitespace, extracting domains from URLs, resolving URL encoding, validating format correctness, and deduplicating across sources.

### STIX 2.1 Indicator Patterns

STIX patterns express IOCs in a standardized format: `[ipv4-addr:value = '203.0.113.1']`, `[domain-name:value = 'malicious.example.com']`, `[url:value = 'http://evil.com/payload']`, `[file:hashes.'SHA-256' = 'abc123...']`. Each indicator includes valid_from, indicator_types, confidence, and optional TLP markings.

## Practical Steps

### Step 1: Build IOC Extraction and Normalization

```python
import re
import hashlib
from urllib.parse import urlparse, unquote
from datetime import datetime

class IOCExtractor:
    """Extract and normalize IOCs from text."""

    PATTERNS = {
        "ipv4": r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b',
        "domain": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        "url": r'https?://[^\s<>"{}|\\^`\[\]]+',
        "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "md5": r'\b[a-fA-F0-9]{32}\b',
        "sha1": r'\b[a-fA-F0-9]{40}\b',
        "sha256": r'\b[a-fA-F0-9]{64}\b',
    }

    WHITELIST_DOMAINS = {
        "google.com", "microsoft.com", "amazon.com", "github.com",
        "cloudflare.com", "akamai.com", "example.com",
    }

    def extract_from_text(self, text):
        """Extract all IOC types from free text."""
        # Refang any already-defanged indicators first
        text = self._refang(text)
        iocs = {"ipv4": set(), "domain": set(), "url": set(),
                "email": set(), "md5": set(), "sha1": set(), "sha256": set()}

        for ioc_type, pattern in self.PATTERNS.items():
            matches = re.findall(pattern, text)
            for match in matches:
                normalized = self._normalize(match, ioc_type)
                if normalized and not self._is_whitelisted(normalized, ioc_type):
                    iocs[ioc_type].add(normalized)

        # Remove domains that are part of URLs
        url_domains = set()
        for url in iocs["url"]:
            parsed = urlparse(url)
            url_domains.add(parsed.netloc)
        iocs["domain"] -= url_domains

        total = sum(len(v) for v in iocs.values())
        print(f"[+] Extracted {total} unique IOCs from text")
        return {k: sorted(v) for k, v in iocs.items()}

    def _refang(self, text):
        """Convert defanged indicators back to active form."""
        text = text.replace("hxxp://", "http://").replace("hxxps://", "https://")
        text = text.replace("[.]", ".").replace("[@]", "@")
        text = text.replace("[://]", "://").replace("(.)", ".")
        return text

    def _normalize(self, value, ioc_type):
        """Normalize an IOC value."""
        value = value.strip().lower()
        if ioc_type == "url":
            value = unquote(value).rstrip("/")
        elif ioc_type == "domain":
            value = value.rstrip(".")
        return value

    def _is_whitelisted(self, value, ioc_type):
        """Check if IOC is in whitelist."""
        if ioc_type == "domain":
            return value in self.WHITELIST_DOMAINS
        if ioc_type == "url":
            parsed = urlparse(value)
            return parsed.netloc in self.WHITELIST_DOMAINS
        return False

extractor = IOCExtractor()
sample_text = """
Malware C2: hxxps://evil-domain[.]com/beacon
Drops payload from 192.168.1.100 and contacts 10[.]0[.]0[.]1
SHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
Phishing email from attacker[@]phishing-domain[.]com
"""
iocs = extractor.extract_from_text(sample_text)
```

### Step 2: Defanging Engine

```python
class IOCDefanger:
    """Defang IOCs for safe sharing in reports and communications."""

    def defang_url(self, url):
        return url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")

    def defang_domain(self, domain):
        return domain.replace(".", "[.]")

    def defang_ip(self, ip):
        return ip.replace(".", "[.]")

    def defang_email(self, email):
        return email.replace("@", "[@]").replace(".", "[.]")

    def defang_all(self, iocs):
        """Defang all IOCs in a dictionary."""
        defanged = {}
        for ioc_type, values in iocs.items():
            if ioc_type == "url":
                defanged[ioc_type] = [self.defang_url(v) for v in values]
            elif ioc_type == "domain":
                defanged[ioc_type] = [self.defang_domain(v) for v in values]
            elif ioc_type == "ipv4":
                defanged[ioc_type] = [self.defang_ip(v) for v in values]
            elif ioc_type == "email":
                defanged[ioc_type] = [self.defang_email(v) for v in values]
            else:
                defanged[ioc_type] = values  # Hashes don't need defanging
        return defanged

    def generate_sharing_report(self, iocs, defanged, report_name="IOC Report"):
        """Generate a human-readable defanged IOC report."""
        report = f"# {report_name}\n"
        report += f"Generated: {datetime.now().isoformat()}\n\n"

        for ioc_type in ["url", "domain", "ipv4", "email", "sha256", "sha1", "md5"]:
            values = defanged.get(ioc_type, [])
            if values:
                report += f"## {ioc_type.upper()} ({len(values)})\n"
                for v in values:
                    report += f"- `{v}`\n"
                report += "\n"

        return report

defanger = IOCDefanger()
defanged = defanger.defang_all(iocs)
report = defanger.generate_sharing_report(iocs, defanged, "Malware Campaign IOCs")
print(report)
```

### Step 3: Convert to STIX 2.1 Format

```python
from stix2 import Indicator, Bundle, TLP_WHITE, TLP_GREEN, TLP_AMBER
from datetime import datetime

class STIXConverter:
    """Convert raw IOCs to STIX 2.1 Indicator objects."""

    TLP_MAP = {"white": TLP_WHITE, "green": TLP_GREEN, "amber": TLP_AMBER}

    def iocs_to_stix(self, iocs, tlp="green", confidence=75):
        """Convert IOC dictionary to STIX 2.1 bundle."""
        stix_objects = []
        marking = self.TLP_MAP.get(tlp, TLP_GREEN)

        for ip in iocs.get("ipv4", []):
            stix_objects.append(Indicator(
                name=f"Malicious IP: {ip}",
                pattern=f"[ipv4-addr:value = '{ip}']",
                pattern_type="stix",
                valid_from=datetime.now(),
                indicator_types=["malicious-activity"],
                confidence=confidence,
                object_marking_refs=[marking],
            ))

        for domain in iocs.get("domain", []):
            stix_objects.append(Indicator(
                name=f"Malicious Domain: {domain}",
                pattern=f"[domain-name:value = '{domain}']",
                pattern_type="stix",
                valid_from=datetime.now(),
                indicator_types=["malicious-activity"],
                confidence=confidence,
                object_marking_refs=[marking],
            ))

        for url in iocs.get("url", []):
            escaped = url.replace("'", "\\'")
            stix_objects.append(Indicator(
                name=f"Malicious URL: {url[:60]}",
                pattern=f"[url:value = '{escaped}']",
                pattern_type="stix",
                valid_from=datetime.now(),
                indicator_types=["malicious-activity"],
                confidence=confidence,
                object_marking_refs=[marking],
            ))

        for sha256 in iocs.get("sha256", []):
            stix_objects.append(Indicator(
                name=f"Malicious File Hash: {sha256[:16]}...",
                pattern=f"[file:hashes.'SHA-256' = '{sha256}']",
                pattern_type="stix",
                valid_from=datetime.now(),
                indicator_types=["malicious-activity"],
                confidence=confidence,
                object_marking_refs=[marking],
            ))

        bundle = Bundle(objects=stix_objects)
        print(f"[+] Created STIX bundle with {len(stix_objects)} indicators")
        return bundle

converter = STIXConverter()
stix_bundle = converter.iocs_to_stix(iocs, tlp="amber", confidence=80)
with open("iocs_stix_bundle.json", "w") as f:
    f.write(stix_bundle.serialize(pretty=True))
```

### Step 4: Distribute Through MISP and TAXII

```python
import requests
import json

class IOCDistributor:
    """Distribute IOCs through various channels."""

    def push_to_misp(self, iocs, misp_url, misp_key, event_info):
        """Push IOCs to MISP as a new event."""
        headers = {
            "Authorization": misp_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        event = {
            "Event": {
                "info": event_info,
                "distribution": "1",  # This community only
                "threat_level_id": "2",  # Medium
                "analysis": "2",  # Completed
                "Attribute": [],
            }
        }

        type_mapping = {
            "ipv4": "ip-dst",
            "domain": "domain",
            "url": "url",
            "email": "email-src",
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
        }

        for ioc_type, values in iocs.items():
            misp_type = type_mapping.get(ioc_type)
            if misp_type:
                for value in values:
                    event["Event"]["Attribute"].append({
                        "type": misp_type,
                        "value": value,
                        "category": "Network activity" if ioc_type in ("ipv4", "domain", "url") else "Payload delivery",
                        "to_ids": True,
                    })

        resp = requests.post(
            f"{misp_url}/events",
            headers=headers,
            json=event,
            verify=False,
        )
        if resp.status_code == 200:
            event_id = resp.json().get("Event", {}).get("id", "")
            print(f"[+] MISP event created: {event_id}")
            return event_id
        else:
            print(f"[-] MISP error: {resp.status_code} - {resp.text[:200]}")
            return None

    def push_to_taxii(self, stix_bundle, taxii_url, collection_id, username, password):
        """Push STIX bundle to TAXII 2.1 collection."""
        from taxii2client.v21 import Collection
        collection = Collection(
            f"{taxii_url}/collections/{collection_id}/",
            user=username, password=password,
        )
        response = collection.add_objects(stix_bundle.serialize())
        print(f"[+] TAXII: Published bundle, status: {response.status}")
        return response

distributor = IOCDistributor()
distributor.push_to_misp(
    iocs,
    misp_url="https://misp.organization.com",
    misp_key="YOUR_MISP_API_KEY",
    event_info="Malware Campaign IOCs - 2025",
)
```

## Validation Criteria

- IOCs extracted correctly from free text with refanging support
- Defanging produces safe, non-clickable indicators
- STIX 2.1 bundle contains valid indicator patterns
- IOCs distributed to MISP and TAXII successfully
- Deduplication prevents duplicate indicators
- Whitelisting prevents false positives on known-good domains

## References

- [CISA: Cybersecurity Automation and Threat Intelligence Sharing](https://www.cisa.gov/sites/default/files/publications/Operational%20Value%20of%20IOCs_508c.pdf)
- [Defang Python Library](https://pypi.org/project/defang/)
- [ioc-fanger](https://pypi.org/project/ioc-fanger/)
- [STIX 2.1 Indicator Specification](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html)
- [Grokipedia: Defanging](https://grokipedia.com/page/defanging)
- [Hunt.io: Best IOC Feeds](https://hunt.io/glossary/best-ioc-feeds)
