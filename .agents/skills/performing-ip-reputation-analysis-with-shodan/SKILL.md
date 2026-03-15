---
name: performing-ip-reputation-analysis-with-shodan
description: Analyze IP address reputation using the Shodan API to identify open ports, running services, known vulnerabilities, and hosting context for threat intelligence enrichment and incident triage.
domain: cybersecurity
subdomain: threat-intelligence
tags: [shodan, ip-reputation, enrichment, threat-intelligence, reconnaissance, vulnerability, api, internet-scanning]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing IP Reputation Analysis with Shodan

## Overview

Shodan is the world's first search engine for internet-connected devices, continuously scanning the IPv4 and IPv6 address space to catalog open ports, running services, SSL certificates, and known vulnerabilities. This skill covers using the Shodan API and InternetDB free API to enrich IP addresses from security alerts, assess threat levels based on exposed services and vulnerabilities, identify hosting infrastructure patterns, and integrate IP reputation data into SOC triage and threat intelligence workflows.

## Prerequisites

- Python 3.9+ with `shodan` library (`pip install shodan`)
- Shodan API key (free tier: limited queries; paid plans for higher limits and streaming)
- Understanding of TCP/UDP ports, common services, and CVE identifiers
- Familiarity with ASN, CIDR notation, and IP geolocation concepts
- Network security knowledge for interpreting scan results

## Key Concepts

### Shodan Data Model

Each IP record in Shodan contains: open ports and protocols, banner data (service responses), SSL/TLS certificate details, known CVE vulnerabilities, hostname(s) and reverse DNS, ASN and ISP information, geographic location, operating system fingerprint, and historical scan data showing changes over time.

### InternetDB API

Shodan's free InternetDB API (internetdb.shodan.io) provides quick IP lookups without authentication, returning open ports, hostnames, tags, CPEs, and known vulnerabilities. This is useful for high-volume enrichment where the full Shodan API would hit rate limits.

### Reputation Scoring

IP reputation is assessed by combining: number and type of open ports (unusual ports indicate compromise), vulnerable services (unpatched software with known CVEs), hosting type (residential, cloud, VPN/proxy, bulletproof hosting), historical activity (past associations with malware, scanning, spam), and geographic context (countries known for specific threat activity).

## Practical Steps

### Step 1: Basic IP Enrichment with Shodan API

```python
import shodan
import json
from datetime import datetime

class ShodanEnricher:
    def __init__(self, api_key):
        self.api = shodan.Shodan(api_key)
        self.info = self.api.info()
        print(f"[+] Shodan API initialized. Credits: {self.info.get('scan_credits', 0)}")

    def enrich_ip(self, ip_address):
        """Full enrichment of an IP address via Shodan."""
        try:
            host = self.api.host(ip_address)
            enrichment = {
                "ip": ip_address,
                "organization": host.get("org", ""),
                "asn": host.get("asn", ""),
                "isp": host.get("isp", ""),
                "country": host.get("country_name", ""),
                "country_code": host.get("country_code", ""),
                "city": host.get("city", ""),
                "latitude": host.get("latitude"),
                "longitude": host.get("longitude"),
                "os": host.get("os", ""),
                "ports": host.get("ports", []),
                "hostnames": host.get("hostnames", []),
                "domains": host.get("domains", []),
                "vulns": host.get("vulns", []),
                "tags": host.get("tags", []),
                "last_update": host.get("last_update", ""),
                "services": [],
            }

            for service in host.get("data", []):
                svc = {
                    "port": service.get("port", 0),
                    "transport": service.get("transport", "tcp"),
                    "product": service.get("product", ""),
                    "version": service.get("version", ""),
                    "module": service.get("_shodan", {}).get("module", ""),
                    "banner": service.get("data", "")[:200],
                }
                if "ssl" in service:
                    svc["ssl_subject"] = service["ssl"].get("cert", {}).get("subject", {})
                    svc["ssl_issuer"] = service["ssl"].get("cert", {}).get("issuer", {})
                    svc["ssl_expires"] = service["ssl"].get("cert", {}).get("expires", "")
                enrichment["services"].append(svc)

            # Calculate reputation score
            enrichment["reputation"] = self._calculate_reputation(enrichment)
            print(f"[+] {ip_address}: {len(enrichment['ports'])} ports, "
                  f"{len(enrichment['vulns'])} vulns, "
                  f"reputation: {enrichment['reputation']['level']}")
            return enrichment

        except shodan.APIError as e:
            print(f"[-] Shodan error for {ip_address}: {e}")
            return None

    def _calculate_reputation(self, data):
        """Calculate IP reputation score based on Shodan data."""
        score = 0
        factors = []

        # Vulnerability assessment
        vuln_count = len(data.get("vulns", []))
        if vuln_count > 10:
            score += 40
            factors.append(f"{vuln_count} known vulnerabilities")
        elif vuln_count > 5:
            score += 25
            factors.append(f"{vuln_count} known vulnerabilities")
        elif vuln_count > 0:
            score += 10
            factors.append(f"{vuln_count} known vulnerabilities")

        # Suspicious port analysis
        suspicious_ports = {4444, 5555, 6666, 8888, 9090, 1234, 31337,
                           6667, 6697, 8080, 8443, 3128, 1080}
        open_ports = set(data.get("ports", []))
        sus_found = open_ports.intersection(suspicious_ports)
        if sus_found:
            score += 15
            factors.append(f"suspicious ports: {sus_found}")

        # Tag-based assessment
        malicious_tags = {"self-signed", "cloud", "vpn", "proxy", "tor"}
        tags = set(data.get("tags", []))
        mal_tags = tags.intersection(malicious_tags)
        if mal_tags:
            score += 10
            factors.append(f"tags: {mal_tags}")

        # Too many open ports
        port_count = len(data.get("ports", []))
        if port_count > 20:
            score += 15
            factors.append(f"excessive open ports ({port_count})")

        level = (
            "critical" if score >= 50
            else "high" if score >= 35
            else "medium" if score >= 15
            else "low"
        )

        return {"score": score, "level": level, "factors": factors}

    def enrich_ip_free(self, ip_address):
        """Quick IP enrichment using free InternetDB API."""
        import requests
        resp = requests.get(f"https://internetdb.shodan.io/{ip_address}", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            print(f"[+] InternetDB: {ip_address} -> "
                  f"{len(data.get('ports', []))} ports, "
                  f"{len(data.get('vulns', []))} vulns")
            return data
        return None

enricher = ShodanEnricher("YOUR_SHODAN_API_KEY")
result = enricher.enrich_ip("8.8.8.8")
print(json.dumps(result, indent=2, default=str))
```

### Step 2: Batch IP Reputation Check

```python
import time

def batch_ip_reputation(enricher, ip_list, output_file="ip_reputation.json"):
    """Check reputation for a list of IP addresses."""
    results = []
    for i, ip in enumerate(ip_list):
        result = enricher.enrich_ip(ip)
        if result:
            results.append(result)
        if (i + 1) % 10 == 0:
            print(f"  [{i+1}/{len(ip_list)}] Processed")
            time.sleep(1)  # Rate limiting

    # Sort by reputation score (highest risk first)
    results.sort(key=lambda x: x.get("reputation", {}).get("score", 0), reverse=True)

    with open(output_file, "w") as f:
        json.dump(results, f, indent=2, default=str)

    # Summary
    levels = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in results:
        level = r.get("reputation", {}).get("level", "low")
        levels[level] += 1

    print(f"\n=== Batch Reputation Summary ===")
    print(f"Total IPs: {len(results)}")
    for level, count in levels.items():
        print(f"  {level.upper()}: {count}")

    return results

suspicious_ips = ["203.0.113.1", "198.51.100.5", "192.0.2.100"]
results = batch_ip_reputation(enricher, suspicious_ips)
```

### Step 3: Infrastructure Correlation

```python
def correlate_infrastructure(enricher, ip_address):
    """Find related infrastructure based on shared attributes."""
    host_data = enricher.enrich_ip(ip_address)
    if not host_data:
        return {}

    correlations = {
        "same_org": [],
        "same_asn": [],
        "shared_ssl": [],
    }

    # Search for same organization
    org = host_data.get("organization", "")
    if org:
        try:
            results = enricher.api.search(f'org:"{org}"', limit=20)
            for match in results.get("matches", []):
                correlations["same_org"].append({
                    "ip": match.get("ip_str", ""),
                    "port": match.get("port", 0),
                    "product": match.get("product", ""),
                })
        except shodan.APIError:
            pass

    # Search for same SSL certificate
    for service in host_data.get("services", []):
        ssl_subject = service.get("ssl_subject", {})
        if ssl_subject:
            cn = ssl_subject.get("CN", "")
            if cn:
                try:
                    results = enricher.api.search(f'ssl.cert.subject.CN:"{cn}"', limit=20)
                    for match in results.get("matches", []):
                        correlations["shared_ssl"].append({
                            "ip": match.get("ip_str", ""),
                            "cn": cn,
                        })
                except shodan.APIError:
                    pass

    print(f"[+] Infrastructure correlations for {ip_address}:")
    print(f"  Same org: {len(correlations['same_org'])} hosts")
    print(f"  Shared SSL: {len(correlations['shared_ssl'])} hosts")
    return correlations
```

## Validation Criteria

- Shodan API queried successfully with proper authentication
- IP enrichment returns ports, services, vulnerabilities, and geolocation
- Reputation scoring classifies IPs by threat level
- Batch enrichment handles rate limiting correctly
- Infrastructure correlation identifies related hosts
- InternetDB free API used for high-volume lookups

## References

- [Shodan Developer API](https://developer.shodan.io/api)
- [Shodan InternetDB API](https://internetdb.shodan.io/)
- [Shodan Python Library](https://github.com/achillean/shodan-python)
- [Query.ai: Leveraging Shodan for Security Research](https://www.query.ai/resources/blogs/leveraging-shodan-for-security-research/)
- [Torq: Shodan IP Enrichment Workflow](https://kb.torq.io/en/articles/9350284-shodan-ip-address-enrichment-with-cache-workflow-template)
- [Recorded Future: Shodan Integration](https://support.recordedfuture.com/hc/en-us/articles/115001403928-Shodan)
