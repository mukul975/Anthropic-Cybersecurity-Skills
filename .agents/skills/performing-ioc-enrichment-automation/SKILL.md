---
name: performing-ioc-enrichment-automation
description: >
  Automates Indicator of Compromise (IOC) enrichment by orchestrating lookups across VirusTotal,
  AbuseIPDB, Shodan, MISP, and other intelligence sources to provide contextual scoring and
  disposition recommendations. Use when SOC analysts need rapid multi-source enrichment of IPs,
  domains, URLs, and file hashes during alert triage or incident investigation.
domain: cybersecurity
subdomain: soc-operations
tags: [soc, ioc, enrichment, automation, virustotal, abuseipdb, shodan, threat-intelligence]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing IOC Enrichment Automation

## When to Use

Use this skill when:
- SOC analysts need to quickly enrich IOCs from multiple sources during alert triage
- High alert volumes require automated enrichment to reduce manual lookup time
- Incident investigations need comprehensive IOC context for scope assessment
- SOAR playbooks require enrichment actions as part of automated triage workflows

**Do not use** for bulk blocking decisions without analyst review — enrichment provides context, not definitive malicious/benign determination.

## Prerequisites

- API keys: VirusTotal (free or premium), AbuseIPDB, Shodan, URLScan.io, GreyNoise
- Python 3.8+ with `requests`, `vt-py`, `shodan` libraries
- MISP instance or TIP for cross-referencing organizational intelligence
- SOAR platform (optional) for workflow integration
- Rate limit awareness: VT free (4 req/min), AbuseIPDB (1000/day), Shodan (1 req/sec)

## Workflow

### Step 1: Build Unified Enrichment Engine

Create a multi-source enrichment pipeline:

```python
import requests
import vt
import shodan
import time
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class EnrichmentResult:
    ioc_value: str
    ioc_type: str
    virustotal: dict = field(default_factory=dict)
    abuseipdb: dict = field(default_factory=dict)
    shodan_data: dict = field(default_factory=dict)
    greynoise: dict = field(default_factory=dict)
    urlscan: dict = field(default_factory=dict)
    misp_matches: list = field(default_factory=list)
    risk_score: float = 0.0
    disposition: str = "Unknown"

class IOCEnrichmentEngine:
    def __init__(self, config):
        self.vt_client = vt.Client(config["virustotal_key"])
        self.shodan_api = shodan.Shodan(config["shodan_key"])
        self.abuseipdb_key = config["abuseipdb_key"]
        self.greynoise_key = config["greynoise_key"]
        self.urlscan_key = config["urlscan_key"]

    def enrich_ip(self, ip_address):
        result = EnrichmentResult(ioc_value=ip_address, ioc_type="ip")

        # VirusTotal
        try:
            vt_obj = self.vt_client.get_object(f"/ip_addresses/{ip_address}")
            result.virustotal = {
                "malicious": vt_obj.last_analysis_stats.get("malicious", 0),
                "suspicious": vt_obj.last_analysis_stats.get("suspicious", 0),
                "total_engines": sum(vt_obj.last_analysis_stats.values()),
                "reputation": vt_obj.reputation,
                "country": getattr(vt_obj, "country", "Unknown"),
                "as_owner": getattr(vt_obj, "as_owner", "Unknown")
            }
        except Exception as e:
            result.virustotal = {"error": str(e)}

        # AbuseIPDB
        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                params={"ipAddress": ip_address, "maxAgeInDays": 90}
            )
            data = response.json()["data"]
            result.abuseipdb = {
                "confidence_score": data["abuseConfidenceScore"],
                "total_reports": data["totalReports"],
                "is_tor": data.get("isTor", False),
                "usage_type": data.get("usageType", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "domain": data.get("domain", "Unknown")
            }
        except Exception as e:
            result.abuseipdb = {"error": str(e)}

        # Shodan
        try:
            host = self.shodan_api.host(ip_address)
            result.shodan_data = {
                "ports": host.get("ports", []),
                "os": host.get("os", "Unknown"),
                "organization": host.get("org", "Unknown"),
                "isp": host.get("isp", "Unknown"),
                "vulns": host.get("vulns", []),
                "last_update": host.get("last_update", "Unknown")
            }
        except shodan.APIError:
            result.shodan_data = {"status": "Not found in Shodan"}

        # GreyNoise
        try:
            response = requests.get(
                f"https://api.greynoise.io/v3/community/{ip_address}",
                headers={"key": self.greynoise_key}
            )
            gn_data = response.json()
            result.greynoise = {
                "classification": gn_data.get("classification", "unknown"),
                "noise": gn_data.get("noise", False),
                "riot": gn_data.get("riot", False),
                "name": gn_data.get("name", "Unknown")
            }
        except Exception as e:
            result.greynoise = {"error": str(e)}

        # Calculate composite risk score
        result.risk_score = self._calculate_ip_risk(result)
        result.disposition = self._determine_disposition(result.risk_score)
        return result

    def enrich_domain(self, domain):
        result = EnrichmentResult(ioc_value=domain, ioc_type="domain")

        # VirusTotal
        try:
            vt_obj = self.vt_client.get_object(f"/domains/{domain}")
            result.virustotal = {
                "malicious": vt_obj.last_analysis_stats.get("malicious", 0),
                "suspicious": vt_obj.last_analysis_stats.get("suspicious", 0),
                "reputation": vt_obj.reputation,
                "creation_date": getattr(vt_obj, "creation_date", "Unknown"),
                "registrar": getattr(vt_obj, "registrar", "Unknown"),
                "categories": getattr(vt_obj, "categories", {})
            }
        except Exception as e:
            result.virustotal = {"error": str(e)}

        # URLScan.io
        try:
            response = requests.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{domain}",
                headers={"API-Key": self.urlscan_key}
            )
            scans = response.json().get("results", [])
            result.urlscan = {
                "total_scans": len(scans),
                "verdicts": [s.get("verdicts", {}).get("overall", {}).get("malicious", False)
                            for s in scans[:5]],
                "last_scan": scans[0]["task"]["time"] if scans else "Never scanned"
            }
        except Exception as e:
            result.urlscan = {"error": str(e)}

        result.risk_score = self._calculate_domain_risk(result)
        result.disposition = self._determine_disposition(result.risk_score)
        return result

    def enrich_hash(self, file_hash):
        result = EnrichmentResult(ioc_value=file_hash, ioc_type="hash")

        # VirusTotal
        try:
            vt_obj = self.vt_client.get_object(f"/files/{file_hash}")
            result.virustotal = {
                "malicious": vt_obj.last_analysis_stats.get("malicious", 0),
                "suspicious": vt_obj.last_analysis_stats.get("suspicious", 0),
                "undetected": vt_obj.last_analysis_stats.get("undetected", 0),
                "total_engines": sum(vt_obj.last_analysis_stats.values()),
                "type_description": getattr(vt_obj, "type_description", "Unknown"),
                "popular_threat_name": getattr(vt_obj, "popular_threat_classification", {}).get(
                    "suggested_threat_label", "Unknown"
                ),
                "sandbox_verdicts": getattr(vt_obj, "sandbox_verdicts", {}),
                "first_seen": getattr(vt_obj, "first_submission_date", "Unknown")
            }
        except vt.APIError:
            result.virustotal = {"status": "Not found in VirusTotal"}

        # MalwareBazaar
        try:
            response = requests.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": file_hash}
            )
            mb_data = response.json()
            if mb_data["query_status"] == "ok":
                entry = mb_data["data"][0]
                result.abuseipdb = {  # Reusing field for MalwareBazaar data
                    "malware_family": entry.get("signature", "Unknown"),
                    "tags": entry.get("tags", []),
                    "file_type": entry.get("file_type", "Unknown"),
                    "delivery_method": entry.get("delivery_method", "Unknown"),
                    "first_seen": entry.get("first_seen", "Unknown")
                }
        except Exception:
            pass

        result.risk_score = self._calculate_hash_risk(result)
        result.disposition = self._determine_disposition(result.risk_score)
        return result

    def _calculate_ip_risk(self, result):
        score = 0
        vt = result.virustotal
        abuse = result.abuseipdb
        gn = result.greynoise

        if isinstance(vt, dict) and "malicious" in vt:
            score += min(vt["malicious"] * 3, 30)
        if isinstance(abuse, dict) and "confidence_score" in abuse:
            score += abuse["confidence_score"] * 0.3
        if isinstance(gn, dict):
            if gn.get("classification") == "malicious":
                score += 20
            elif gn.get("riot"):
                score -= 20  # Known benign service
        return min(max(score, 0), 100)

    def _calculate_domain_risk(self, result):
        score = 0
        vt = result.virustotal
        if isinstance(vt, dict) and "malicious" in vt:
            score += min(vt["malicious"] * 4, 40)
            if vt.get("reputation", 0) < -5:
                score += 20
        return min(max(score, 0), 100)

    def _calculate_hash_risk(self, result):
        score = 0
        vt = result.virustotal
        if isinstance(vt, dict) and "malicious" in vt:
            total = vt.get("total_engines", 1)
            detection_rate = vt["malicious"] / total if total > 0 else 0
            score = detection_rate * 100
        return min(max(score, 0), 100)

    def _determine_disposition(self, risk_score):
        if risk_score >= 70:
            return "MALICIOUS — Block recommended"
        elif risk_score >= 40:
            return "SUSPICIOUS — Monitor and investigate"
        elif risk_score >= 10:
            return "LOW RISK — Likely benign, verify context"
        else:
            return "CLEAN — No indicators of malicious activity"

    def close(self):
        self.vt_client.close()
```

### Step 2: Batch Enrichment for Incident Investigation

```python
# Process multiple IOCs from an incident
iocs = [
    {"type": "ip", "value": "185.234.218.50"},
    {"type": "domain", "value": "evil-c2-server.com"},
    {"type": "hash", "value": "a1b2c3d4e5f6..."},
    {"type": "ip", "value": "45.33.32.156"},
]

config = {
    "virustotal_key": "YOUR_VT_KEY",
    "shodan_key": "YOUR_SHODAN_KEY",
    "abuseipdb_key": "YOUR_ABUSEIPDB_KEY",
    "greynoise_key": "YOUR_GREYNOISE_KEY",
    "urlscan_key": "YOUR_URLSCAN_KEY"
}

engine = IOCEnrichmentEngine(config)

results = []
for ioc in iocs:
    if ioc["type"] == "ip":
        result = engine.enrich_ip(ioc["value"])
    elif ioc["type"] == "domain":
        result = engine.enrich_domain(ioc["value"])
    elif ioc["type"] == "hash":
        result = engine.enrich_hash(ioc["value"])
    results.append(result)
    time.sleep(15)  # Rate limiting for free VT API

engine.close()

# Print summary
for r in results:
    print(f"{r.ioc_type}: {r.ioc_value}")
    print(f"  Risk Score: {r.risk_score}")
    print(f"  Disposition: {r.disposition}")
    print()
```

### Step 3: Integrate with Splunk for Automated Enrichment

Create a Splunk custom search command for inline enrichment:

```spl
index=notable sourcetype="stash"
| table src_ip, dest_ip, file_hash, url
| lookup threat_intel_ip_lookup ip AS src_ip OUTPUT vt_score, abuse_score, disposition
| lookup threat_intel_hash_lookup hash AS file_hash OUTPUT vt_detections, malware_family
| eval combined_risk = coalesce(vt_score, 0) + coalesce(abuse_score, 0)
| where combined_risk > 50
| sort - combined_risk
```

### Step 4: Generate Enrichment Report

```python
def generate_enrichment_report(results):
    report = []
    report.append("IOC ENRICHMENT REPORT")
    report.append("=" * 60)

    for r in sorted(results, key=lambda x: x.risk_score, reverse=True):
        report.append(f"\n{r.ioc_type.upper()}: {r.ioc_value}")
        report.append(f"  Risk Score: {r.risk_score}/100")
        report.append(f"  Disposition: {r.disposition}")

        if r.virustotal and "malicious" in r.virustotal:
            report.append(f"  VirusTotal: {r.virustotal['malicious']}/{r.virustotal.get('total_engines', 'N/A')} malicious")
        if r.abuseipdb and "confidence_score" in r.abuseipdb:
            report.append(f"  AbuseIPDB: {r.abuseipdb['confidence_score']}% confidence, {r.abuseipdb['total_reports']} reports")
        if r.greynoise and "classification" in r.greynoise:
            report.append(f"  GreyNoise: {r.greynoise['classification']}")
        if r.shodan_data and "ports" in r.shodan_data:
            report.append(f"  Shodan: Ports {r.shodan_data['ports']}, Org: {r.shodan_data.get('organization', 'N/A')}")

    return "\n".join(report)
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **IOC Enrichment** | Process of adding contextual intelligence to raw indicators from multiple external sources |
| **Composite Risk Score** | Weighted aggregate score combining multiple intelligence sources for disposition decisions |
| **Rate Limiting** | API request restrictions requiring throttling (VT free: 4/min, AbuseIPDB: 1000/day) |
| **GreyNoise RIOT** | Rule It Out — GreyNoise dataset of known benign services to reduce false positives |
| **Passive DNS** | Historical DNS resolution data showing domain-to-IP mappings over time |
| **Defanging** | Modifying IOCs for safe handling in reports (evil.com becomes evil[.]com) |

## Tools & Systems

- **VirusTotal**: Multi-engine malware scanner providing file, URL, IP, and domain analysis with 70+ AV engines
- **AbuseIPDB**: Community IP reputation database with abuse confidence scoring and ISP attribution
- **Shodan**: Internet-wide scanner providing open ports, banners, and vulnerability data for IP addresses
- **GreyNoise**: Internet noise intelligence distinguishing targeted attacks from opportunistic scanning
- **URLScan.io**: URL analysis platform capturing screenshots, DOM, and network requests for phishing detection

## Common Scenarios

- **Alert Triage Enrichment**: Auto-enrich all IPs in a notable event to determine if source is known malicious
- **Incident Scope Assessment**: Batch-enrich all IOCs from a compromised host to identify C2 infrastructure
- **Threat Intel Validation**: Enrich received IOC feed to validate quality before adding to blocking controls
- **Phishing URL Analysis**: Enrich URLs from reported phishing emails with URLScan and VT before user notification
- **False Positive Investigation**: Enrich flagged IP to determine if it belongs to CDN/cloud provider (legitimate)

## Output Format

```
IOC ENRICHMENT REPORT — IR-2024-0450
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Enrichment Time: 2024-03-15 14:30 UTC
IOCs Processed:  4

IP: 185.234.218[.]50
  Risk Score:   87/100 — MALICIOUS
  VirusTotal:   14/90 engines flagged malicious
  AbuseIPDB:    92% confidence, 347 reports
  Shodan:       Ports [22, 80, 443, 4444], Org: BulletProof Hosting
  GreyNoise:    malicious — known C2 infrastructure
  Action:       BLOCK immediately

DOMAIN: evil-c2-server[.]com
  Risk Score:   73/100 — MALICIOUS
  VirusTotal:   8/90 engines flagged
  URLScan:      5 scans, 4 malicious verdicts
  WHOIS:        Registered 3 days ago via Namecheap
  Action:       BLOCK and add to DNS sinkhole

HASH: a1b2c3d4e5f6...
  Risk Score:   91/100 — MALICIOUS
  VirusTotal:   52/72 engines (Cobalt Strike Beacon)
  MalwareBazaar: Tags: cobalt-strike, beacon, c2
  Action:       BLOCK hash, quarantine affected endpoints

IP: 45.33.32[.]156
  Risk Score:   5/100 — CLEAN
  VirusTotal:   0/90 engines
  GreyNoise:    benign — Shodan scanner
  Action:       No action required (known scanner)
```
