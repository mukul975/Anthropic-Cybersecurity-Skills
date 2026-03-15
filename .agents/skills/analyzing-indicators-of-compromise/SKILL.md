---
name: analyzing-indicators-of-compromise
description: >
  Analyzes indicators of compromise (IOCs) including IP addresses, domains, file hashes, URLs,
  and email artifacts to determine maliciousness confidence, campaign attribution, and blocking
  priority. Use when triaging IOCs from phishing emails, security alerts, or external threat feeds;
  enriching raw IOCs with multi-source intelligence; or making block/monitor/whitelist decisions.
  Activates for requests involving VirusTotal, AbuseIPDB, MalwareBazaar, MISP, or IOC enrichment pipelines.
domain: cybersecurity
subdomain: threat-intelligence
tags: [IOC, VirusTotal, AbuseIPDB, MalwareBazaar, MISP, threat-intelligence, STIX, NIST-CSF]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Analyzing Indicators of Compromise

## When to Use

Use this skill when:
- A phishing email or alert generates IOCs (URLs, IP addresses, file hashes) requiring rapid triage
- Automated feeds deliver bulk IOCs that need confidence scoring before ingestion into blocking controls
- An incident investigation requires contextual enrichment of observed network artifacts

**Do not use** this skill in isolation for high-stakes blocking decisions — always combine automated enrichment with analyst judgment, especially for shared infrastructure (CDNs, cloud providers).

## Prerequisites

- VirusTotal API key (free or Enterprise) for multi-AV and sandbox lookup
- AbuseIPDB API key for IP reputation checks
- MISP instance or TIP for cross-referencing against known campaigns
- Python with `requests` and `vt-py` libraries, or SOAR platform with pre-built connectors

## Workflow

### Step 1: Normalize and Classify IOC Types

Before enriching, classify each IOC:
- **IPv4/IPv6 address**: Check if RFC 1918 private (skip external enrichment), validate format
- **Domain/FQDN**: Defang for safe handling (`evil[.]com`), extract registered domain via tldextract
- **URL**: Extract domain + path separately; check for redirectors
- **File hash**: Identify hash type (MD5/SHA-1/SHA-256); prefer SHA-256 for uniqueness
- **Email address**: Split into domain (check MX/DMARC) and local part for pattern analysis

Defang IOCs in documentation (replace `.` with `[.]` and `://` with `[://]`) to prevent accidental clicks.

### Step 2: Multi-Source Enrichment

**VirusTotal (file hash, URL, IP, domain)**:
```python
import vt

client = vt.Client("YOUR_VT_API_KEY")

# File hash lookup
file_obj = client.get_object(f"/files/{sha256_hash}")
detections = file_obj.last_analysis_stats
print(f"Malicious: {detections['malicious']}/{sum(detections.values())}")

# Domain analysis
domain_obj = client.get_object(f"/domains/{domain}")
print(domain_obj.last_analysis_stats)
print(domain_obj.reputation)
client.close()
```

**AbuseIPDB (IP addresses)**:
```python
import requests

response = requests.get(
    "https://api.abuseipdb.com/api/v2/check",
    headers={"Key": "YOUR_KEY", "Accept": "application/json"},
    params={"ipAddress": "1.2.3.4", "maxAgeInDays": 90}
)
data = response.json()["data"]
print(f"Confidence: {data['abuseConfidenceScore']}%, Reports: {data['totalReports']}")
```

**MalwareBazaar (file hashes)**:
```python
response = requests.post(
    "https://mb-api.abuse.ch/api/v1/",
    data={"query": "get_info", "hash": sha256_hash}
)
result = response.json()
if result["query_status"] == "ok":
    print(result["data"][0]["tags"], result["data"][0]["signature"])
```

### Step 3: Contextualize with Campaign Attribution

Query MISP for existing events matching the IOC:
```python
from pymisp import PyMISP

misp = PyMISP("https://misp.example.com", "API_KEY")
results = misp.search(value="evil-domain.com", type_attribute="domain")
for event in results:
    print(event["Event"]["info"], event["Event"]["threat_level_id"])
```

Check Shodan for IP context (hosting provider, open ports, banners) to identify if the IP belongs to bulletproof hosting or a legitimate cloud provider (false positive risk).

### Step 4: Assign Confidence Score and Disposition

Apply a tiered decision framework:
- **Block (High Confidence ≥ 70%)**: ≥15 AV detections on VT, AbuseIPDB score ≥70, matches known malware family or campaign
- **Monitor/Alert (Medium 40–69%)**: 5–14 AV detections, moderate AbuseIPDB score, no campaign attribution
- **Whitelist/Investigate (Low <40%)**: ≤4 AV detections, no abuse reports, legitimate service (Google, Cloudflare CDN IPs)
- **False Positive**: Legitimate business service incorrectly flagged; document and exclude from future alerts

### Step 5: Document and Distribute

Record findings in TIP/MISP with:
- All enrichment data collected (timestamps, source, score)
- Disposition decision and rationale
- Blocking actions taken (firewall, proxy, DNS sinkhole)
- Related incident ticket number

Export to STIX indicator object with confidence field set appropriately.

## Key Concepts

| Term | Definition |
|------|-----------|
| **IOC** | Indicator of Compromise — observable network or host artifact indicating potential compromise |
| **Enrichment** | Process of adding contextual data to a raw IOC from multiple intelligence sources |
| **Defanging** | Modifying IOCs (replacing `.` with `[.]`) to prevent accidental activation in documentation |
| **False Positive Rate** | Percentage of benign artifacts incorrectly flagged as malicious; critical for tuning block thresholds |
| **Sinkhole** | DNS server redirecting malicious domain lookups to a benign IP for detection without blocking traffic entirely |
| **TTL** | Time-to-live for an IOC in blocking controls; IP indicators should expire after 30 days, domains after 90 days |

## Tools & Systems

- **VirusTotal**: Multi-engine malware scanner and threat intelligence platform with 70+ AV engines, sandbox reports, and community comments
- **AbuseIPDB**: Community-maintained IP reputation database with 90-day abuse report history
- **MalwareBazaar (abuse.ch)**: Free malware hash repository with YARA rule associations and malware family tagging
- **URLScan.io**: Free URL analysis service that captures screenshots, DOM, and network requests for phishing URL triage
- **Shodan**: Internet-wide scan data providing hosting provider, open ports, and banner information for IP enrichment

## Common Pitfalls

- **Blocking shared infrastructure**: CDN IPs (Cloudflare 104.21.x.x, AWS CloudFront) may legitimately host malicious content but blocking the IP disrupts thousands of legitimate sites.
- **VT score obsession**: Low VT detection count does not mean benign — zero-day malware and custom APT tools often score 0 initially. Check sandbox behavior, MISP, and passive DNS.
- **Missing defanging**: Pasting live IOCs in emails or Confluence docs can trigger automated URL scanners or phishing tools.
- **No expiration policy**: IOCs without TTLs accumulate in blocklists indefinitely, generating false positives as infrastructure is repurposed by legitimate users.
- **Over-relying on single source**: VirusTotal aggregates AV opinions — all may be wrong or lag behind emerging malware. Use 3+ independent sources for high-stakes decisions.
