---
name: analyzing-threat-intelligence-feeds
description: >
  Analyzes structured and unstructured threat intelligence feeds to extract actionable indicators,
  adversary tactics, and campaign context. Use when ingesting commercial or open-source CTI feeds,
  evaluating feed quality, normalizing data into STIX 2.1 format, or enriching existing IOCs with
  campaign attribution. Activates for requests involving ThreatConnect, Recorded Future, Mandiant
  Advantage, MISP, AlienVault OTX, or automated feed aggregation pipelines.
domain: cybersecurity
subdomain: threat-intelligence
tags: [STIX, TAXII, MITRE-ATT&CK, IOC, ThreatConnect, Recorded-Future, MISP, CTI, NIST-CSF]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Analyzing Threat Intelligence Feeds

## When to Use

Use this skill when:
- Ingesting new commercial or OSINT threat feeds and assessing their signal-to-noise ratio
- Normalizing heterogeneous IOC formats (STIX 2.1, OpenIOC, YARA, Sigma) into a unified schema
- Evaluating feed freshness, fidelity, and relevance to the organization's threat profile
- Building automated enrichment pipelines that correlate IOCs against SIEM events

**Do not use** this skill for raw packet capture analysis or live incident triage without first establishing a CTI baseline.

## Prerequisites

- Access to a Threat Intelligence Platform (TIP) such as ThreatConnect, MISP, or OpenCTI
- API keys for at least one commercial feed (Recorded Future, Mandiant Advantage, or VirusTotal Enterprise)
- TAXII 2.1 client library (taxii2-client Python package or equivalent)
- Role with read/write permissions to the TIP's indicator database

## Workflow

### Step 1: Enumerate and Prioritize Feed Sources

List all available feeds categorized by type (commercial, government, ISAC, OSINT):
- Commercial: Recorded Future, Mandiant Advantage, CrowdStrike Falcon Intelligence
- Government: CISA AIS (Automated Indicator Sharing), FBI InfraGard, MS-ISAC
- OSINT: AlienVault OTX, Abuse.ch, PhishTank, Emerging Threats

Score each feed on: update frequency, historical accuracy rate, coverage of your sector, and attribution depth. Use a weighted scoring matrix with criteria from NIST SP 800-150 (Guide to Cyber Threat Information Sharing).

### Step 2: Ingest via TAXII 2.1 or API

For TAXII-enabled feeds:
```
taxii2-client discover https://feed.example.com/taxii/
taxii2-client get-collection --collection-id <id> --since 2024-01-01
```

For REST API feeds (e.g., Recorded Future):
- Query `/v2/indicator/search` with `risk_score_min=65` to filter low-confidence IOCs
- Apply rate limiting and exponential backoff for API resilience

### Step 3: Normalize to STIX 2.1

Convert each IOC to STIX 2.1 objects using the OASIS standard schema:
- IP address → `indicator` object with `pattern: "[ipv4-addr:value = '...']"`
- Domain → `indicator` with `pattern: "[domain-name:value = '...']"`
- File hash → `indicator` with `pattern: "[file:hashes.SHA-256 = '...']"`

Attach `relationship` objects linking indicators to `threat-actor` or `malware` objects. Use `confidence` field (0–100) based on source fidelity rating.

### Step 4: Deduplicate and Enrich

Run deduplication against existing TIP database using normalized value + type as composite key. Enrich surviving IOCs:
- VirusTotal: detection ratio, sandbox behavior reports
- PassiveTotal (RiskIQ): WHOIS history, passive DNS, SSL certificate chains
- Shodan: banner data, open ports, geographic location

### Step 5: Distribute to Consuming Systems

Export enriched indicators via TAXII 2.1 push to SIEM (Splunk, Microsoft Sentinel), firewalls (Palo Alto XSOAR playbooks), and EDR platforms. Set TTL (time-to-live) per indicator type: IP addresses 30 days, domains 90 days, file hashes 1 year.

## Key Concepts

| Term | Definition |
|------|-----------|
| **STIX 2.1** | Structured Threat Information Expression — OASIS standard JSON schema for CTI objects including indicators, threat actors, campaigns, and relationships |
| **TAXII 2.1** | Trusted Automated eXchange of Intelligence Information — HTTPS-based protocol for sharing STIX content between servers and clients |
| **IOC** | Indicator of Compromise — observable artifact (IP, domain, hash, URL) that indicates a system may have been breached |
| **TLP** | Traffic Light Protocol — color-coded classification (RED/AMBER/GREEN/WHITE) defining sharing restrictions for CTI |
| **Confidence Score** | Numeric value (0–100 in STIX) reflecting the producer's certainty about an indicator's malicious attribution |
| **Feed Fidelity** | Historical accuracy rate of a feed measured by true positive rate in production detections |

## Tools & Systems

- **ThreatConnect TC Exchange**: Aggregates 100+ commercial and OSINT feeds; provides automated playbooks for IOC enrichment
- **MISP (Malware Information Sharing Platform)**: Open-source TIP supporting STIX/TAXII; widely used by ISACs and government CERTs
- **OpenCTI**: Open-source platform with native MITRE ATT&CK integration and graph-based relationship visualization
- **Recorded Future**: Commercial feed with AI-powered risk scoring and real-time dark web monitoring
- **taxii2-client**: Python library for TAXII 2.0/2.1 client operations (pip install taxii2-client)
- **PyMISP**: Python API for MISP feed management and IOC submission

## Common Pitfalls

- **IOC age staleness**: IP addresses and domains rotate frequently; applying 1-year-old IOCs generates false positives. Enforce TTL policies.
- **Missing context**: Blocking an IOC without understanding the associated campaign or adversary can disrupt legitimate business traffic (e.g., CDN IPs shared with malicious actors).
- **Feed overlap without deduplication**: Ingesting the same IOC from five feeds without deduplication inflates indicator counts and SIEM rule complexity.
- **TLP violation**: Redistributing RED-classified intelligence outside authorized boundaries violates sharing agreements and trust relationships.
- **Over-blocking on low-confidence indicators**: Indicators with confidence below 50 should trigger detection-only rules, not blocking, to avoid operational disruption.
