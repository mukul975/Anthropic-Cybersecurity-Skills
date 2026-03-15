---
name: collecting-open-source-intelligence
description: >
  Collects and synthesizes open-source intelligence (OSINT) about threat actors, malicious
  infrastructure, and attack campaigns using publicly available data sources, passive reconnaissance
  tools, and dark web monitoring. Use when investigating external threat actor infrastructure,
  performing pre-engagement reconnaissance for authorized red team assessments, or enriching CTI
  reports with publicly available adversary context. Activates for requests involving Maltego,
  Shodan, OSINT framework, SpiderFoot, or infrastructure reconnaissance.
domain: cybersecurity
subdomain: threat-intelligence
tags: [OSINT, Maltego, Shodan, Recon-ng, SpiderFoot, threat-intelligence, ATT&CK-T1591, NIST-CSF]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Collecting Open-Source Intelligence

## When to Use

Use this skill when:
- Investigating external infrastructure associated with a phishing campaign targeting your organization
- Enriching threat actor profiles with publicly observable indicators (WHOIS, ASN data, SSL certificates)
- Conducting authorized attack surface discovery to understand your organization's external exposure

**Do not use** this skill for active scanning against targets without explicit written authorization — OSINT collection must remain passive (no packets sent to target systems) unless scope permits active recon.

## Prerequisites

- Maltego CE or commercial license for graph-based link analysis
- Shodan API key (https://shodan.io) for internet-wide device/service discovery
- OSINT Framework familiarity (https://osintframework.com) for tool selection
- SpiderFoot HX or open-source SpiderFoot for automated OSINT correlation

## Workflow

### Step 1: Define Collection Requirements

Establish the intelligence requirement (IR) before collecting. Document:
- Target: threat actor group, malicious domain, IP range, or organization
- Priority Intelligence Requirements (PIRs): What specific questions need answering?
- Legal authority: Passive OSINT is legal; active probing requires authorization
- Data handling: TLP classification for collected intelligence

### Step 2: Passive DNS and WHOIS Investigation

```bash
# Passive DNS via SecurityTrails API
curl "https://api.securitytrails.com/v1/domain/evil-domain.com/dns/a" \
  -H "apikey: YOUR_KEY"

# WHOIS history via ARIN / RIPE
whois -h whois.arin.net evil-domain.com

# Certificate transparency logs (no API key required)
curl "https://crt.sh/?q=%.evil-domain.com&output=json" | jq '.[].name_value'
```

Certificate transparency logs reveal all subdomains for a target domain, often exposing staging, VPN, or internal infrastructure inadvertently made public.

### Step 3: Shodan Infrastructure Mapping

```python
import shodan

api = shodan.Shodan("YOUR_SHODAN_API_KEY")

# Search for specific C2 framework signatures (Cobalt Strike beacon)
results = api.search('product:"Cobalt Strike" port:443')
for r in results['matches']:
    print(r['ip_str'], r['port'], r['org'], r.get('ssl', {}).get('cert', {}).get('subject', ''))

# Find infrastructure associated with a known threat actor's ASN
results = api.search('asn:AS12345 http.title:"Redirector"')
```

Correlate Shodan results with passive DNS to build infrastructure clusters.

### Step 4: Maltego Graph Analysis

In Maltego, use these built-in transforms for threat actor infrastructure mapping:
1. Start with a known malicious domain (Entity: Domain)
2. Run "To IP Address [DNS]" → identifies hosting IPs
3. Run "To Shared Hosting" → identifies co-hosted domains (potentially same threat actor)
4. Run "To DNS Name [Reverse DNS]" → identifies PTR records
5. Run "To Whois" → identifies registrant email/organization
6. Pivot on registrant email → "To Domains [Registrant Email]" → expands to all domains registered with same email

Maltego Maltego Cyber threat intelligence transforms (VirusTotal, Shodan, PassiveTotal, URLScan) extend graph coverage.

### Step 5: Dark Web and Paste Site Monitoring

Use SpiderFoot HX or manual searches for:
- Paste sites (Pastebin, Ghostbin): search for leaked credentials, IOCs, malware configs
- Dark web forums: via Tor browser with appropriate operational security
- GitHub/GitLab: search for exposed credentials or organization-specific strings

```bash
# SpiderFoot CLI for automated OSINT
python sf.py -s evil-domain.com -m sfp_shodan,sfp_virustotal,sfp_passivetotal \
  -o TF -R result.json
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Passive OSINT** | Intelligence collection that does not send any packets to target systems — uses public databases, search engines, cached data |
| **PIR** | Priority Intelligence Requirement — specific question the intelligence collection must answer, preventing unfocused data gathering |
| **Certificate Transparency** | Public log of all SSL/TLS certificates issued by CAs, enabling discovery of subdomains via crt.sh |
| **Pivoting** | Using one data point (IP, email, registrant name) to discover related infrastructure or accounts |
| **ASN** | Autonomous System Number — block of IP addresses under a single routing policy; useful for clustering threat actor infrastructure |
| **Co-hosted Domains** | Multiple domains resolving to the same IP, potentially indicating shared attacker infrastructure |

## Tools & Systems

- **Maltego**: Graph-based link analysis platform with 50+ data source transforms for IP, domain, email, and social media analysis
- **Shodan**: Internet-wide scanner database with 1B+ indexed devices; supports banner, port, SSL certificate, and vulnerability searches
- **SpiderFoot**: Automated OSINT tool with 200+ modules covering DNS, WHOIS, dark web, breach data, and social media
- **Recon-ng**: Python-based OSINT framework with modular design for domain, email, and social media reconnaissance
- **crt.sh**: Free certificate transparency search engine for subdomain and certificate discovery
- **OSINT Framework (osintframework.com)**: Curated directory of OSINT tools organized by intelligence category

## Common Pitfalls

- **Leaving digital footprints**: Visiting a threat actor's website or Shodan-queried IP can alert the adversary. Use Tor or VPN with a dedicated OSINT VM.
- **Confirmation bias in graph analysis**: Maltego graphs can create false connections. Verify each pivot independently before treating as confirmed.
- **Outdated data**: WHOIS privacy services and bulletproof hosting rotate frequently. Always check data timestamps — 6-month-old passive DNS may no longer be valid.
- **Attribution overconfidence**: Infrastructure overlap does not guarantee same threat actor. False flag operations deliberately share indicators across groups.
- **Legal boundaries**: Some OSINT tools perform active scans (port scanning, banner grabbing). Confirm tool behavior before use against external targets without authorization.
