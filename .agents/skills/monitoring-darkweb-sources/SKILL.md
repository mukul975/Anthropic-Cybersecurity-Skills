---
name: monitoring-darkweb-sources
description: >
  Monitors dark web forums, marketplaces, paste sites, and ransomware leak sites for mentions
  of organizational assets, leaked credentials, threatened attacks, and threat actor communications
  to provide early warning intelligence. Use when establishing dark web monitoring coverage,
  investigating specific data breach claims, or enriching incident investigations with dark web
  context. Activates for requests involving dark web OSINT, leak site monitoring, credential
  exposure, Recorded Future dark web, or Tor hidden service intelligence.
domain: cybersecurity
subdomain: threat-intelligence
tags: [dark-web, OSINT, credential-monitoring, ransomware-leaks, Recorded-Future, SpiderFoot, CTI]
version: 1.0.0
author: team-cybersecurity
license: Apache-2.0
---
# Monitoring Dark Web Sources

## When to Use

Use this skill when:
- Establishing continuous monitoring for organizational domain names, executive names, and product brands on dark web forums
- Investigating a reported data breach claim found on a ransomware leak site or paste site
- Enriching an incident investigation with context about stolen credentials or planned attacks

**Do not use** this skill without proper operational security measures — dark web browsing without isolation exposes analyst infrastructure to adversary counter-intelligence.

## Prerequisites

- Commercial dark web monitoring service (Recorded Future, Flashpoint, Intel 471, or Cybersixgill)
- Isolated operational environment: Whonix OS or Tails OS running in a VM with no persistent storage
- Keyword watchlist: organization domain, key executive names, product names, IP ranges, known credentials
- Legal guidance confirming passive monitoring is authorized in your jurisdiction

## Workflow

### Step 1: Establish Keyword Monitoring via Commercial Services

Configure dark web monitoring keywords in your CTI platform (e.g., Recorded Future Exposure module):
- Domain variations: `company.com`, `@company.com`, `company[dot]com`
- Executive names: CEO, CISO, CFO full names
- Product/brand names
- Internal codenames or project names (if suspected breach scope is broad)
- Known email domains for credential monitoring

Most commercial services (Flashpoint, Intel 471, Cybersixgill) crawl forums like XSS, Exploit[.]in, BreachForums, and Russian-language cybercriminal communities without analyst exposure.

### Step 2: Manual Investigation with Operational Security

For investigations requiring direct dark web access:

**Environment setup**:
1. Use a dedicated physical machine or air-gapped VM (Whonix + VirtualBox)
2. Connect via Tor Browser only — never via standard browser
3. Use a cover identity with no links to organization
4. Never log in with real credentials to any dark web site
5. Document all sessions in investigation log with timestamps

**Paste site monitoring** (clearnet-accessible, no Tor required):
```bash
# Hunt paste sites via API
curl "https://psbdmp.ws/api/search/company.com" | jq '.data[].id'
curl "https://pastebin.com/search?q=company.com" # Rate-limited public search
```

### Step 3: Investigate Ransomware Leak Sites

Ransomware groups maintain .onion leak sites. Monitor these through commercial services rather than direct access. When a claim appears about your organization:

1. Capture screenshot evidence via commercial service (do not access directly)
2. Assess legitimacy: Does the threat actor's claimed data align with any known internal systems?
3. Check timestamp: Is this claim recent or historical?
4. Cross-reference with any known security incidents or phishing campaigns from that timeframe
5. Engage IR team if claim appears credible before public disclosure

Known active ransomware leak site operators (as of early 2025): LockBit (disrupted Feb 2024), ALPHV/BlackCat (disrupted Dec 2023), Cl0p, RansomHub, Play.

### Step 4: Credential Exposure Monitoring

For leaked credential monitoring:
- **Have I Been Pwned Enterprise**: Domain-level notification for credential exposures in breach datasets
- **SpyCloud**: Commercial credential monitoring with anti-cracking and plaintext password recovery from criminal markets
- **Flare Systems**: Automated monitoring of paste sites and dark web markets for credential dumps

When credential exposures are confirmed:
1. Force password reset for affected accounts immediately
2. Check if credentials provide access to any organizational systems (SSO, VPN)
3. Review access logs for the period between credential exposure and detection for unauthorized access

### Step 5: Document and Escalate Findings

For each dark web finding:
- Capture evidence (commercial service screenshot, paste site archive)
- Classify severity: P1 (imminent attack threat or active data exposure), P2 (credential exposure), P3 (general mention)
- Notify appropriate stakeholders within defined SLAs
- Open investigation ticket and link to evidence artifacts
- Apply TLP:RED for any findings referencing named executives or specific attack plans

## Key Concepts

| Term | Definition |
|------|-----------|
| **Dark Web** | Tor-accessible hidden services (.onion domains) not indexed by standard search engines; hosts both legitimate and criminal content |
| **Paste Site** | Clearnet text-sharing sites (Pastebin, Ghostbin) frequently used to publish stolen data or malware configurations |
| **Ransomware Leak Site** | .onion site operated by ransomware group to publish stolen victim data as extortion leverage |
| **Operational Security (OPSEC)** | Protecting analyst identity and organizational affiliation during dark web investigation |
| **Credential Stuffing** | Automated use of leaked username/password pairs against authentication systems |
| **Stealer Logs** | Data packages exfiltrated by infostealer malware containing saved browser credentials, cookies, and session tokens |

## Tools & Systems

- **Recorded Future Dark Web Module**: Automated monitoring of dark web sources with alerting on organization-specific keywords
- **Flashpoint**: Dark web forum monitoring with human intelligence augmentation for criminal community context
- **Intel 471**: Closed-source access to cybercriminal communities with structured intelligence on threat actors
- **SpyCloud**: Credential exposure monitoring with recaptured plaintext passwords from criminal markets
- **Have I Been Pwned Enterprise**: Domain-level breach notification API for credential monitoring at scale

## Common Pitfalls

- **Direct access without OPSEC**: Accessing dark web forums without Tor and a cover identity can expose analyst IP, browser fingerprint, and organization affiliation to adversaries.
- **Overreacting to unverified claims**: Ransomware groups and forum posters fabricate attack claims for extortion or reputation. Verify before escalating to incident response.
- **Missing clearnet sources**: Most dark web intelligence programs miss Telegram channels, Discord servers, and paste sites which operate on the clearnet and host significant criminal activity.
- **Inadequate legal review**: Dark web monitoring must be reviewed by legal counsel — passive monitoring is generally lawful but active participation in criminal markets is not.
- **No evidence preservation**: Dark web content disappears rapidly. Capture timestamped evidence immediately upon discovery using commercial service exports.
