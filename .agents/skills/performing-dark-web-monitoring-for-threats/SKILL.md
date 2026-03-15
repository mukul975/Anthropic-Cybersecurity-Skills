---
name: performing-dark-web-monitoring-for-threats
description: Dark web monitoring involves systematically scanning Tor hidden services, underground forums, paste sites, and dark web marketplaces to identify threats targeting an organization, including leaked cre
domain: cybersecurity
subdomain: threat-intelligence
tags: [threat-intelligence, cti, ioc, mitre-attack, stix, dark-web, tor, threat-monitoring]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing Dark Web Monitoring for Threats

## Overview

Dark web monitoring involves systematically scanning Tor hidden services, underground forums, paste sites, and dark web marketplaces to identify threats targeting an organization, including leaked credentials, data breaches, threat actor discussions, vulnerability exploitation tools, and planned attacks. This skill covers setting up monitoring infrastructure, using Tor-based collection tools, implementing automated alerting for brand mentions and credential leaks, and analyzing dark web intelligence for actionable threat indicators.

## Prerequisites

- Tor Browser and Tor proxy (SOCKS5 on port 9050)
- Python 3.9+ with `requests`, `stem`, `beautifulsoup4`, `stix2` libraries
- Understanding of Tor hidden service architecture (.onion domains)
- API access to dark web monitoring services (Flare, SpyCloud, DarkOwl, Intel 471)
- Awareness of legal and ethical boundaries for dark web research
- Isolated VM for dark web browsing (no personal or corporate identity leakage)

## Key Concepts

### Dark Web Intelligence Sources
- **Underground Forums**: Hacking forums where threat actors discuss TTPs, sell exploits, and share tools
- **Paste Sites**: Platforms for sharing stolen data, credentials, and code snippets
- **Marketplaces**: Dark web markets selling stolen data, RaaS, exploit kits, and access
- **Telegram/Discord**: Alternative communication channels for cybercriminal groups
- **Ransomware Leak Sites**: Blogs where ransomware groups post stolen data from victims

### Collection Methods
- **Automated Crawling**: Tor-based web crawlers scanning hidden services
- **API-Based Monitoring**: Commercial dark web monitoring APIs (Flare, DarkOwl, Intel 471)
- **Manual HUMINT**: Analyst-driven research on specific forums and marketplaces
- **Credential Monitoring**: Breach databases and paste site monitoring for leaked credentials

### OPSEC for Dark Web Research
- Use dedicated VMs with no personal data
- Route all traffic through Tor (Whonix or Tails recommended)
- Never use personal accounts or identifiable information
- Use separate email addresses and personas for forum registration
- Disable JavaScript in Tor Browser for enhanced security
- Never download or execute files from dark web sources on production systems

## Practical Steps

### Step 1: Set Up Tor-Based HTTP Client

```python
import requests
from requests.adapters import HTTPAdapter

def create_tor_session():
    """Create a requests session routed through Tor SOCKS5 proxy."""
    session = requests.Session()
    session.proxies = {
        "http": "socks5h://127.0.0.1:9050",
        "https": "socks5h://127.0.0.1:9050",
    }
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
    })
    return session


def verify_tor_connection(session):
    """Verify that traffic is routed through Tor."""
    try:
        resp = session.get("https://check.torproject.org/api/ip", timeout=30)
        data = resp.json()
        return {
            "is_tor": data.get("IsTor", False),
            "ip": data.get("IP", ""),
        }
    except Exception as e:
        return {"error": str(e)}
```

### Step 2: Monitor Paste Sites for Credential Leaks

```python
import re
from datetime import datetime

def monitor_paste_sites(session, organization_domains):
    """Monitor paste sites for leaked credentials matching organization domains."""
    findings = []

    # Check Have I Been Pwned API (clearnet)
    for domain in organization_domains:
        try:
            resp = requests.get(
                f"https://haveibeenpwned.com/api/v3/breaches",
                headers={"hibp-api-key": "YOUR_HIBP_KEY"},
                timeout=30,
            )
            if resp.status_code == 200:
                breaches = resp.json()
                for breach in breaches:
                    if domain.lower() in breach.get("Domain", "").lower():
                        findings.append({
                            "source": "HIBP",
                            "breach_name": breach["Name"],
                            "breach_date": breach.get("BreachDate"),
                            "data_classes": breach.get("DataClasses", []),
                            "pwn_count": breach.get("PwnCount", 0),
                            "domain": domain,
                        })
        except Exception as e:
            print(f"[-] HIBP error for {domain}: {e}")

    return findings


def search_for_keywords(session, keywords, onion_paste_urls):
    """Search dark web paste sites for specific keywords."""
    results = []

    for paste_url in onion_paste_urls:
        try:
            resp = session.get(paste_url, timeout=60)
            if resp.status_code == 200:
                content = resp.text.lower()
                for keyword in keywords:
                    if keyword.lower() in content:
                        results.append({
                            "url": paste_url,
                            "keyword": keyword,
                            "timestamp": datetime.utcnow().isoformat(),
                            "snippet": extract_context(content, keyword.lower()),
                        })
        except Exception as e:
            print(f"[-] Error fetching {paste_url}: {e}")

    return results


def extract_context(text, keyword, context_chars=200):
    """Extract text context around a keyword match."""
    idx = text.find(keyword)
    if idx == -1:
        return ""
    start = max(0, idx - context_chars)
    end = min(len(text), idx + len(keyword) + context_chars)
    return text[start:end]
```

### Step 3: Monitor Ransomware Leak Sites

```python
def check_ransomware_leak_sites(session, organization_name):
    """Check known ransomware group leak sites for organization mentions."""
    # Use Ransomwatch API (clearnet aggregator of ransomware leak sites)
    try:
        resp = requests.get(
            "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json",
            timeout=30,
        )
        if resp.status_code == 200:
            posts = resp.json()
            matches = []
            for post in posts:
                post_title = post.get("post_title", "").lower()
                if organization_name.lower() in post_title:
                    matches.append({
                        "group": post.get("group_name", ""),
                        "title": post.get("post_title", ""),
                        "discovered": post.get("discovered", ""),
                        "url": post.get("post_url", ""),
                    })
            return matches
    except Exception as e:
        print(f"[-] Ransomwatch error: {e}")
    return []
```

### Step 4: Generate Dark Web Intelligence Report

```python
def generate_dark_web_report(findings, organization):
    """Generate structured dark web intelligence report."""
    report = {
        "organization": organization,
        "report_date": datetime.utcnow().isoformat(),
        "executive_summary": "",
        "credential_leaks": [],
        "ransomware_mentions": [],
        "dark_web_mentions": [],
        "recommendations": [],
    }

    for finding in findings:
        if finding.get("source") == "HIBP":
            report["credential_leaks"].append(finding)
        elif finding.get("group"):
            report["ransomware_mentions"].append(finding)
        else:
            report["dark_web_mentions"].append(finding)

    # Generate executive summary
    cred_count = len(report["credential_leaks"])
    ransom_count = len(report["ransomware_mentions"])
    report["executive_summary"] = (
        f"Monitoring identified {cred_count} credential leak sources "
        f"and {ransom_count} ransomware group mentions for {organization}."
    )

    if ransom_count > 0:
        report["recommendations"].append(
            "CRITICAL: Organization mentioned on ransomware leak site. "
            "Initiate incident response immediately."
        )
    if cred_count > 0:
        report["recommendations"].append(
            "HIGH: Leaked credentials detected. Force password resets for "
            "affected accounts and enable MFA."
        )

    return report
```

## Validation Criteria

- Tor connection established and verified via check.torproject.org
- Credential leak monitoring returns results from HIBP and paste sites
- Ransomware leak site monitoring identifies relevant mentions
- Dark web intelligence report generated with actionable recommendations
- All monitoring performed within legal and ethical boundaries
- OPSEC maintained: no personal or corporate identity exposure

## References

- [Tor Project](https://www.torproject.org/)
- [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [Ransomwatch](https://github.com/joshhighet/ransomwatch)
- [DarkOwl](https://www.darkowl.com/)
- [Intel 471](https://intel471.com/)
- [Flare Systems](https://flare.io/)
