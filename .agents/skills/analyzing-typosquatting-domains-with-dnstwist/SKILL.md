---
name: analyzing-typosquatting-domains-with-dnstwist
description: Detect typosquatting, homograph phishing, and brand impersonation domains using dnstwist to generate domain permutations and identify registered lookalike domains targeting your organization.
domain: cybersecurity
subdomain: threat-intelligence
tags: [dnstwist, typosquatting, phishing, domain-monitoring, brand-protection, homograph, dns, threat-intelligence]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Analyzing Typosquatting Domains with DNSTwist

## Overview

DNSTwist is a domain name permutation engine that generates similar-looking domain names to detect typosquatting, homograph phishing attacks, and brand impersonation. It creates thousands of domain permutations using techniques like character substitution, transposition, insertion, omission, and homoglyph replacement, then checks DNS records (A, AAAA, NS, MX), calculates web page similarity using fuzzy hashing (ssdeep) and perceptual hashing (pHash), and identifies potentially malicious registered domains.

## Prerequisites

- Python 3.9+ with `dnstwist` installed (`pip install dnstwist[full]`)
- Optional: GeoIP database for IP geolocation
- Optional: Shodan API key for enrichment
- Network access to perform DNS queries
- Understanding of DNS record types and domain registration

## Key Concepts

### Domain Permutation Techniques

DNSTwist generates permutations using: addition (appending characters), bitsquatting (bit-flip errors), homoglyph (visually similar Unicode characters like rn vs m), hyphenation (adding hyphens), insertion (inserting characters), omission (removing characters), repetition (repeating characters), replacement (replacing with adjacent keyboard keys), subdomain (inserting dots), transposition (swapping adjacent characters), vowel-swap (swapping vowels), and dictionary-based (appending common words).

### Fuzzy Hashing and Visual Similarity

DNSTwist uses ssdeep (locality-sensitive hash) to compare HTML content and pHash (perceptual hash) to compare screenshots of web pages. This helps identify cloned phishing sites that visually mimic the legitimate site. A high similarity score indicates a likely phishing page.

### Detection Workflow

The typical workflow is: generate domain permutations -> resolve DNS records -> check for registered domains -> compare web page similarity -> flag suspicious domains -> alert security team -> request takedown. For a typical corporate domain, dnstwist generates 5,000-10,000 permutations.

## Practical Steps

### Step 1: Basic Domain Permutation Scan

```python
import subprocess
import json
import csv
from datetime import datetime

def run_dnstwist_scan(domain, output_file=None):
    """Run dnstwist scan against a target domain."""
    cmd = [
        "dnstwist",
        "--registered",     # Only show registered domains
        "--format", "json", # Output in JSON
        "--nameservers", "8.8.8.8,1.1.1.1",
        "--threads", "50",
        "--mxcheck",        # Check MX records
        "--ssdeep",         # Fuzzy hash comparison
        "--geoip",          # GeoIP lookup
        domain,
    ]

    print(f"[*] Scanning permutations for: {domain}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

    if result.returncode == 0:
        results = json.loads(result.stdout)
        registered = [r for r in results if r.get("dns_a") or r.get("dns_aaaa")]
        print(f"[+] Found {len(registered)} registered lookalike domains")

        if output_file:
            with open(output_file, "w") as f:
                json.dump(registered, f, indent=2)
            print(f"[+] Results saved to {output_file}")

        return registered
    else:
        print(f"[-] dnstwist error: {result.stderr}")
        return []

results = run_dnstwist_scan("example.com", "typosquat_results.json")
```

### Step 2: Analyze and Prioritize Results

```python
def analyze_results(results, legitimate_ips=None):
    """Analyze dnstwist results and prioritize threats."""
    legitimate_ips = legitimate_ips or set()
    high_risk = []
    medium_risk = []
    low_risk = []

    for entry in results:
        domain = entry.get("domain", "")
        fuzzer = entry.get("fuzzer", "")
        dns_a = entry.get("dns_a", [])
        dns_mx = entry.get("dns_mx", [])
        ssdeep_score = entry.get("ssdeep_score", 0)

        risk_score = 0
        risk_factors = []

        # High similarity to legitimate site
        if ssdeep_score and ssdeep_score > 50:
            risk_score += 40
            risk_factors.append(f"high web similarity ({ssdeep_score}%)")

        # Has MX records (can receive email / phishing)
        if dns_mx:
            risk_score += 20
            risk_factors.append("has MX records (email capable)")

        # Recently registered (if whois data available)
        whois_created = entry.get("whois_created", "")
        if whois_created:
            try:
                created = datetime.fromisoformat(whois_created.replace("Z", "+00:00"))
                age_days = (datetime.now(created.tzinfo) - created).days
                if age_days < 30:
                    risk_score += 30
                    risk_factors.append(f"recently registered ({age_days} days)")
                elif age_days < 90:
                    risk_score += 15
                    risk_factors.append(f"registered {age_days} days ago")
            except (ValueError, TypeError):
                pass

        # Homoglyph attacks are highest risk
        if fuzzer == "homoglyph":
            risk_score += 25
            risk_factors.append("homoglyph (visually identical)")
        elif fuzzer in ("addition", "replacement", "transposition"):
            risk_score += 10
            risk_factors.append(f"permutation type: {fuzzer}")

        # Not pointing to legitimate infrastructure
        if dns_a and not set(dns_a).intersection(legitimate_ips):
            risk_score += 10
            risk_factors.append("different IP from legitimate")

        entry["risk_score"] = risk_score
        entry["risk_factors"] = risk_factors

        if risk_score >= 50:
            high_risk.append(entry)
        elif risk_score >= 25:
            medium_risk.append(entry)
        else:
            low_risk.append(entry)

    high_risk.sort(key=lambda x: x["risk_score"], reverse=True)
    medium_risk.sort(key=lambda x: x["risk_score"], reverse=True)

    print(f"\n=== Typosquatting Analysis ===")
    print(f"High Risk: {len(high_risk)}")
    print(f"Medium Risk: {len(medium_risk)}")
    print(f"Low Risk: {len(low_risk)}")

    if high_risk:
        print(f"\n--- High Risk Domains ---")
        for entry in high_risk[:10]:
            print(f"  {entry['domain']} (score: {entry['risk_score']})")
            for factor in entry['risk_factors']:
                print(f"    - {factor}")

    return {"high": high_risk, "medium": medium_risk, "low": low_risk}

analysis = analyze_results(results, legitimate_ips={"93.184.216.34"})
```

### Step 3: Continuous Monitoring Pipeline

```python
import time
import hashlib

class TyposquatMonitor:
    def __init__(self, domains, known_domains_file="known_typosquats.json"):
        self.domains = domains
        self.known_file = known_domains_file
        self.known_domains = self._load_known()

    def _load_known(self):
        try:
            with open(self.known_file, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def _save_known(self):
        with open(self.known_file, "w") as f:
            json.dump(self.known_domains, f, indent=2)

    def scan_all_domains(self):
        """Scan all monitored domains for new typosquats."""
        new_findings = []
        for domain in self.domains:
            results = run_dnstwist_scan(domain)
            for entry in results:
                domain_key = entry.get("domain", "")
                if domain_key not in self.known_domains:
                    entry["first_seen"] = datetime.now().isoformat()
                    entry["monitored_domain"] = domain
                    self.known_domains[domain_key] = entry
                    new_findings.append(entry)
                    print(f"  [NEW] {domain_key} ({entry.get('fuzzer', '')})")

        self._save_known()
        print(f"\n[+] New typosquatting domains found: {len(new_findings)}")
        return new_findings

    def generate_alert(self, findings):
        """Generate alert for new high-risk typosquatting domains."""
        analysis = analyze_results(findings)
        alerts = []
        for entry in analysis["high"]:
            alerts.append({
                "severity": "HIGH",
                "domain": entry["domain"],
                "target": entry.get("monitored_domain", ""),
                "risk_score": entry["risk_score"],
                "risk_factors": entry["risk_factors"],
                "dns_a": entry.get("dns_a", []),
                "dns_mx": entry.get("dns_mx", []),
                "timestamp": datetime.now().isoformat(),
            })
        return alerts

monitor = TyposquatMonitor(["mycompany.com", "mycompany.org"])
new_findings = monitor.scan_all_domains()
alerts = monitor.generate_alert(new_findings)
```

### Step 4: Export for Blocklist and Takedown

```python
def export_blocklist(analysis, output_file="blocklist.txt"):
    """Export high-risk domains as blocklist for firewall/proxy."""
    domains = []
    for entry in analysis["high"] + analysis["medium"]:
        domain = entry.get("domain", "")
        if domain:
            domains.append(domain)

    with open(output_file, "w") as f:
        f.write(f"# Typosquatting blocklist generated {datetime.now().isoformat()}\n")
        for d in sorted(set(domains)):
            f.write(f"{d}\n")

    print(f"[+] Blocklist saved: {len(domains)} domains -> {output_file}")
    return domains

def generate_takedown_report(high_risk_domains):
    """Generate takedown request report."""
    report = f"""# Domain Takedown Request
Generated: {datetime.now().isoformat()}

## Summary
{len(high_risk_domains)} domains identified as potential typosquatting/phishing.

## Domains Requiring Takedown
"""
    for entry in high_risk_domains:
        report += f"""
### {entry['domain']}
- **Permutation Type**: {entry.get('fuzzer', 'unknown')}
- **IP Address**: {', '.join(entry.get('dns_a', ['N/A']))}
- **MX Records**: {', '.join(entry.get('dns_mx', ['N/A']))}
- **Risk Score**: {entry.get('risk_score', 0)}
- **Risk Factors**: {'; '.join(entry.get('risk_factors', []))}
- **Web Similarity**: {entry.get('ssdeep_score', 'N/A')}%
"""
    with open("takedown_report.md", "w") as f:
        f.write(report)
    print("[+] Takedown report generated: takedown_report.md")

export_blocklist(analysis)
generate_takedown_report(analysis["high"])
```

## Validation Criteria

- DNSTwist generates domain permutations for target domain
- DNS resolution identifies registered lookalike domains
- Web similarity scoring detects cloned phishing pages
- Risk scoring prioritizes domains by threat level
- Continuous monitoring detects newly registered typosquats
- Blocklist and takedown reports generated correctly

## References

- [dnstwist GitHub Repository](https://github.com/elceef/dnstwist)
- [dnstwister Online Service](https://dnstwister.report/)
- [HawkEye: Detect Typosquatting with DNSTwist](https://hawk-eye.io/2022/11/how-to-detect-typosquatting-using-dnstwist/)
- [Darktrace: Monitoring Typosquatting Domains](https://www.darktrace.com/blog/vigilance-in-action-monitoring-typosquatting-domains)
- [Security Risk Advisors: Domain Monitoring](https://sra.io/blog/domain-monitoring-fast-and-cheap/)
- [Conscia: How to Detect Typosquatting](https://conscia.com/blog/diving-deep-how-to-detect-typosquatting/)
