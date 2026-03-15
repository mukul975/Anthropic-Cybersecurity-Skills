---
name: performing-paste-site-monitoring-for-credentials
description: Monitor paste sites like Pastebin and GitHub Gists for leaked credentials, API keys, and sensitive data dumps using automated scraping and keyword matching to detect breaches early.
domain: cybersecurity
subdomain: threat-intelligence
tags: [paste-monitoring, credential-leak, pastebin, data-breach, threat-intelligence, osint, early-warning]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing Paste Site Monitoring for Credentials

## Overview

Paste sites (Pastebin, GitHub Gists, Ghostbin, Dpaste, Hastebin) are frequently used as staging areas for leaked credentials, database dumps, API keys, and sensitive data before wider distribution on dark web forums and Telegram channels. Monitoring these sites provides early breach detection, enabling organizations to respond before stolen data is weaponized. This skill covers building automated paste site monitors using the Pastebin Scraping API, keyword-based alerting, credential pattern matching, and integration with incident response workflows.

## Prerequisites

- Python 3.9+ with `requests`, `beautifulsoup4`, `regex`, `pymisp` libraries
- Pastebin PRO account with Scraping API access ($49.95/month for programmatic access)
- GitHub API token for Gist monitoring
- Keyword lists specific to your organization (domains, project names, internal terms)
- Elasticsearch or database for paste storage and search

## Key Concepts

### Paste Site Threat Landscape

Over 300,000 user credentials are posted on Pastebin annually, averaging 1,000 username/password pairs per leak. Paste sites serve three primary threat intelligence purposes: early breach detection (credentials appear on paste sites before dark web), threat actor profiling (actors use paste sites for C2 configuration, data staging, tool sharing), and malware discovery (encoded payloads, configuration files, C2 addresses).

### Monitoring Approaches

Active monitoring queries paste site APIs or scraping endpoints at regular intervals. The Pastebin Scraping API provides real-time access to new public pastes. For GitHub, the search API allows monitoring Gists and repository commits for exposed secrets. Passive monitoring uses services like IntelX, Dehashed, or Have I Been Pwned that aggregate paste site data.

### Credential Pattern Detection

Effective monitoring uses regex patterns for email:password combinations, API keys (AWS, Azure, GCP, Stripe, Twilio), database connection strings, private keys (SSH, PGP), JWT tokens, and internal hostnames/URLs. Organization-specific keywords (domain names, product names, employee names) reduce false positives.

## Practical Steps

### Step 1: Pastebin Scraping API Monitor

```python
import requests
import re
import json
import time
from datetime import datetime

class PastebinMonitor:
    SCRAPING_URL = "https://scrape.pastebin.com/api_scraping.php"
    RAW_URL = "https://scrape.pastebin.com/api_scrape_item.php"

    def __init__(self, keywords, output_dir="paste_alerts"):
        self.keywords = [k.lower() for k in keywords]
        self.output_dir = output_dir
        self.seen_keys = set()
        self.credential_patterns = {
            "email_password": re.compile(
                r'[\w.+-]+@[\w-]+\.[\w.]+[\s:;|,]+[\S]{6,}', re.IGNORECASE),
            "aws_key": re.compile(
                r'AKIA[0-9A-Z]{16}'),
            "aws_secret": re.compile(
                r'[0-9a-zA-Z/+=]{40}'),
            "github_token": re.compile(
                r'ghp_[0-9a-zA-Z]{36}'),
            "slack_token": re.compile(
                r'xox[baprs]-[0-9a-zA-Z-]+'),
            "private_key": re.compile(
                r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
            "jwt_token": re.compile(
                r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'),
            "connection_string": re.compile(
                r'(?:mongodb|postgres|mysql|redis)://[^\s]+'),
            "api_key_generic": re.compile(
                r'(?:api[_-]?key|apikey|access[_-]?token)[\s]*[=:]\s*["\']?[\w-]{20,}',
                re.IGNORECASE),
        }

    def fetch_recent_pastes(self, limit=100):
        """Fetch recent public pastes from Pastebin Scraping API."""
        params = {"limit": limit}
        try:
            resp = requests.get(self.SCRAPING_URL, params=params, timeout=30)
            if resp.status_code == 200:
                pastes = resp.json()
                print(f"[+] Fetched {len(pastes)} recent pastes")
                return pastes
            else:
                print(f"[-] API error: {resp.status_code}")
                return []
        except Exception as e:
            print(f"[-] Fetch error: {e}")
            return []

    def get_paste_content(self, paste_key):
        """Get the raw content of a paste."""
        params = {"i": paste_key}
        try:
            resp = requests.get(self.RAW_URL, params=params, timeout=15)
            if resp.status_code == 200:
                return resp.text
            return ""
        except Exception:
            return ""

    def analyze_paste(self, content, paste_metadata):
        """Analyze paste content for credentials and keywords."""
        findings = {
            "keyword_matches": [],
            "credential_matches": {},
            "severity": "low",
        }

        content_lower = content.lower()

        # Check keywords
        for keyword in self.keywords:
            if keyword in content_lower:
                count = content_lower.count(keyword)
                findings["keyword_matches"].append({
                    "keyword": keyword,
                    "count": count,
                })

        # Check credential patterns
        for pattern_name, pattern in self.credential_patterns.items():
            matches = pattern.findall(content)
            if matches:
                findings["credential_matches"][pattern_name] = {
                    "count": len(matches),
                    "samples": matches[:3],
                }

        # Calculate severity
        cred_count = sum(
            m["count"] for m in findings["credential_matches"].values()
        )
        if findings["keyword_matches"] and cred_count > 0:
            findings["severity"] = "critical"
        elif findings["keyword_matches"]:
            findings["severity"] = "high"
        elif cred_count > 10:
            findings["severity"] = "high"
        elif cred_count > 0:
            findings["severity"] = "medium"

        return findings

    def monitor_loop(self, interval=120, iterations=None):
        """Continuous monitoring loop."""
        count = 0
        while iterations is None or count < iterations:
            pastes = self.fetch_recent_pastes()
            alerts = []

            for paste in pastes:
                paste_key = paste.get("key", "")
                if paste_key in self.seen_keys:
                    continue
                self.seen_keys.add(paste_key)

                content = self.get_paste_content(paste_key)
                if not content:
                    continue

                findings = self.analyze_paste(content, paste)
                if findings["severity"] != "low":
                    alert = {
                        "paste_key": paste_key,
                        "title": paste.get("title", "Untitled"),
                        "user": paste.get("user", "Anonymous"),
                        "date": paste.get("date", ""),
                        "size": paste.get("size", 0),
                        "url": f"https://pastebin.com/{paste_key}",
                        "findings": findings,
                        "detected_at": datetime.now().isoformat(),
                    }
                    alerts.append(alert)
                    print(f"  [ALERT-{findings['severity'].upper()}] "
                          f"{paste_key}: {findings['keyword_matches']}")

            if alerts:
                self._save_alerts(alerts)

            count += 1
            if iterations is None or count < iterations:
                time.sleep(interval)

        return alerts

    def _save_alerts(self, alerts):
        """Save alerts to JSON file."""
        filename = f"{self.output_dir}/alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        import os
        os.makedirs(self.output_dir, exist_ok=True)
        with open(filename, "w") as f:
            json.dump(alerts, f, indent=2)
        print(f"[+] Saved {len(alerts)} alerts to {filename}")

monitor = PastebinMonitor(
    keywords=["mycompany.com", "internal-project", "employee-name"],
)
alerts = monitor.monitor_loop(interval=120, iterations=5)
```

### Step 2: GitHub Gist and Code Search Monitoring

```python
class GitHubSecretMonitor:
    def __init__(self, github_token, org_keywords):
        self.token = github_token
        self.keywords = org_keywords
        self.headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json",
        }

    def search_code(self, query, per_page=30):
        """Search GitHub code for leaked secrets."""
        url = "https://api.github.com/search/code"
        params = {"q": query, "per_page": per_page}
        resp = requests.get(url, headers=self.headers, params=params)
        if resp.status_code == 200:
            results = resp.json().get("items", [])
            print(f"[+] GitHub code search: {len(results)} results for '{query}'")
            return results
        return []

    def search_gists(self, keyword):
        """Search public Gists for sensitive data."""
        url = "https://api.github.com/gists/public"
        params = {"per_page": 100}
        resp = requests.get(url, headers=self.headers, params=params)
        matches = []
        if resp.status_code == 200:
            gists = resp.json()
            for gist in gists:
                description = (gist.get("description") or "").lower()
                files = gist.get("files", {})
                for filename, file_info in files.items():
                    if keyword.lower() in description or keyword.lower() in filename.lower():
                        matches.append({
                            "gist_id": gist["id"],
                            "description": gist.get("description", ""),
                            "filename": filename,
                            "url": gist["html_url"],
                            "created_at": gist["created_at"],
                        })
        return matches

    def monitor_org_secrets(self, org_domain):
        """Monitor for organization secrets leaked on GitHub."""
        queries = [
            f'"{org_domain}" password',
            f'"{org_domain}" api_key',
            f'"{org_domain}" secret',
            f'"{org_domain}" token',
            f'"{org_domain}" credentials',
        ]
        all_findings = []
        for query in queries:
            results = self.search_code(query)
            for result in results:
                all_findings.append({
                    "query": query,
                    "repo": result.get("repository", {}).get("full_name", ""),
                    "path": result.get("path", ""),
                    "url": result.get("html_url", ""),
                    "score": result.get("score", 0),
                })
            time.sleep(10)  # GitHub rate limiting
        return all_findings

gh_monitor = GitHubSecretMonitor("YOUR_GITHUB_TOKEN", ["mycompany.com"])
findings = gh_monitor.monitor_org_secrets("mycompany.com")
```

### Step 3: Alert and Incident Response Integration

```python
def generate_credential_leak_alert(alert_data):
    """Generate incident alert for credential leak detection."""
    alert = {
        "title": f"Credential Leak Detected - {alert_data.get('severity', 'unknown').upper()}",
        "source": alert_data.get("url", ""),
        "detected_at": alert_data.get("detected_at", ""),
        "severity": alert_data.get("severity", "medium"),
        "summary": f"Paste containing organization keywords and credentials found",
        "keyword_matches": alert_data.get("findings", {}).get("keyword_matches", []),
        "credential_types": list(alert_data.get("findings", {}).get("credential_matches", {}).keys()),
        "recommended_actions": [
            "Verify if leaked credentials are valid",
            "Force password reset for affected accounts",
            "Rotate exposed API keys and tokens",
            "Check access logs for unauthorized usage",
            "Report paste for takedown",
            "Update monitoring keywords if new patterns found",
        ],
    }
    return alert
```

## Validation Criteria

- Pastebin Scraping API queried successfully with rate limiting
- Credential patterns detected (email:password, API keys, private keys)
- Organization-specific keywords matched with context
- GitHub code search identifies exposed secrets
- Alerts generated with severity classification
- Integration with incident response workflow

## References

- [Authentic8: Pastebin for CTI Research](https://www.authentic8.com/blog/what-is-pastebin-cyberthreat-intelligence)
- [PasteHunter GitHub](https://github.com/dibsy/pastehunter)
- [Scavenger Credential Crawler](https://github.com/rndinfosecguy/Scavenger)
- [Bitdefender: Credentials on Pastebin](https://www.bitdefender.com/en-us/blog/hotforsecurity/more-than-300000-user-credentials-posted-on-pastebin-over-the-last-year)
- [zSecurity: Pastebin Monitoring](https://zsecurity.org/glossary/pastebin-monitoring/)
- [SecurityBoulevard: Need to Monitor Paste Sites](https://securityboulevard.com/2019/11/orvis-data-leak-and-the-need-to-monitor-paste-sites/)
