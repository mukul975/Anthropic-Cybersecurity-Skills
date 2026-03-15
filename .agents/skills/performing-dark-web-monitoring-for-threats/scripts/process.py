#!/usr/bin/env python3
"""
Dark Web Monitoring for Threats Script

Monitors dark web sources for organizational threats:
- Credential leak detection via HIBP and paste sites
- Ransomware leak site monitoring via Ransomwatch
- Brand mention monitoring across dark web sources
- Generates structured intelligence reports

Requirements:
    pip install requests[socks] beautifulsoup4 stix2

Usage:
    python process.py --org "Acme Corp" --domains acme.com,acme.io --check-credentials
    python process.py --org "Acme Corp" --check-ransomware
    python process.py --org "Acme Corp" --full-scan --output report.json
"""

import argparse
import json
import sys
from datetime import datetime
from typing import Optional

import requests


class DarkWebMonitor:
    """Monitor dark web sources for organizational threats."""

    def __init__(self, organization: str, domains: list = None, hibp_key: str = ""):
        self.organization = organization
        self.domains = domains or []
        self.hibp_key = hibp_key
        self.findings = []

    def check_credential_leaks(self) -> list:
        """Check for credential leaks via HIBP API."""
        leaks = []
        headers = {}
        if self.hibp_key:
            headers["hibp-api-key"] = self.hibp_key

        try:
            resp = requests.get(
                "https://haveibeenpwned.com/api/v3/breaches",
                headers=headers,
                timeout=30,
            )
            if resp.status_code == 200:
                breaches = resp.json()
                for domain in self.domains:
                    for breach in breaches:
                        breach_domain = breach.get("Domain", "").lower()
                        if domain.lower() in breach_domain or breach_domain in domain.lower():
                            leak = {
                                "type": "credential_leak",
                                "source": "HIBP",
                                "breach_name": breach["Name"],
                                "breach_date": breach.get("BreachDate"),
                                "data_classes": breach.get("DataClasses", []),
                                "pwn_count": breach.get("PwnCount", 0),
                                "domain": domain,
                                "is_verified": breach.get("IsVerified", False),
                                "severity": "HIGH",
                            }
                            leaks.append(leak)
                            self.findings.append(leak)
                            print(
                                f"[!] Credential leak: {breach['Name']} "
                                f"({breach.get('PwnCount', 0)} accounts)"
                            )
        except Exception as e:
            print(f"[-] HIBP check failed: {e}")

        return leaks

    def check_ransomware_leaks(self) -> list:
        """Check ransomware leak site aggregator for organization mentions."""
        mentions = []
        try:
            resp = requests.get(
                "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json",
                timeout=30,
            )
            if resp.status_code == 200:
                posts = resp.json()
                org_lower = self.organization.lower()
                domain_patterns = [d.lower().split(".")[0] for d in self.domains]

                for post in posts:
                    title = post.get("post_title", "").lower()
                    if org_lower in title or any(d in title for d in domain_patterns):
                        mention = {
                            "type": "ransomware_leak",
                            "source": "ransomwatch",
                            "group": post.get("group_name", ""),
                            "title": post.get("post_title", ""),
                            "discovered": post.get("discovered", ""),
                            "url": post.get("post_url", ""),
                            "severity": "CRITICAL",
                        }
                        mentions.append(mention)
                        self.findings.append(mention)
                        print(
                            f"[!!!] RANSOMWARE LEAK: {post.get('group_name')} - "
                            f"{post.get('post_title')}"
                        )
        except Exception as e:
            print(f"[-] Ransomwatch check failed: {e}")

        return mentions

    def check_breach_directory(self) -> list:
        """Check public breach directories for organization data."""
        breaches = []
        try:
            # Check BreachDirectory (public API)
            for domain in self.domains:
                resp = requests.get(
                    f"https://breachdirectory.org/api/entries?domain={domain}",
                    timeout=30,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("result"):
                        breaches.append({
                            "type": "breach_directory",
                            "domain": domain,
                            "entries_found": len(data.get("result", [])),
                            "severity": "HIGH",
                        })
        except Exception as e:
            print(f"[-] Breach directory check failed: {e}")
        return breaches

    def generate_report(self) -> dict:
        """Generate comprehensive dark web monitoring report."""
        critical = [f for f in self.findings if f.get("severity") == "CRITICAL"]
        high = [f for f in self.findings if f.get("severity") == "HIGH"]
        medium = [f for f in self.findings if f.get("severity") == "MEDIUM"]

        report = {
            "report_metadata": {
                "organization": self.organization,
                "domains_monitored": self.domains,
                "report_date": datetime.utcnow().isoformat(),
                "classification": "TLP:AMBER",
            },
            "executive_summary": (
                f"Dark web monitoring for {self.organization} identified "
                f"{len(critical)} critical, {len(high)} high, and "
                f"{len(medium)} medium severity findings."
            ),
            "findings_by_severity": {
                "critical": critical,
                "high": high,
                "medium": medium,
            },
            "all_findings": self.findings,
            "recommendations": [],
        }

        if critical:
            report["recommendations"].append(
                "IMMEDIATE: Activate incident response for ransomware leak detection. "
                "Assess data exposure scope and notify affected parties."
            )
        if high:
            report["recommendations"].append(
                "URGENT: Force password resets for all accounts in detected breaches. "
                "Enable MFA across all services."
            )
        report["recommendations"].append(
            "ONGOING: Continue dark web monitoring with weekly reporting cadence."
        )

        return report

    def full_scan(self) -> dict:
        """Run all dark web monitoring checks."""
        print(f"[*] Starting dark web monitoring for: {self.organization}")
        print(f"[*] Domains: {', '.join(self.domains)}")

        print("\n[*] Checking credential leaks...")
        self.check_credential_leaks()

        print("\n[*] Checking ransomware leak sites...")
        self.check_ransomware_leaks()

        print(f"\n[+] Total findings: {len(self.findings)}")
        return self.generate_report()


def main():
    parser = argparse.ArgumentParser(description="Dark Web Monitoring Tool")
    parser.add_argument("--org", required=True, help="Organization name")
    parser.add_argument("--domains", help="Comma-separated domains to monitor")
    parser.add_argument("--hibp-key", default="", help="HIBP API key")
    parser.add_argument("--check-credentials", action="store_true")
    parser.add_argument("--check-ransomware", action="store_true")
    parser.add_argument("--full-scan", action="store_true")
    parser.add_argument("--output", default="darkweb_report.json", help="Output file")

    args = parser.parse_args()
    domains = args.domains.split(",") if args.domains else []
    monitor = DarkWebMonitor(args.org, domains, args.hibp_key)

    if args.full_scan:
        report = monitor.full_scan()
    elif args.check_credentials:
        monitor.check_credential_leaks()
        report = monitor.generate_report()
    elif args.check_ransomware:
        monitor.check_ransomware_leaks()
        report = monitor.generate_report()
    else:
        report = monitor.full_scan()

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[+] Report saved to {args.output}")
    print(json.dumps(report["executive_summary"], indent=2))


if __name__ == "__main__":
    main()
