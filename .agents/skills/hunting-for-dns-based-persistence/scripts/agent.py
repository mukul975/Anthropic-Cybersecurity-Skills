#!/usr/bin/env python3
"""DNS Persistence Hunting Agent - detects DNS hijacking, dangling CNAMEs, and unauthorized zone changes."""

import json
import argparse
import logging
import requests
import subprocess
import socket
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DANGLING_CNAME_SERVICES = [
    "s3.amazonaws.com", "cloudfront.net", "azurewebsites.net", "herokuapp.com",
    "github.io", "pantheonsite.io", "readme.io", "surge.sh",
    "unbouncepages.com", "wordpress.com", "shopify.com",
]


def query_securitytrails(domain, api_key):
    """Query SecurityTrails API for passive DNS history."""
    headers = {"APIKEY": api_key, "Content-Type": "application/json"}
    url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()


def get_subdomains(domain, api_key):
    """Enumerate subdomains via SecurityTrails API."""
    headers = {"APIKEY": api_key}
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return [f"{sub}.{domain}" for sub in data.get("subdomains", [])]


def resolve_record(hostname, record_type="A"):
    """Resolve DNS record using dig command."""
    cmd = ["dig", "+short", record_type, hostname]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    return [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]


def detect_dangling_cnames(subdomains):
    """Detect CNAME records pointing to decommissioned services (subdomain takeover risk)."""
    findings = []
    for subdomain in subdomains:
        cname_records = resolve_record(subdomain, "CNAME")
        for cname in cname_records:
            for service in DANGLING_CNAME_SERVICES:
                if cname.rstrip(".").endswith(service):
                    a_records = resolve_record(cname, "A")
                    if not a_records:
                        findings.append({
                            "subdomain": subdomain, "cname": cname.rstrip("."),
                            "service": service, "resolves": False,
                            "severity": "critical",
                            "issue": "Dangling CNAME - subdomain takeover possible",
                            "mitre": "T1584.001",
                        })
    return findings


def detect_wildcard_abuse(domain):
    """Check for wildcard DNS records that resolve all subdomains."""
    findings = []
    random_sub = f"randomtestxyz123.{domain}"
    results = resolve_record(random_sub, "A")
    if results:
        findings.append({
            "domain": domain, "wildcard_target": results,
            "severity": "high",
            "issue": "Wildcard DNS record detected - all subdomains resolve",
            "detail": f"Random subdomain {random_sub} resolves to {results}",
        })
    return findings


def check_ns_delegation(domain):
    """Verify NS records haven't been modified to point to unauthorized servers."""
    findings = []
    ns_records = resolve_record(domain, "NS")
    known_providers = ["awsdns", "azure-dns", "cloudflare", "google", "route53", "ns1."]
    for ns in ns_records:
        ns_lower = ns.lower().rstrip(".")
        is_known = any(provider in ns_lower for provider in known_providers)
        if not is_known:
            findings.append({
                "domain": domain, "nameserver": ns_lower,
                "severity": "high",
                "issue": "NS record points to unrecognized nameserver",
                "recommendation": "Verify this is an authorized nameserver for the domain",
            })
    return findings


def analyze_dns_history(domain, api_key):
    """Analyze historical DNS changes for signs of hijacking."""
    findings = []
    try:
        history = query_securitytrails(domain, api_key)
        records = history.get("records", [])
        if len(records) >= 2:
            for i in range(1, len(records)):
                prev_ips = set(v.get("ip", "") for v in records[i - 1].get("values", []))
                curr_ips = set(v.get("ip", "") for v in records[i].get("values", []))
                changed = curr_ips - prev_ips
                if changed:
                    findings.append({
                        "domain": domain,
                        "first_seen": records[i].get("first_seen", ""),
                        "new_ips": list(changed),
                        "severity": "medium",
                        "issue": f"DNS A record changed: added {changed}",
                    })
    except requests.RequestException as e:
        logger.warning("SecurityTrails query failed: %s", e)
    return findings


def generate_report(domain, dangling, wildcard, ns_findings, history_findings):
    all_findings = dangling + wildcard + ns_findings + history_findings
    critical = sum(1 for f in all_findings if f.get("severity") == "critical")
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "target_domain": domain,
        "dangling_cnames": dangling,
        "wildcard_abuse": wildcard,
        "ns_delegation_issues": ns_findings,
        "historical_anomalies": history_findings,
        "total_findings": len(all_findings),
        "critical_findings": critical,
        "risk_level": "critical" if critical > 0 else "high" if all_findings else "low",
    }


def main():
    parser = argparse.ArgumentParser(description="DNS Persistence Hunting Agent")
    parser.add_argument("--domain", required=True, help="Target domain to hunt")
    parser.add_argument("--api-key", required=True, help="SecurityTrails API key")
    parser.add_argument("--output", default="dns_persistence_report.json")
    args = parser.parse_args()

    subdomains = get_subdomains(args.domain, args.api_key)
    logger.info("Discovered %d subdomains for %s", len(subdomains), args.domain)
    dangling = detect_dangling_cnames(subdomains[:200])
    wildcard = detect_wildcard_abuse(args.domain)
    ns_findings = check_ns_delegation(args.domain)
    history_findings = analyze_dns_history(args.domain, args.api_key)
    report = generate_report(args.domain, dangling, wildcard, ns_findings, history_findings)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("DNS hunt: %s - %d findings (%d critical), %d subdomains checked",
                args.domain, report["total_findings"], report["critical_findings"], len(subdomains))
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
