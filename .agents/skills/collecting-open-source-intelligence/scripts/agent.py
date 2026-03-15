#!/usr/bin/env python3
# For authorized penetration testing and lab environments only
"""OSINT Collection Agent - Gathers open-source intelligence on targets using Shodan and crt.sh."""

import json
import logging
import argparse
from datetime import datetime

import requests
import shodan

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def search_shodan(api_key, query, max_results=100):
    """Search Shodan for hosts matching a query."""
    api = shodan.Shodan(api_key)
    results = api.search(query, limit=max_results)
    hosts = []
    for match in results["matches"]:
        hosts.append({
            "ip": match["ip_str"],
            "port": match["port"],
            "org": match.get("org", ""),
            "os": match.get("os", ""),
            "hostnames": match.get("hostnames", []),
            "product": match.get("product", ""),
            "version": match.get("version", ""),
            "country": match.get("location", {}).get("country_name", ""),
            "ssl_subject": match.get("ssl", {}).get("cert", {}).get("subject", {}),
        })
    logger.info("Shodan returned %d results for query: %s", len(hosts), query)
    return hosts


def shodan_host_lookup(api_key, ip_address):
    """Lookup a specific host on Shodan for detailed information."""
    api = shodan.Shodan(api_key)
    host = api.host(ip_address)
    return {
        "ip": host["ip_str"],
        "org": host.get("org", ""),
        "os": host.get("os", ""),
        "ports": host.get("ports", []),
        "vulns": host.get("vulns", []),
        "hostnames": host.get("hostnames", []),
        "country": host.get("country_name", ""),
        "city": host.get("city", ""),
        "asn": host.get("asn", ""),
    }


def query_crtsh(domain):
    """Query certificate transparency logs via crt.sh for subdomain discovery."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    resp = requests.get(url, timeout=30)
    if resp.status_code != 200:
        logger.warning("crt.sh query failed for %s: %d", domain, resp.status_code)
        return []
    entries = resp.json()
    subdomains = set()
    for entry in entries:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name and "*" not in name:
                subdomains.add(name)
    logger.info("crt.sh found %d unique subdomains for %s", len(subdomains), domain)
    return sorted(subdomains)


def whois_lookup(domain):
    """Perform WHOIS lookup via RDAP (Registration Data Access Protocol)."""
    url = f"https://rdap.org/domain/{domain}"
    resp = requests.get(url, timeout=30)
    if resp.status_code == 200:
        data = resp.json()
        return {
            "domain": domain,
            "status": data.get("status", []),
            "nameservers": [ns.get("ldhName", "") for ns in data.get("nameservers", [])],
            "events": [
                {"action": e["eventAction"], "date": e["eventDate"]}
                for e in data.get("events", [])
            ],
        }
    return {"domain": domain, "error": resp.status_code}


def query_securitytrails(api_key, domain):
    """Query SecurityTrails API for DNS history."""
    url = f"https://api.securitytrails.com/v1/domain/{domain}"
    headers = {"apikey": api_key}
    resp = requests.get(url, headers=headers, timeout=30)
    if resp.status_code == 200:
        data = resp.json()
        return {
            "domain": domain,
            "current_dns": data.get("current_dns", {}),
            "alexa_rank": data.get("alexa_rank"),
            "hostname": data.get("hostname"),
        }
    return {"domain": domain, "error": resp.status_code}


def search_github_exposure(query, github_token=None):
    """Search GitHub for exposed credentials or sensitive data."""
    headers = {"Accept": "application/vnd.github.v3+json"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    url = "https://api.github.com/search/code"
    resp = requests.get(url, headers=headers, params={"q": query, "per_page": 20}, timeout=30)
    if resp.status_code == 200:
        items = resp.json().get("items", [])
        results = []
        for item in items:
            results.append({
                "repo": item["repository"]["full_name"],
                "path": item["path"],
                "url": item["html_url"],
            })
        logger.info("GitHub search found %d results for: %s", len(results), query)
        return results
    return []


def generate_osint_report(domain, subdomains, shodan_results, whois_data, github_results):
    """Generate a consolidated OSINT report."""
    report = {
        "target": domain,
        "timestamp": datetime.utcnow().isoformat(),
        "subdomains": subdomains,
        "subdomain_count": len(subdomains),
        "shodan_hosts": shodan_results,
        "whois": whois_data,
        "github_exposure": github_results,
    }
    lines = [
        f"OSINT REPORT - {domain}",
        "=" * 40,
        f"Subdomains discovered: {len(subdomains)}",
        f"Shodan hosts found: {len(shodan_results)}",
        f"GitHub exposures: {len(github_results)}",
    ]
    print("\n".join(lines))
    return report


def main():
    parser = argparse.ArgumentParser(description="OSINT Collection Agent")
    parser.add_argument("--domain", required=True, help="Target domain for OSINT")
    parser.add_argument("--shodan-key", help="Shodan API key")
    parser.add_argument("--shodan-query", help="Custom Shodan search query")
    parser.add_argument("--github-token", help="GitHub personal access token")
    parser.add_argument("--output", default="osint_report.json")
    args = parser.parse_args()

    subdomains = query_crtsh(args.domain)
    whois_data = whois_lookup(args.domain)

    shodan_results = []
    if args.shodan_key:
        query = args.shodan_query or f"hostname:{args.domain}"
        shodan_results = search_shodan(args.shodan_key, query)

    github_results = []
    if args.github_token:
        github_results = search_github_exposure(
            f'"{args.domain}" password OR secret OR api_key', args.github_token
        )

    report = generate_osint_report(
        args.domain, subdomains, shodan_results, whois_data, github_results
    )
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("OSINT report saved to %s", args.output)


if __name__ == "__main__":
    main()
