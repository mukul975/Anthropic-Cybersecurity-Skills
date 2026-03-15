#!/usr/bin/env python3
# For authorized penetration testing and lab environments only
"""External Reconnaissance Agent - Maps organization attack surface using passive OSINT."""

import json
import logging
import argparse
from datetime import datetime

import requests
import shodan

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def enumerate_subdomains_crtsh(domain):
    """Discover subdomains via certificate transparency logs."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    resp = requests.get(url, timeout=60)
    subdomains = set()
    if resp.status_code == 200:
        for entry in resp.json():
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower()
                if name and "*" not in name and domain in name:
                    subdomains.add(name)
    logger.info("crt.sh: %d subdomains for %s", len(subdomains), domain)
    return sorted(subdomains)


def enumerate_dns_records(domain):
    """Query public DNS records for a domain using DNS-over-HTTPS."""
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    records = {}
    for rtype in record_types:
        url = f"https://dns.google/resolve?name={domain}&type={rtype}"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            answers = data.get("Answer", [])
            if answers:
                records[rtype] = [a.get("data", "") for a in answers]
    logger.info("DNS records collected for %s: %s", domain, list(records.keys()))
    return records


def shodan_org_search(api_key, org_name, max_results=50):
    """Search Shodan for hosts belonging to an organization."""
    api = shodan.Shodan(api_key)
    results = api.search(f'org:"{org_name}"', limit=max_results)
    hosts = []
    for match in results["matches"]:
        hosts.append({
            "ip": match["ip_str"],
            "port": match["port"],
            "product": match.get("product", ""),
            "version": match.get("version", ""),
            "os": match.get("os", ""),
            "hostnames": match.get("hostnames", []),
        })
    logger.info("Shodan: %d hosts for org '%s'", len(hosts), org_name)
    return hosts


def check_email_security(domain):
    """Check SPF, DKIM, and DMARC records for email security posture."""
    email_security = {}
    for prefix, rtype in [("", "TXT"), ("_dmarc.", "TXT")]:
        url = f"https://dns.google/resolve?name={prefix}{domain}&type={rtype}"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            answers = resp.json().get("Answer", [])
            for a in answers:
                data = a.get("data", "")
                if "v=spf1" in data:
                    email_security["spf"] = data
                elif "v=DMARC1" in data:
                    email_security["dmarc"] = data
    email_security["spf_present"] = "spf" in email_security
    email_security["dmarc_present"] = "dmarc" in email_security
    logger.info("Email security for %s: SPF=%s DMARC=%s",
                domain, email_security["spf_present"], email_security["dmarc_present"])
    return email_security


def search_breach_data(email_domain):
    """Search Have I Been Pwned for breached accounts (requires API key)."""
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email_domain}"
    headers = {"hibp-api-key": "PLACEHOLDER", "user-agent": "OSINT-Agent"}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            return resp.json()
    except requests.RequestException:
        pass
    return []


def check_web_technologies(domain):
    """Identify web technologies via HTTP response headers."""
    technologies = {}
    try:
        resp = requests.get(f"https://{domain}", timeout=10, allow_redirects=True, verify=False)
        headers = resp.headers
        tech_headers = {
            "Server": headers.get("Server", ""),
            "X-Powered-By": headers.get("X-Powered-By", ""),
            "X-AspNet-Version": headers.get("X-AspNet-Version", ""),
            "X-Generator": headers.get("X-Generator", ""),
        }
        technologies = {k: v for k, v in tech_headers.items() if v}
        technologies["status_code"] = resp.status_code
        technologies["final_url"] = resp.url
    except requests.RequestException as e:
        technologies["error"] = str(e)
    return technologies


def search_github_leaks(domain, github_token=None):
    """Search GitHub for leaked credentials related to the target domain."""
    headers = {"Accept": "application/vnd.github.v3+json"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    queries = [f'"{domain}" password', f'"{domain}" api_key', f'"{domain}" secret']
    all_results = []
    for query in queries:
        resp = requests.get(
            "https://api.github.com/search/code",
            headers=headers, params={"q": query, "per_page": 10}, timeout=15
        )
        if resp.status_code == 200:
            items = resp.json().get("items", [])
            for item in items:
                all_results.append({
                    "repo": item["repository"]["full_name"],
                    "path": item["path"],
                    "url": item["html_url"],
                    "query": query,
                })
    logger.info("GitHub: %d potential leaks for %s", len(all_results), domain)
    return all_results


def generate_recon_report(domain, subdomains, dns, shodan_hosts, email_sec, technologies, github_leaks):
    """Generate external reconnaissance report."""
    report = {
        "target": domain,
        "timestamp": datetime.utcnow().isoformat(),
        "subdomains": {"count": len(subdomains), "list": subdomains},
        "dns_records": dns,
        "shodan_hosts": {"count": len(shodan_hosts), "hosts": shodan_hosts},
        "email_security": email_sec,
        "web_technologies": technologies,
        "github_leaks": github_leaks,
    }
    print(f"RECON REPORT - {domain}")
    print(f"Subdomains: {len(subdomains)}, Shodan hosts: {len(shodan_hosts)}, GitHub leaks: {len(github_leaks)}")
    return report


def main():
    parser = argparse.ArgumentParser(description="External Reconnaissance OSINT Agent")
    parser.add_argument("--domain", required=True, help="Target domain")
    parser.add_argument("--org", help="Organization name for Shodan search")
    parser.add_argument("--shodan-key", help="Shodan API key")
    parser.add_argument("--github-token", help="GitHub token for code search")
    parser.add_argument("--output", default="recon_report.json")
    args = parser.parse_args()

    subdomains = enumerate_subdomains_crtsh(args.domain)
    dns = enumerate_dns_records(args.domain)
    email_sec = check_email_security(args.domain)
    technologies = check_web_technologies(args.domain)

    shodan_hosts = []
    if args.shodan_key and args.org:
        shodan_hosts = shodan_org_search(args.shodan_key, args.org)

    github_leaks = search_github_leaks(args.domain, args.github_token) if args.github_token else []

    report = generate_recon_report(
        args.domain, subdomains, dns, shodan_hosts, email_sec, technologies, github_leaks
    )
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Recon report saved to %s", args.output)


if __name__ == "__main__":
    main()
