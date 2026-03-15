#!/usr/bin/env python3
"""
Threat Actor Infrastructure Tracking Script

Tracks and maps adversary infrastructure using:
- Shodan/Censys for service discovery
- Passive DNS for domain-IP relationships
- Certificate Transparency for certificate monitoring
- WHOIS for registration data pivoting

Requirements:
    pip install shodan requests stix2

Usage:
    python process.py --ip 198.51.100.1 --shodan-key KEY
    python process.py --domain evil.com --ct-search
    python process.py --c2-hunt cobalt-strike --shodan-key KEY
"""

import argparse
import json
import sys
from datetime import datetime
from collections import defaultdict
from typing import Optional

import requests

try:
    import shodan
except ImportError:
    shodan = None


class InfrastructureTracker:
    """Track threat actor infrastructure across multiple data sources."""

    def __init__(self, shodan_key: str = "", securitytrails_key: str = ""):
        self.shodan_api = shodan.Shodan(shodan_key) if shodan and shodan_key else None
        self.st_key = securitytrails_key
        self.findings = {"ips": {}, "domains": {}, "certificates": [], "pivots": []}

    def shodan_host_lookup(self, ip: str) -> Optional[dict]:
        """Look up IP on Shodan."""
        if not self.shodan_api:
            print("[-] Shodan API not configured")
            return None
        try:
            host = self.shodan_api.host(ip)
            result = {
                "ip": ip,
                "org": host.get("org", ""),
                "asn": host.get("asn", ""),
                "isp": host.get("isp", ""),
                "country": host.get("country_name", ""),
                "city": host.get("city", ""),
                "os": host.get("os"),
                "ports": host.get("ports", []),
                "vulns": host.get("vulns", []),
                "hostnames": host.get("hostnames", []),
                "services": [],
            }
            for svc in host.get("data", []):
                service = {
                    "port": svc.get("port"),
                    "transport": svc.get("transport"),
                    "product": svc.get("product", ""),
                    "version": svc.get("version", ""),
                    "banner": svc.get("data", "")[:200],
                }
                ssl = svc.get("ssl", {})
                if ssl:
                    service["jarm"] = ssl.get("jarm", "")
                    service["ja3s"] = ssl.get("ja3s", "")
                    cert = ssl.get("cert", {})
                    if cert:
                        service["cert_subject"] = cert.get("subject", {})
                        service["cert_issuer"] = cert.get("issuer", {})
                        service["cert_expires"] = cert.get("expires", "")
                result["services"].append(service)

            self.findings["ips"][ip] = result
            print(f"[+] Shodan: {ip} - {result['org']} - Ports: {result['ports']}")
            return result
        except Exception as e:
            print(f"[-] Shodan error for {ip}: {e}")
            return None

    def search_c2_servers(self, framework: str, limit: int = 50) -> list:
        """Search for C2 framework servers on Shodan."""
        if not self.shodan_api:
            return []

        queries = {
            "cobalt-strike": 'product:"Cobalt Strike Beacon"',
            "metasploit": 'product:"Metasploit"',
            "sliver": 'ssl:"multiplayer" ssl:"operators"',
            "havoc": 'http.html_hash:-1472705893',
            "brute-ratel": 'http.html_hash:"-1957161625"',
        }

        query = queries.get(framework.lower(), framework)
        try:
            results = self.shodan_api.search(query, limit=limit)
            servers = []
            for match in results.get("matches", []):
                servers.append({
                    "ip": match["ip_str"],
                    "port": match["port"],
                    "org": match.get("org", ""),
                    "asn": match.get("asn", ""),
                    "country": match.get("location", {}).get("country_name", ""),
                    "timestamp": match.get("timestamp", ""),
                })
            print(f"[+] Found {len(servers)} {framework} servers")
            return servers
        except Exception as e:
            print(f"[-] C2 search error: {e}")
            return []

    def ct_log_search(self, domain: str) -> Optional[dict]:
        """Search Certificate Transparency logs via crt.sh."""
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json", timeout=30
            )
            if resp.status_code == 200:
                certs = resp.json()
                unique_domains = set()
                for cert in certs:
                    for name in cert.get("name_value", "").split("\n"):
                        name = name.strip()
                        if name:
                            unique_domains.add(name)

                result = {
                    "domain": domain,
                    "total_certs": len(certs),
                    "unique_domains": sorted(unique_domains),
                    "recent_certs": [
                        {
                            "common_name": c.get("common_name", ""),
                            "issuer": c.get("issuer_name", ""),
                            "not_before": c.get("not_before", ""),
                            "not_after": c.get("not_after", ""),
                        }
                        for c in certs[:20]
                    ],
                }
                self.findings["certificates"].append(result)
                print(f"[+] CT: {domain} - {len(certs)} certs, {len(unique_domains)} domains")
                return result
        except Exception as e:
            print(f"[-] CT search error: {e}")
        return None

    def passive_dns_securitytrails(self, domain: str) -> Optional[dict]:
        """Query SecurityTrails passive DNS."""
        if not self.st_key:
            print("[-] SecurityTrails API key not configured")
            return None
        try:
            resp = requests.get(
                f"https://api.securitytrails.com/v1/domain/{domain}",
                headers={"APIKEY": self.st_key},
                timeout=30,
            )
            if resp.status_code == 200:
                data = resp.json()
                dns = data.get("current_dns", {})
                result = {
                    "domain": domain,
                    "a_records": [
                        r.get("ip") for r in dns.get("a", {}).get("values", [])
                    ],
                    "mx_records": [
                        r.get("host") for r in dns.get("mx", {}).get("values", [])
                    ],
                    "ns_records": [
                        r.get("nameserver") for r in dns.get("ns", {}).get("values", [])
                    ],
                    "alexa_rank": data.get("alexa_rank"),
                }
                self.findings["domains"][domain] = result
                print(f"[+] pDNS: {domain} -> {result['a_records']}")
                return result
        except Exception as e:
            print(f"[-] SecurityTrails error: {e}")
        return None

    def pivot_from_ip(self, ip: str) -> dict:
        """Perform full infrastructure pivot from an IP address."""
        pivot_results = {"origin_ip": ip, "discovered": []}

        # Shodan lookup
        shodan_data = self.shodan_host_lookup(ip)
        if shodan_data:
            for hostname in shodan_data.get("hostnames", []):
                pivot_results["discovered"].append({
                    "type": "domain",
                    "value": hostname,
                    "source": "shodan_hostname",
                })

            for svc in shodan_data.get("services", []):
                cert_cn = svc.get("cert_subject", {}).get("CN", "")
                if cert_cn and cert_cn != ip:
                    pivot_results["discovered"].append({
                        "type": "domain",
                        "value": cert_cn,
                        "source": "ssl_certificate",
                    })

        # CT search for discovered domains
        seen_domains = set()
        for item in pivot_results["discovered"]:
            if item["type"] == "domain":
                domain = item["value"]
                if domain not in seen_domains:
                    seen_domains.add(domain)
                    ct = self.ct_log_search(domain)
                    if ct:
                        for d in ct.get("unique_domains", []):
                            if d not in seen_domains:
                                pivot_results["discovered"].append({
                                    "type": "domain",
                                    "value": d,
                                    "source": "ct_log",
                                })

        self.findings["pivots"].append(pivot_results)
        return pivot_results

    def generate_report(self) -> dict:
        """Generate infrastructure tracking report."""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "summary": {
                "ips_tracked": len(self.findings["ips"]),
                "domains_tracked": len(self.findings["domains"]),
                "certificates_found": sum(
                    c.get("total_certs", 0) for c in self.findings["certificates"]
                ),
                "pivots_performed": len(self.findings["pivots"]),
            },
            "findings": self.findings,
        }


def main():
    parser = argparse.ArgumentParser(description="Infrastructure Tracking Tool")
    parser.add_argument("--ip", help="IP address to investigate")
    parser.add_argument("--domain", help="Domain to investigate")
    parser.add_argument("--c2-hunt", help="C2 framework to hunt")
    parser.add_argument("--ct-search", action="store_true", help="Search CT logs")
    parser.add_argument("--pivot", action="store_true", help="Full pivot from IP")
    parser.add_argument("--shodan-key", default="", help="Shodan API key")
    parser.add_argument("--st-key", default="", help="SecurityTrails API key")
    parser.add_argument("--output", default="infra_report.json", help="Output file")

    args = parser.parse_args()
    tracker = InfrastructureTracker(args.shodan_key, args.st_key)

    if args.ip and args.pivot:
        results = tracker.pivot_from_ip(args.ip)
        print(json.dumps(results, indent=2))
    elif args.ip:
        tracker.shodan_host_lookup(args.ip)
    elif args.domain and args.ct_search:
        tracker.ct_log_search(args.domain)
    elif args.domain:
        tracker.passive_dns_securitytrails(args.domain)
    elif args.c2_hunt:
        servers = tracker.search_c2_servers(args.c2_hunt)
        print(json.dumps(servers, indent=2))

    report = tracker.generate_report()
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
