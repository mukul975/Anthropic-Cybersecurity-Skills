#!/usr/bin/env python3
"""
DNS Enumeration and Zone Transfer Agent — AUTHORIZED TESTING ONLY
Performs DNS reconnaissance including record enumeration, zone transfer
attempts, and subdomain discovery using dnspython.

WARNING: Only use with explicit written authorization for the target domain.
"""

import json
import sys
from datetime import datetime, timezone

import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype


def enumerate_dns_records(domain: str) -> dict:
    """Enumerate common DNS record types for a domain."""
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA"]
    results = {}

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records = []
            for rdata in answers:
                records.append(str(rdata))
            results[rtype] = records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            results[rtype] = []
        except dns.exception.DNSException:
            results[rtype] = []

    return results


def get_nameservers(domain: str) -> list[str]:
    """Resolve authoritative nameservers for a domain."""
    nameservers = []
    try:
        ns_records = dns.resolver.resolve(domain, "NS")
        for ns in ns_records:
            ns_name = str(ns).rstrip(".")
            try:
                a_records = dns.resolver.resolve(ns_name, "A")
                for a in a_records:
                    nameservers.append({"name": ns_name, "ip": str(a)})
            except dns.exception.DNSException:
                nameservers.append({"name": ns_name, "ip": "unresolved"})
    except dns.exception.DNSException as e:
        nameservers.append({"error": str(e)})

    return nameservers


def attempt_zone_transfer(domain: str, nameservers: list[dict]) -> dict:
    """Attempt AXFR zone transfer against each nameserver."""
    results = {"vulnerable": False, "records": [], "tested_servers": []}

    for ns in nameservers:
        ns_ip = ns.get("ip", "")
        ns_name = ns.get("name", "")
        if ns_ip == "unresolved" or "error" in ns:
            continue

        server_result = {"nameserver": ns_name, "ip": ns_ip, "transfer_allowed": False}

        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
            server_result["transfer_allowed"] = True
            results["vulnerable"] = True

            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        results["records"].append({
                            "name": str(name),
                            "type": dns.rdatatype.to_text(rdataset.rdtype),
                            "ttl": rdataset.ttl,
                            "data": str(rdata),
                        })

        except dns.exception.FormError:
            server_result["error"] = "Transfer refused (FORMERR)"
        except dns.xfr.TransferError:
            server_result["error"] = "Transfer refused"
        except dns.exception.DNSException as e:
            server_result["error"] = str(e)
        except Exception as e:
            server_result["error"] = str(e)

        results["tested_servers"].append(server_result)

    return results


def check_email_security(domain: str) -> dict:
    """Check SPF, DKIM, and DMARC DNS records."""
    security = {"spf": None, "dmarc": None, "dkim_selectors": []}

    try:
        txt_records = dns.resolver.resolve(domain, "TXT")
        for txt in txt_records:
            txt_str = str(txt).strip('"')
            if txt_str.startswith("v=spf1"):
                security["spf"] = txt_str
    except dns.exception.DNSException:
        pass

    try:
        dmarc = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for txt in dmarc:
            txt_str = str(txt).strip('"')
            if "v=DMARC1" in txt_str:
                security["dmarc"] = txt_str
    except dns.exception.DNSException:
        pass

    common_selectors = ["default", "google", "selector1", "selector2", "s1", "s2", "mail", "k1"]
    for selector in common_selectors:
        try:
            dkim = dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            for txt in dkim:
                security["dkim_selectors"].append({
                    "selector": selector,
                    "record": str(txt).strip('"')[:100],
                })
        except dns.exception.DNSException:
            pass

    return security


def brute_force_subdomains(domain: str, wordlist: list[str] = None) -> list[dict]:
    """Brute-force subdomain discovery via DNS resolution."""
    if wordlist is None:
        wordlist = [
            "www", "mail", "ftp", "admin", "api", "dev", "staging",
            "test", "vpn", "portal", "app", "login", "secure",
            "m", "blog", "shop", "cdn", "ns1", "ns2", "mx",
            "remote", "gateway", "intranet", "extranet", "webmail",
            "owa", "autodiscover", "sso", "auth", "git", "ci",
        ]

    found = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    for sub in wordlist:
        fqdn = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(fqdn, "A")
            ips = [str(a) for a in answers]
            found.append({"subdomain": fqdn, "ips": ips, "record_type": "A"})
        except dns.exception.DNSException:
            pass

        try:
            answers = resolver.resolve(fqdn, "CNAME")
            cnames = [str(c) for c in answers]
            found.append({"subdomain": fqdn, "cnames": cnames, "record_type": "CNAME"})
        except dns.exception.DNSException:
            pass

    return found


def generate_report(
    domain: str, records: dict, nameservers: list, zone_transfer: dict,
    email_security: dict, subdomains: list,
) -> str:
    """Generate DNS enumeration report."""
    lines = [
        "DNS ENUMERATION AND ZONE TRANSFER REPORT — AUTHORIZED TESTING ONLY",
        "=" * 65,
        f"Target Domain: {domain}",
        f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "DNS RECORDS:",
    ]
    for rtype, recs in records.items():
        if recs:
            lines.append(f"  {rtype}: {', '.join(recs[:5])}")

    lines.extend([
        "",
        f"NAMESERVERS ({len(nameservers)}):",
    ])
    for ns in nameservers:
        if "error" not in ns:
            lines.append(f"  {ns['name']} ({ns['ip']})")

    vuln = "VULNERABLE" if zone_transfer["vulnerable"] else "NOT VULNERABLE"
    lines.extend([
        "",
        f"ZONE TRANSFER: {vuln}",
        f"  Records Leaked: {len(zone_transfer['records'])}",
    ])

    lines.extend([
        "",
        "EMAIL SECURITY:",
        f"  SPF: {'Present' if email_security['spf'] else 'MISSING'}",
        f"  DMARC: {'Present' if email_security['dmarc'] else 'MISSING'}",
        f"  DKIM Selectors Found: {len(email_security['dkim_selectors'])}",
        "",
        f"SUBDOMAINS DISCOVERED: {len(subdomains)}",
    ])
    for sub in subdomains[:15]:
        ips = sub.get("ips", sub.get("cnames", []))
        lines.append(f"  {sub['subdomain']} -> {', '.join(ips)}")

    return "\n".join(lines)


if __name__ == "__main__":
    print("[!] DNS ENUMERATION — AUTHORIZED TESTING ONLY\n")

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_domain>")
        sys.exit(1)

    domain = sys.argv[1]

    print(f"[*] Enumerating DNS records for {domain}...")
    records = enumerate_dns_records(domain)

    print("[*] Resolving nameservers...")
    nameservers = get_nameservers(domain)

    print("[*] Attempting zone transfer...")
    zone_transfer = attempt_zone_transfer(domain, nameservers)

    print("[*] Checking email security records...")
    email_security = check_email_security(domain)

    print("[*] Brute-forcing subdomains...")
    subdomains = brute_force_subdomains(domain)

    report = generate_report(domain, records, nameservers, zone_transfer, email_security, subdomains)
    print(report)

    output = f"dns_enum_{domain.replace('.', '_')}_{datetime.now(timezone.utc).strftime('%Y%m%d')}.json"
    with open(output, "w") as f:
        json.dump({"records": records, "nameservers": nameservers, "zone_transfer": zone_transfer,
                    "email_security": email_security, "subdomains": subdomains}, f, indent=2)
    print(f"\n[*] Results saved to {output}")
