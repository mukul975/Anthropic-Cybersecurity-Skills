#!/usr/bin/env python3
"""Agent for analyzing Certificate Transparency logs for phishing detection."""

import os
import json
import argparse
from datetime import datetime

import requests
from pycrtsh import Crtsh


def search_certificates(domain, include_expired=False):
    """Search crt.sh for certificates matching a domain."""
    c = Crtsh()
    certs = c.search(domain)
    if not include_expired:
        now = datetime.utcnow()
        certs = [cert for cert in certs if cert.get("not_after")
                 and datetime.strptime(str(cert["not_after"]), "%Y-%m-%dT%H:%M:%S") > now]
    return certs


def get_certificate_details(cert_id):
    """Get full certificate details from crt.sh by ID."""
    c = Crtsh()
    return c.get(cert_id, type="id")


def search_crtsh_api(domain):
    """Query crt.sh REST API directly for certificate records."""
    url = f"https://crt.sh/?q={domain}&output=json"
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp.json()


def levenshtein_distance(s1, s2):
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def detect_typosquatting(target_domain, ct_records, max_distance=3):
    """Detect typosquatting domains using Levenshtein distance."""
    base = target_domain.split(".")[0]
    suspicious = []
    seen = set()
    for record in ct_records:
        domain = record.get("common_name", "") or record.get("name_value", "")
        if not domain or domain in seen:
            continue
        seen.add(domain)
        candidate_base = domain.split(".")[0].lstrip("*").lstrip(".")
        if candidate_base == base:
            continue
        dist = levenshtein_distance(base, candidate_base)
        if 0 < dist <= max_distance:
            suspicious.append({
                "domain": domain,
                "distance": dist,
                "issuer": record.get("issuer_name", ""),
                "not_before": record.get("not_before", ""),
                "not_after": record.get("not_after", ""),
            })
    return sorted(suspicious, key=lambda x: x["distance"])


def detect_unauthorized_cas(ct_records, allowed_cas):
    """Find certificates issued by unauthorized Certificate Authorities."""
    unauthorized = []
    for record in ct_records:
        issuer = record.get("issuer_name", "")
        if issuer and not any(ca.lower() in issuer.lower() for ca in allowed_cas):
            unauthorized.append({
                "domain": record.get("common_name", ""),
                "issuer": issuer,
                "not_before": record.get("not_before", ""),
                "cert_id": record.get("id"),
            })
    return unauthorized


def monitor_new_certificates(domain, hours_back=24):
    """Find certificates issued in the last N hours."""
    records = search_crtsh_api(f"%.{domain}")
    cutoff = datetime.utcnow().timestamp() - (hours_back * 3600)
    recent = []
    for r in records:
        not_before = r.get("not_before", "")
        if not_before:
            try:
                cert_time = datetime.strptime(not_before, "%Y-%m-%dT%H:%M:%S")
                if cert_time.timestamp() > cutoff:
                    recent.append({
                        "domain": r.get("common_name", ""),
                        "issuer": r.get("issuer_name", ""),
                        "not_before": not_before,
                        "name_value": r.get("name_value", ""),
                    })
            except ValueError:
                continue
    return recent


def find_wildcard_certificates(ct_records):
    """Identify wildcard certificates that could cover many subdomains."""
    wildcards = []
    for r in ct_records:
        name = r.get("common_name", "") or r.get("name_value", "")
        if name.startswith("*."):
            wildcards.append({
                "domain": name,
                "issuer": r.get("issuer_name", ""),
                "not_before": r.get("not_before", ""),
                "not_after": r.get("not_after", ""),
            })
    return wildcards


def main():
    parser = argparse.ArgumentParser(description="Certificate Transparency Analysis Agent")
    parser.add_argument("--domain", required=True, help="Target domain to monitor")
    parser.add_argument("--allowed-cas", nargs="*", default=["Let's Encrypt", "DigiCert",
                        "Sectigo", "Amazon", "Google Trust Services"])
    parser.add_argument("--output", default="ct_report.json")
    parser.add_argument("--action", choices=[
        "search", "typosquat", "unauthorized_ca", "monitor", "full_scan"
    ], default="full_scan")
    args = parser.parse_args()

    report = {"domain": args.domain, "generated_at": datetime.utcnow().isoformat(),
              "findings": {}}

    ct_records = search_crtsh_api(f"%.{args.domain}")
    report["findings"]["total_certificates"] = len(ct_records)
    print(f"[+] Found {len(ct_records)} certificates for {args.domain}")

    if args.action in ("typosquat", "full_scan"):
        typos = detect_typosquatting(args.domain, ct_records)
        report["findings"]["typosquatting"] = typos
        print(f"[+] Typosquatting domains: {len(typos)}")

    if args.action in ("unauthorized_ca", "full_scan"):
        unauth = detect_unauthorized_cas(ct_records, args.allowed_cas)
        report["findings"]["unauthorized_cas"] = unauth[:50]
        print(f"[+] Unauthorized CA certs: {len(unauth)}")

    if args.action in ("monitor", "full_scan"):
        recent = monitor_new_certificates(args.domain)
        report["findings"]["recent_24h"] = recent
        print(f"[+] Certificates issued in last 24h: {len(recent)}")

    wildcards = find_wildcard_certificates(ct_records)
    report["findings"]["wildcard_certs"] = wildcards
    print(f"[+] Wildcard certificates: {len(wildcards)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
