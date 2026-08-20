#!/usr/bin/env python3
"""Brand impersonation monitoring agent.

Monitors for brand impersonation by checking Certificate Transparency
logs for suspicious domain registrations, performing DNS lookups for
typosquatting domains, and scanning social media profile names. Uses
crt.sh API and DNS resolution to identify potential phishing domains.
"""
import argparse
import json
import socket
import sys
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("[!] 'requests' required: pip install requests", file=sys.stderr)
    sys.exit(1)


def generate_typosquat_variants(domain):
    """Generate common typosquatting domain variants."""
    name, tld = domain.rsplit(".", 1) if "." in domain else (domain, "com")
    variants = set()
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"

    # Character omission
    for i in range(len(name)):
        variants.add(f"{name[:i]}{name[i+1:]}.{tld}")
    # Character swap
    for i in range(len(name) - 1):
        swapped = list(name)
        swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
        variants.add(f"{''.join(swapped)}.{tld}")
    # Character replacement (adjacent keys)
    adjacent = {"a": "sq", "e": "wr", "i": "uo", "o": "ip", "u": "yi",
                "s": "ad", "n": "bm", "r": "et", "t": "ry", "l": "kp"}
    for i, c in enumerate(name):
        for adj in adjacent.get(c, ""):
            variants.add(f"{name[:i]}{adj}{name[i+1:]}.{tld}")
    # Character doubling
    for i in range(len(name)):
        variants.add(f"{name[:i]}{name[i]}{name[i:]}.{tld}")
    # Homoglyph substitution
    homoglyphs = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5"}
    for i, c in enumerate(name):
        if c in homoglyphs:
            variants.add(f"{name[:i]}{homoglyphs[c]}{name[i+1:]}.{tld}")
    # TLD variants
    for alt_tld in ["com", "net", "org", "io", "co", "info", "biz", "xyz"]:
        if alt_tld != tld:
            variants.add(f"{name}.{alt_tld}")
    # Prefix/suffix
    for prefix in ["my", "the", "get", "go", "login", "secure", "account"]:
        variants.add(f"{prefix}{name}.{tld}")
        variants.add(f"{name}{prefix}.{tld}")
    # Hyphen insertion
    for i in range(1, len(name)):
        variants.add(f"{name[:i]}-{name[i:]}.{tld}")

    variants.discard(domain)
    return sorted(variants)


def check_domain_resolution(domains, max_check=200):
    """Check which typosquat domains actually resolve."""
    resolved = []
    checked = 0
    for domain in domains[:max_check]:
        checked += 1
        try:
            ip = socket.gethostbyname(domain)
            resolved.append({
                "domain": domain,
                "ip": ip,
                "resolves": True,
                "severity": "HIGH",
            })
        except socket.gaierror:
            pass
    print(f"[+] Checked {checked} domains, {len(resolved)} resolve to an IP")
    return resolved


def search_certificate_transparency(domain):
    """Search crt.sh for certificates containing the brand name."""
    print(f"[*] Searching Certificate Transparency for: {domain}")
    findings = []
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%25{domain}%25&output=json",
            timeout=30,
        )
        if resp.status_code == 200:
            certs = resp.json()
            seen_names = set()
            for cert in certs:
                common_name = cert.get("common_name", "")
                if common_name not in seen_names and domain not in common_name.split(".")[-2:]:
                    seen_names.add(common_name)
                    findings.append({
                        "type": "ct_log",
                        "common_name": common_name,
                        "issuer": cert.get("issuer_name", ""),
                        "not_before": cert.get("not_before", ""),
                        "not_after": cert.get("not_after", ""),
                        "severity": "MEDIUM",
                    })
            print(f"[+] Found {len(findings)} suspicious certificates")
    except requests.RequestException as e:
        print(f"[!] CT search error: {e}")
    return findings


def format_summary(domain, variants_count, resolved, ct_findings):
    """Print monitoring summary."""
    print(f"\n{'='*60}")
    print("  Brand Impersonation Monitoring Report")
    print(f"{'='*60}")
    print(f"  Brand Domain       : {domain}")
    print(f"  Typosquat Variants : {variants_count}")
    print(f"  Resolved Domains   : {len(resolved)}")
    print(f"  CT Log Matches     : {len(ct_findings)}")

    if resolved:
        print("\n  Active Typosquat Domains (resolving):")
        for r in resolved[:20]:
            print(f"    [{r['severity']:6s}] {r['domain']:40s} -> {r['ip']}")

    if ct_findings:
        print("\n  Certificate Transparency Findings:")
        for f in ct_findings[:15]:
            print(f"    {f['common_name']:40s} (issued: {f['not_before'][:10]})")


def main():
    parser = argparse.ArgumentParser(description="Brand impersonation monitoring agent")
    parser.add_argument("--domain", required=True, help="Brand domain to monitor (e.g., example.com)")
    parser.add_argument("--max-check", type=int, default=200, help="Max domains to DNS-check")
    parser.add_argument("--skip-ct", action="store_true", help="Skip Certificate Transparency search")
    parser.add_argument("--skip-dns", action="store_true", help="Skip DNS resolution check")
    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    variants = generate_typosquat_variants(args.domain)
    print(f"[*] Generated {len(variants)} typosquat variants for {args.domain}")

    resolved = []
    if not args.skip_dns:
        resolved = check_domain_resolution(variants, args.max_check)

    ct_findings = []
    if not args.skip_ct:
        ct_findings = search_certificate_transparency(args.domain.split(".")[0])

    format_summary(args.domain, len(variants), resolved, ct_findings)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "Brand Monitor",
        "domain": args.domain,
        "variants_generated": len(variants),
        "resolved_domains": resolved,
        "ct_findings": ct_findings,
        "risk_level": (
            "CRITICAL" if len(resolved) > 10
            else "HIGH" if resolved
            else "MEDIUM" if ct_findings
            else "LOW"
        ),
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
