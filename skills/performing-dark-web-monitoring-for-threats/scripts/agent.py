#!/usr/bin/env python3
"""Dark web threat monitoring agent.

Monitors for organization-specific threats on the dark web by checking
breach databases (Have I Been Pwned API), paste sites, and public
threat intelligence feeds for leaked credentials, exposed data, and
mentions of organizational domains.
"""
import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("[!] 'requests' required: pip install requests", file=sys.stderr)
    sys.exit(1)


def check_hibp_breaches(domain, api_key=None):
    """Check Have I Been Pwned for breaches involving a domain."""
    findings = []
    print(f"[*] Checking HIBP breaches for domain: {domain}")
    headers = {"user-agent": "dark-web-monitor-agent"}
    if api_key:
        headers["hibp-api-key"] = api_key
    try:
        resp = requests.get(
            "https://haveibeenpwned.com/api/v3/breaches",
            headers=headers, timeout=15,
        )
        resp.raise_for_status()
        breaches = resp.json()
        domain_breaches = [b for b in breaches if domain.lower() in b.get("Domain", "").lower()]
        for breach in domain_breaches:
            findings.append({
                "type": "breach",
                "source": "HIBP",
                "name": breach.get("Name", ""),
                "domain": breach.get("Domain", ""),
                "breach_date": breach.get("BreachDate", ""),
                "added_date": breach.get("AddedDate", ""),
                "pwn_count": breach.get("PwnCount", 0),
                "data_classes": breach.get("DataClasses", []),
                "is_verified": breach.get("IsVerified", False),
                "severity": "CRITICAL" if breach.get("PwnCount", 0) > 10000 else "HIGH",
            })
        print(f"[+] Found {len(domain_breaches)} breaches for {domain}")
    except requests.RequestException as e:
        print(f"[!] HIBP API error: {e}")
    return findings


def check_hibp_email(email, api_key):
    """Check if a specific email appears in known breaches."""
    if not api_key:
        return []
    findings = []
    headers = {"hibp-api-key": api_key, "user-agent": "dark-web-monitor-agent"}
    try:
        resp = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers=headers, params={"truncateResponse": "false"}, timeout=15,
        )
        if resp.status_code == 200:
            breaches = resp.json()
            for breach in breaches:
                findings.append({
                    "type": "email_breach",
                    "email": email,
                    "breach": breach.get("Name", ""),
                    "breach_date": breach.get("BreachDate", ""),
                    "data_classes": breach.get("DataClasses", []),
                    "severity": "HIGH",
                })
        elif resp.status_code == 404:
            pass  # Not found in any breaches
        time.sleep(1.5)  # HIBP rate limit
    except requests.RequestException:
        pass
    return findings


def check_hibp_password(password):
    """Check if a password appears in known breaches using k-anonymity."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    try:
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=10,
        )
        resp.raise_for_status()
        for line in resp.text.splitlines():
            parts = line.split(":")
            if parts[0] == suffix:
                count = int(parts[1])
                return {"compromised": True, "count": count, "severity": "CRITICAL"}
        return {"compromised": False, "count": 0, "severity": "INFO"}
    except requests.RequestException:
        return {"compromised": None, "error": "API unavailable"}


def check_paste_dumps(domain, api_key=None):
    """Check for organization mentions in paste sites via HIBP."""
    findings = []
    if not api_key:
        return findings
    # HIBP paste API requires per-email queries
    return findings


def search_threat_intel_feeds(domain):
    """Search public threat intelligence for domain mentions."""
    findings = []
    print(f"[*] Checking public threat intelligence for: {domain}")

    # Check URLhaus for malicious URLs from domain
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain}, timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "ok":
                urls = data.get("urls", [])
                if urls:
                    findings.append({
                        "type": "malicious_urls",
                        "source": "URLhaus",
                        "domain": domain,
                        "count": len(urls),
                        "severity": "HIGH",
                        "detail": f"{len(urls)} malicious URLs associated with domain",
                        "samples": [u.get("url", "")[:80] for u in urls[:5]],
                    })
    except requests.RequestException:
        pass

    # Check AbuseIPDB
    abuse_key = os.environ.get("ABUSEIPDB_KEY", "")
    if abuse_key:
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check-block",
                headers={"Key": abuse_key, "Accept": "application/json"},
                params={"network": domain}, timeout=15,
            )
        except requests.RequestException:
            pass

    return findings


def format_summary(all_findings, domain):
    """Print monitoring summary."""
    print(f"\n{'='*60}")
    print("  Dark Web Threat Monitoring Report")
    print(f"{'='*60}")
    print(f"  Target Domain: {domain}")
    print(f"  Total Findings: {len(all_findings)}")

    by_type = {}
    for f in all_findings:
        t = f.get("type", "unknown")
        by_type[t] = by_type.get(t, 0) + 1

    if by_type:
        print("\n  By Type:")
        for t, count in by_type.items():
            print(f"    {t:20s}: {count}")

    breaches = [f for f in all_findings if f["type"] == "breach"]
    if breaches:
        print(f"\n  Known Breaches ({len(breaches)}):")
        for b in breaches:
            print(f"    [{b['severity']:8s}] {b['name']:25s} | "
                  f"Date: {b['breach_date']} | Records: {b.get('pwn_count', 'N/A')}")
            if b.get("data_classes"):
                print(f"             Data: {', '.join(b['data_classes'][:5])}")

    severity_counts = {}
    for f in all_findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    return severity_counts


def main():
    parser = argparse.ArgumentParser(description="Dark web threat monitoring agent")
    parser.add_argument("--domain", required=True, help="Organization domain to monitor")
    parser.add_argument("--emails", nargs="+", help="Specific emails to check")
    parser.add_argument("--hibp-key", help="HIBP API key (or HIBP_API_KEY env)")
    parser.add_argument("--check-passwords", nargs="+", help="Check passwords against breach DB")
    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    hibp_key = args.hibp_key or os.environ.get("HIBP_API_KEY", "")
    all_findings = []

    all_findings.extend(check_hibp_breaches(args.domain, hibp_key))

    if args.emails and hibp_key:
        for email in args.emails:
            all_findings.extend(check_hibp_email(email, hibp_key))

    if args.check_passwords:
        for pwd in args.check_passwords:
            result = check_hibp_password(pwd)
            if result.get("compromised"):
                all_findings.append({
                    "type": "compromised_password",
                    "severity": "CRITICAL",
                    "detail": f"Password found in {result['count']} breaches",
                })

    all_findings.extend(search_threat_intel_feeds(args.domain))
    severity_counts = format_summary(all_findings, args.domain)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "Dark Web Monitor",
        "domain": args.domain,
        "findings": all_findings,
        "severity_counts": severity_counts,
        "risk_level": (
            "CRITICAL" if severity_counts.get("CRITICAL", 0) > 0
            else "HIGH" if severity_counts.get("HIGH", 0) > 0
            else "MEDIUM" if all_findings else "LOW"
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
