#!/usr/bin/env python3
"""Agent for performing paste site monitoring for leaked credentials."""

import json
import argparse
import re
import time
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None


def check_haveibeenpwned(email, api_key=None):
    """Check if an email appears in Have I Been Pwned breaches."""
    headers = {"User-Agent": "PasteMonitor-Agent"}
    if api_key:
        headers["hibp-api-key"] = api_key
    try:
        resp = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                            headers=headers, timeout=15)
        if resp.status_code == 200:
            breaches = resp.json()
            return {
                "email": email, "breached": True,
                "breach_count": len(breaches),
                "breaches": [{"name": b["Name"], "date": b["BreachDate"],
                              "data_classes": b["DataClasses"]} for b in breaches[:10]],
            }
        elif resp.status_code == 404:
            return {"email": email, "breached": False}
        else:
            return {"email": email, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"email": email, "error": str(e)}


def check_paste_dumps(email, api_key=None):
    """Check for email in paste site dumps via HIBP paste API."""
    headers = {"User-Agent": "PasteMonitor-Agent"}
    if api_key:
        headers["hibp-api-key"] = api_key
    try:
        resp = requests.get(f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}",
                            headers=headers, timeout=15)
        if resp.status_code == 200:
            pastes = resp.json()
            return {
                "email": email, "found_in_pastes": True,
                "paste_count": len(pastes),
                "pastes": [{"source": p.get("Source"), "title": p.get("Title", "")[:100],
                            "date": p.get("Date"), "email_count": p.get("EmailCount")}
                           for p in pastes[:15]],
            }
        elif resp.status_code == 404:
            return {"email": email, "found_in_pastes": False}
        else:
            return {"email": email, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"email": email, "error": str(e)}


def bulk_check_domain(domain, email_list_file, api_key=None):
    """Check all emails from a domain for breach exposure."""
    from pathlib import Path
    emails = [e.strip() for e in Path(email_list_file).read_text().splitlines() if e.strip() and domain in e]
    results = []
    for email in emails[:50]:
        result = check_haveibeenpwned(email, api_key)
        results.append(result)
        time.sleep(1.6)
    breached = [r for r in results if r.get("breached")]
    return {
        "domain": domain,
        "emails_checked": len(results),
        "breached_accounts": len(breached),
        "exposure_rate": round(len(breached) / max(len(results), 1) * 100, 1),
        "results": results,
    }


def scan_text_for_credentials(text_file):
    """Scan a text file (paste dump) for credential patterns."""
    from pathlib import Path
    content = Path(text_file).read_text(encoding="utf-8", errors="replace")
    patterns = {
        "email_password": re.compile(r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s*[:|;]\s*(\S+)"),
        "username_password": re.compile(r"(?:user(?:name)?|login)\s*[:|=]\s*(\S+)\s+(?:pass(?:word)?)\s*[:|=]\s*(\S+)", re.I),
        "api_key": re.compile(r"(?:api[_-]?key|apikey|access[_-]?token)\s*[:|=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?", re.I),
        "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
        "private_key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        "jwt_token": re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
    }
    findings = {}
    for name, pattern in patterns.items():
        matches = pattern.findall(content)
        if matches:
            if isinstance(matches[0], tuple):
                findings[name] = [{"match": m[0][:50]} for m in matches[:20]]
            else:
                findings[name] = [{"match": m[:50]} for m in matches[:20]]
    domains = re.findall(r"@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", content)
    domain_counts = {}
    for d in domains:
        domain_counts[d] = domain_counts.get(d, 0) + 1
    return {
        "file": text_file,
        "credential_types_found": list(findings.keys()),
        "total_matches": sum(len(v) for v in findings.values()),
        "findings": findings,
        "affected_domains": dict(sorted(domain_counts.items(), key=lambda x: -x[1])[:15]),
    }


def generate_exposure_report(domain, email_list_file, api_key=None):
    """Generate credential exposure report for an organization."""
    bulk = bulk_check_domain(domain, email_list_file, api_key)
    return {
        "generated": datetime.utcnow().isoformat(),
        "domain": domain,
        "summary": {
            "emails_checked": bulk["emails_checked"],
            "breached": bulk["breached_accounts"],
            "exposure_rate": bulk["exposure_rate"],
        },
        "recommendations": [
            "Force password reset for all breached accounts",
            "Enable MFA for all accounts",
            "Monitor for credential stuffing attacks",
            "Implement password breach detection (e.g., Azure AD Password Protection)",
        ],
        "details": bulk["results"][:20],
    }


def main():
    if not requests:
        print(json.dumps({"error": "requests not installed"}))
        return
    parser = argparse.ArgumentParser(description="Paste Site Credential Monitoring Agent")
    parser.add_argument("--api-key", help="HIBP API key")
    sub = parser.add_subparsers(dest="command")
    c = sub.add_parser("check", help="Check single email")
    c.add_argument("--email", required=True)
    p = sub.add_parser("pastes", help="Check paste dumps")
    p.add_argument("--email", required=True)
    b = sub.add_parser("bulk", help="Bulk domain check")
    b.add_argument("--domain", required=True)
    b.add_argument("--emails", required=True, help="Email list file")
    s = sub.add_parser("scan", help="Scan text for credentials")
    s.add_argument("--file", required=True)
    r = sub.add_parser("report", help="Exposure report")
    r.add_argument("--domain", required=True)
    r.add_argument("--emails", required=True)
    args = parser.parse_args()
    api_key = args.api_key if hasattr(args, "api_key") else None
    if args.command == "check":
        result = check_haveibeenpwned(args.email, api_key)
    elif args.command == "pastes":
        result = check_paste_dumps(args.email, api_key)
    elif args.command == "bulk":
        result = bulk_check_domain(args.domain, args.emails, api_key)
    elif args.command == "scan":
        result = scan_text_for_credentials(args.file)
    elif args.command == "report":
        result = generate_exposure_report(args.domain, args.emails, api_key)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
