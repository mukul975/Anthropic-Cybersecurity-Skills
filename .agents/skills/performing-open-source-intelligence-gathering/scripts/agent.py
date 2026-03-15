#!/usr/bin/env python3
"""Agent for performing open source intelligence (OSINT) gathering."""

import json
import argparse
import re
import socket
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


def whois_lookup(domain):
    """Perform WHOIS lookup for domain registration info."""
    try:
        import whois
        w = whois.whois(domain)
        return {
            "domain": domain, "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers if isinstance(w.name_servers, list) else [w.name_servers],
            "status": w.status if isinstance(w.status, list) else [w.status],
            "registrant": w.get("org", w.get("name", "")),
        }
    except ImportError:
        return {"error": "python-whois not installed — pip install python-whois"}
    except Exception as e:
        return {"domain": domain, "error": str(e)}


def dns_enumeration(domain):
    """Enumerate DNS records for intelligence gathering."""
    if not HAS_DNS:
        return {"error": "dnspython not installed — pip install dnspython"}
    records = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            pass
    subs = ["www", "mail", "ftp", "vpn", "api", "dev", "staging", "admin",
            "portal", "test", "owa", "remote", "webmail", "autodiscover", "sip"]
    found = []
    for sub in subs:
        try:
            answers = dns.resolver.resolve(f"{sub}.{domain}", "A")
            found.append({"subdomain": f"{sub}.{domain}", "ips": [str(r) for r in answers]})
        except Exception:
            pass
    return {"domain": domain, "records": records, "subdomains": found}


def email_harvest(domain):
    """Search for email addresses associated with a domain."""
    if not requests:
        return {"error": "requests not installed"}
    emails = set()
    try:
        resp = requests.get(f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key=demo", timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for email in data.get("data", {}).get("emails", []):
                emails.add(email.get("value", ""))
    except Exception:
        pass
    pattern = re.compile(rf"[a-zA-Z0-9._%+-]+@{re.escape(domain)}", re.I)
    search_urls = [f"https://www.google.com/search?q=%22%40{domain}%22&num=20"]
    return {
        "domain": domain,
        "emails_found": list(emails)[:20],
        "email_count": len(emails),
        "search_pattern": f"*@{domain}",
    }


def technology_fingerprint(url):
    """Fingerprint web technologies from HTTP response headers."""
    if not requests:
        return {"error": "requests not installed"}
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True)
        headers = dict(resp.headers)
        technologies = []
        server = headers.get("Server", "")
        if server:
            technologies.append({"category": "Web Server", "value": server})
        powered = headers.get("X-Powered-By", "")
        if powered:
            technologies.append({"category": "Framework", "value": powered})
        if "wp-content" in resp.text or "wordpress" in resp.text.lower():
            technologies.append({"category": "CMS", "value": "WordPress"})
        if "drupal" in resp.text.lower():
            technologies.append({"category": "CMS", "value": "Drupal"})
        security_headers = {}
        for h in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
                   "X-Content-Type-Options", "X-XSS-Protection", "Referrer-Policy"]:
            security_headers[h] = headers.get(h, "MISSING")
        return {
            "url": url, "status": resp.status_code,
            "technologies": technologies,
            "security_headers": security_headers,
            "cookies": [{"name": c.name, "secure": c.secure, "httponly": "HttpOnly" in str(c._rest)}
                        for c in resp.cookies][:10],
        }
    except Exception as e:
        return {"url": url, "error": str(e)}


def social_media_search(target_name):
    """Generate social media profile URLs for a target name."""
    username = target_name.lower().replace(" ", "")
    platforms = {
        "linkedin": f"https://www.linkedin.com/in/{username}",
        "twitter": f"https://twitter.com/{username}",
        "github": f"https://github.com/{username}",
        "facebook": f"https://www.facebook.com/{username}",
        "instagram": f"https://www.instagram.com/{username}",
    }
    results = []
    for platform, url in platforms.items():
        if requests:
            try:
                resp = requests.head(url, timeout=5, allow_redirects=True)
                exists = resp.status_code == 200
                results.append({"platform": platform, "url": url, "exists": exists})
            except Exception:
                results.append({"platform": platform, "url": url, "exists": "unknown"})
        else:
            results.append({"platform": platform, "url": url, "exists": "unchecked"})
    return {"target": target_name, "profiles": results}


def main():
    parser = argparse.ArgumentParser(description="OSINT Gathering Agent")
    sub = parser.add_subparsers(dest="command")
    w = sub.add_parser("whois", help="WHOIS lookup")
    w.add_argument("--domain", required=True)
    d = sub.add_parser("dns", help="DNS enumeration")
    d.add_argument("--domain", required=True)
    e = sub.add_parser("email", help="Email harvesting")
    e.add_argument("--domain", required=True)
    t = sub.add_parser("tech", help="Technology fingerprinting")
    t.add_argument("--url", required=True)
    s = sub.add_parser("social", help="Social media search")
    s.add_argument("--name", required=True)
    args = parser.parse_args()
    if args.command == "whois":
        result = whois_lookup(args.domain)
    elif args.command == "dns":
        result = dns_enumeration(args.domain)
    elif args.command == "email":
        result = email_harvest(args.domain)
    elif args.command == "tech":
        result = technology_fingerprint(args.url)
    elif args.command == "social":
        result = social_media_search(args.name)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
