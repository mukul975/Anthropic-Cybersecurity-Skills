#!/usr/bin/env python3
"""
Dark Web Source Monitoring Agent
Monitors dark web forums, paste sites, and ransomware leak sites for
organizational asset mentions using commercial APIs and OSINT tools.
"""

import json
import os
import re
import sys
from datetime import datetime, timezone

import requests


HAVE_I_BEEN_PWNED_API = "https://haveibeenpwned.com/api/v3"
DEHASHED_API = "https://api.dehashed.com/search"


def check_breach_exposure(domain: str, hibp_api_key: str) -> list[dict]:
    """Check Have I Been Pwned for domain breach exposure."""
    if not hibp_api_key:
        return [{"error": "HIBP_API_KEY not set"}]

    headers = {
        "hibp-api-key": hibp_api_key,
        "user-agent": "DarkWebMonitor-Agent",
    }
    resp = requests.get(
        f"{HAVE_I_BEEN_PWNED_API}/breaches",
        headers=headers, timeout=30,
    )
    if resp.status_code != 200:
        return [{"error": f"HIBP returned {resp.status_code}"}]

    breaches = resp.json()
    relevant = []
    for breach in breaches:
        if domain.lower() in breach.get("Domain", "").lower():
            relevant.append({
                "name": breach["Name"],
                "domain": breach["Domain"],
                "breach_date": breach.get("BreachDate", ""),
                "pwn_count": breach.get("PwnCount", 0),
                "data_classes": breach.get("DataClasses", []),
                "is_verified": breach.get("IsVerified", False),
            })

    return relevant


def search_paste_sites(org_keywords: list[str], api_key: str) -> list[dict]:
    """Search paste site archives for organization mentions."""
    results = []
    for keyword in org_keywords:
        resp = requests.get(
            f"{HAVE_I_BEEN_PWNED_API}/pasteaccount/{keyword}",
            headers={"hibp-api-key": api_key, "user-agent": "DarkWebMonitor-Agent"},
            timeout=30,
        )
        if resp.status_code == 200:
            pastes = resp.json()
            for paste in pastes:
                results.append({
                    "keyword": keyword,
                    "source": paste.get("Source", ""),
                    "id": paste.get("Id", ""),
                    "title": paste.get("Title", ""),
                    "date": paste.get("Date", ""),
                    "email_count": paste.get("EmailCount", 0),
                })

    return results


def check_credential_exposure(domain: str, dehashed_key: str, dehashed_email: str) -> dict:
    """Search Dehashed for exposed credentials matching domain."""
    if not dehashed_key:
        return {"error": "DEHASHED_API_KEY not set", "results": []}

    resp = requests.get(
        DEHASHED_API,
        params={"query": f"domain:{domain}", "size": 100},
        auth=(dehashed_email, dehashed_key),
        headers={"Accept": "application/json"},
        timeout=30,
    )

    if resp.status_code != 200:
        return {"error": f"Dehashed returned {resp.status_code}", "results": []}

    data = resp.json()
    entries = data.get("entries", [])
    return {
        "total_exposed": data.get("total", 0),
        "results_returned": len(entries),
        "sources": list(set(e.get("database_name", "") for e in entries)),
        "sample_entries": [
            {"email": e.get("email", ""), "source": e.get("database_name", ""),
             "has_password": bool(e.get("password") or e.get("hashed_password"))}
            for e in entries[:20]
        ],
    }


def monitor_ransomware_leak_sites(org_name: str) -> dict:
    """Check ransomware leak site intelligence feeds for organization mentions.
    Uses Ransomware.live API (public aggregator)."""
    results = {"mentions": [], "checked_groups": []}

    resp = requests.get(
        "https://api.ransomware.live/recentvictims",
        timeout=30,
    )
    if resp.status_code == 200:
        victims = resp.json()
        for victim in victims:
            victim_name = victim.get("victim", "").lower()
            if org_name.lower() in victim_name:
                results["mentions"].append({
                    "victim": victim.get("victim", ""),
                    "group": victim.get("group_name", ""),
                    "discovered": victim.get("discovered", ""),
                    "url": victim.get("post_url", ""),
                })

    resp2 = requests.get("https://api.ransomware.live/groups", timeout=30)
    if resp2.status_code == 200:
        groups = resp2.json()
        results["checked_groups"] = [g.get("name", "") for g in groups[:30]]

    return results


def generate_monitoring_report(
    domain: str, breaches: list, pastes: list, creds: dict, leak_results: dict
) -> str:
    """Generate dark web monitoring report."""
    lines = [
        "DARK WEB MONITORING REPORT",
        "=" * 50,
        f"Monitored Domain: {domain}",
        f"Report Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "BREACH EXPOSURE:",
        f"  Known Breaches Involving Domain: {len(breaches)}",
    ]
    for b in breaches[:5]:
        lines.append(f"  - {b['name']} ({b['breach_date']}) - {b['pwn_count']:,} accounts")

    lines.extend([
        "",
        "PASTE SITE EXPOSURE:",
        f"  Paste Mentions Found: {len(pastes)}",
    ])

    lines.extend([
        "",
        "CREDENTIAL EXPOSURE:",
        f"  Total Exposed Records: {creds.get('total_exposed', 0):,}",
        f"  Source Databases: {len(creds.get('sources', []))}",
    ])

    lines.extend([
        "",
        "RANSOMWARE LEAK SITES:",
        f"  Groups Monitored: {len(leak_results.get('checked_groups', []))}",
        f"  Mentions Found: {len(leak_results.get('mentions', []))}",
    ])
    for m in leak_results.get("mentions", []):
        lines.append(f"  - {m['victim']} by {m['group']} ({m['discovered']})")

    return "\n".join(lines)


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    hibp_key = os.getenv("HIBP_API_KEY", "")
    dehashed_key = os.getenv("DEHASHED_API_KEY", "")
    dehashed_email = os.getenv("DEHASHED_EMAIL", "")

    print(f"[*] Dark web monitoring for: {domain}")

    breaches = check_breach_exposure(domain, hibp_key)
    pastes = search_paste_sites([f"@{domain}"], hibp_key)
    creds = check_credential_exposure(domain, dehashed_key, dehashed_email)
    leak_results = monitor_ransomware_leak_sites(domain.split(".")[0])

    report = generate_monitoring_report(domain, breaches, pastes, creds, leak_results)
    print(report)

    output = f"darkweb_monitor_{domain.replace('.', '_')}_{datetime.now(timezone.utc).strftime('%Y%m%d')}.json"
    with open(output, "w") as f:
        json.dump({"breaches": breaches, "pastes": pastes, "credentials": creds, "leak_sites": leak_results}, f, indent=2)
    print(f"\n[*] Results saved to {output}")
