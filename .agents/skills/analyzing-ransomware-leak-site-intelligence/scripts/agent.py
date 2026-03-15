#!/usr/bin/env python3
"""Ransomware leak site intelligence analysis agent.

Monitors and analyzes ransomware group leak site data for threat intelligence,
victim tracking, and TTI (time-to-intelligence) reporting.
"""

import os
import sys
import json
import re
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict, Counter

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

RANSOMWARE_GROUPS = {
    "lockbit": {"aliases": ["LockBit 3.0", "LockBit Black"], "status": "active"},
    "alphv": {"aliases": ["BlackCat", "ALPHV"], "status": "disrupted"},
    "cl0p": {"aliases": ["Clop", "TA505"], "status": "active"},
    "play": {"aliases": ["PlayCrypt"], "status": "active"},
    "8base": {"aliases": ["8Base"], "status": "active"},
    "akira": {"aliases": ["Akira"], "status": "active"},
    "bianlian": {"aliases": ["BianLian"], "status": "active"},
    "blackbasta": {"aliases": ["Black Basta"], "status": "active"},
    "medusa": {"aliases": ["MedusaLocker", "Medusa Blog"], "status": "active"},
    "rhysida": {"aliases": ["Rhysida"], "status": "active"},
    "royal": {"aliases": ["Royal", "BlackSuit"], "status": "rebranded"},
    "ransomhub": {"aliases": ["RansomHub"], "status": "active"},
}


def query_ransomwatch_api():
    """Query ransomwatch or ransomware.live API for leak site data."""
    if not HAS_REQUESTS:
        return []
    try:
        resp = requests.get("https://api.ransomware.live/recentvictims",
                           timeout=30)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        return [{"error": str(e)}]


def query_ransomlook_group(group_name):
    """Query ransomlook.io API for group information."""
    if not HAS_REQUESTS:
        return {}
    try:
        resp = requests.get(f"https://www.ransomlook.io/api/group/{group_name}",
                           timeout=30)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException:
        return {}


def analyze_victim_data(victims):
    """Analyze victim listing data for intelligence."""
    sector_counts = Counter()
    country_counts = Counter()
    group_counts = Counter()
    timeline = defaultdict(int)

    for v in victims:
        group = v.get("group_name", v.get("group", "unknown")).lower()
        group_counts[group] += 1
        sector = v.get("activity", v.get("sector", "unknown"))
        if sector:
            sector_counts[sector] += 1
        country = v.get("country", "unknown")
        if country:
            country_counts[country] += 1
        date_str = v.get("discovered", v.get("published", ""))
        if date_str:
            try:
                dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                timeline[dt.strftime("%Y-%m")] += 1
            except (ValueError, TypeError):
                pass

    return {
        "total_victims": len(victims),
        "top_groups": dict(group_counts.most_common(10)),
        "top_sectors": dict(sector_counts.most_common(10)),
        "top_countries": dict(country_counts.most_common(10)),
        "monthly_trend": dict(sorted(timeline.items())),
    }


def search_victims(victims, query):
    """Search victims by name, domain, or sector."""
    results = []
    query_lower = query.lower()
    for v in victims:
        name = (v.get("victim", v.get("post_title", "")) or "").lower()
        website = (v.get("website", "") or "").lower()
        sector = (v.get("activity", v.get("sector", "")) or "").lower()
        if query_lower in name or query_lower in website or query_lower in sector:
            results.append(v)
    return results


def assess_group_activity(victims, group_name, days=90):
    """Assess activity level of a specific ransomware group."""
    cutoff = datetime.now() - timedelta(days=days)
    group_victims = []
    for v in victims:
        g = (v.get("group_name", v.get("group", "")) or "").lower()
        if group_name.lower() in g:
            group_victims.append(v)

    recent = []
    for v in group_victims:
        date_str = v.get("discovered", v.get("published", ""))
        if date_str:
            try:
                dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                if dt.replace(tzinfo=None) > cutoff:
                    recent.append(v)
            except (ValueError, TypeError):
                pass

    info = RANSOMWARE_GROUPS.get(group_name.lower(), {})
    return {
        "group": group_name,
        "aliases": info.get("aliases", []),
        "status": info.get("status", "unknown"),
        "total_victims": len(group_victims),
        "recent_victims": len(recent),
        "period_days": days,
        "activity_level": "HIGH" if len(recent) > 20 else "MEDIUM" if len(recent) > 5 else "LOW",
    }


def generate_intelligence_report(victims, target_org=None):
    """Generate ransomware threat intelligence report."""
    analysis = analyze_victim_data(victims)
    report = {
        "report_date": datetime.now().isoformat(),
        "data_source": "ransomware.live API",
        "analysis": analysis,
    }
    if target_org:
        matches = search_victims(victims, target_org)
        report["org_search"] = {
            "query": target_org,
            "matches": len(matches),
            "results": matches[:10],
        }
    return report


if __name__ == "__main__":
    print("=" * 60)
    print("Ransomware Leak Site Intelligence Agent")
    print("Victim tracking, group analysis, sector trends")
    print("=" * 60)

    query = sys.argv[1] if len(sys.argv) > 1 else None

    if not HAS_REQUESTS:
        print("[!] Install requests: pip install requests")
        sys.exit(1)

    print("\n[*] Fetching recent ransomware victims...")
    victims = query_ransomwatch_api()
    if not victims or (len(victims) == 1 and "error" in victims[0]):
        print(f"[!] API error: {victims}")
        sys.exit(1)

    print(f"[*] Retrieved {len(victims)} victim entries")
    report = generate_intelligence_report(victims, target_org=query)
    analysis = report["analysis"]

    print(f"\n--- Top Groups ---")
    for g, c in list(analysis["top_groups"].items())[:5]:
        print(f"  {g:20s} {c} victims")

    print(f"\n--- Top Sectors ---")
    for s, c in list(analysis["top_sectors"].items())[:5]:
        print(f"  {s:30s} {c}")

    print(f"\n--- Top Countries ---")
    for co, c in list(analysis["top_countries"].items())[:5]:
        print(f"  {co:20s} {c}")

    if query:
        matches = report.get("org_search", {})
        print(f"\n--- Search: '{query}' ({matches.get('matches', 0)} results) ---")
        for m in matches.get("results", [])[:5]:
            print(f"  {m.get('group_name', '?'):15s} | {m.get('victim', m.get('post_title', '?'))}")

    print(f"\n{json.dumps(report, indent=2, default=str)}")
