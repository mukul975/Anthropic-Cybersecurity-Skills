#!/usr/bin/env python3
"""Threat intelligence lifecycle management agent.

Manages the threat intelligence lifecycle: collection from feeds,
processing/normalization of IOCs, analysis/enrichment via VirusTotal
and AbuseIPDB, dissemination to SIEM/firewalls, and tracking of
IOC aging and confidence scoring.
"""
import argparse
import csv
import hashlib
import json
import os
import re
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    requests = None


IOC_PATTERNS = {
    "ipv4": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "domain": re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', re.I),
    "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
    "sha1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
    "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
    "url": re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
    "email": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
}


def extract_iocs(text):
    """Extract IOCs from unstructured text."""
    iocs = {}
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = set(pattern.findall(text))
        # Filter out private IPs for ipv4
        if ioc_type == "ipv4":
            matches = {ip for ip in matches
                      if not ip.startswith(("10.", "192.168.", "127.", "0."))
                      and not ip.startswith("172.") or not (16 <= int(ip.split(".")[1]) <= 31)}
        if matches:
            iocs[ioc_type] = sorted(matches)
    return iocs


def load_ioc_feed(source):
    """Load IOCs from a file (JSON, CSV, or plain text)."""
    ext = os.path.splitext(source)[1].lower()
    iocs = []

    if ext == ".json":
        with open(source, "r") as f:
            data = json.load(f)
        if isinstance(data, list):
            iocs = data
        elif isinstance(data, dict):
            iocs = data.get("indicators", data.get("iocs", data.get("data", [])))
    elif ext == ".csv":
        with open(source, "r", newline="") as f:
            reader = csv.DictReader(f)
            iocs = list(reader)
    else:
        with open(source, "r") as f:
            text = f.read()
        extracted = extract_iocs(text)
        for ioc_type, values in extracted.items():
            for v in values:
                iocs.append({"type": ioc_type, "value": v, "source": source})

    return iocs


def normalize_ioc(ioc):
    """Normalize IOC into standard format."""
    if isinstance(ioc, str):
        for ioc_type, pattern in IOC_PATTERNS.items():
            if pattern.fullmatch(ioc):
                return {"type": ioc_type, "value": ioc.lower().strip()}
        return {"type": "unknown", "value": ioc.strip()}

    return {
        "type": (ioc.get("type") or ioc.get("indicator_type") or "unknown").lower(),
        "value": (ioc.get("value") or ioc.get("indicator") or "").lower().strip(),
        "source": ioc.get("source", ""),
        "confidence": ioc.get("confidence", 50),
        "first_seen": ioc.get("first_seen", ""),
        "last_seen": ioc.get("last_seen", ""),
        "tags": ioc.get("tags", []),
        "description": ioc.get("description", ""),
    }


def enrich_ioc_virustotal(ioc_value, ioc_type, api_key):
    """Enrich IOC via VirusTotal API v3."""
    if not requests or not api_key:
        return {}

    headers = {"x-apikey": api_key}
    base = "https://www.virustotal.com/api/v3"

    if ioc_type in ("md5", "sha1", "sha256"):
        url = f"{base}/files/{ioc_value}"
    elif ioc_type == "domain":
        url = f"{base}/domains/{ioc_value}"
    elif ioc_type == "ipv4":
        url = f"{base}/ip_addresses/{ioc_value}"
    elif ioc_type == "url":
        url_id = hashlib.sha256(ioc_value.encode()).hexdigest()
        url = f"{base}/urls/{url_id}"
    else:
        return {}

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": data.get("reputation", 0),
                "source": "virustotal",
            }
    except requests.RequestException:
        pass
    return {}


def calculate_confidence(ioc, enrichment=None):
    """Calculate confidence score for an IOC (0-100)."""
    score = ioc.get("confidence", 50)

    # Boost for VT detections
    if enrichment:
        malicious = enrichment.get("malicious", 0)
        if malicious > 10:
            score = min(score + 30, 100)
        elif malicious > 5:
            score = min(score + 20, 100)
        elif malicious > 0:
            score = min(score + 10, 100)
        elif enrichment.get("harmless", 0) > 20:
            score = max(score - 20, 0)

    # Decay based on age
    first_seen = ioc.get("first_seen", "")
    if first_seen:
        try:
            if "T" in first_seen:
                seen_dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
            else:
                seen_dt = datetime.strptime(first_seen[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - seen_dt).days
            if age_days > 180:
                score = max(score - 20, 0)
            elif age_days > 90:
                score = max(score - 10, 0)
        except (ValueError, TypeError):
            pass

    return min(max(score, 0), 100)


def format_summary(iocs, enriched_count):
    """Print lifecycle report."""
    print(f"\n{'='*60}")
    print("  Threat Intelligence Lifecycle Report")
    print(f"{'='*60}")
    print(f"  Total IOCs    : {len(iocs)}")
    print(f"  Enriched      : {enriched_count}")

    by_type = {}
    for ioc in iocs:
        t = ioc.get("type", "unknown")
        by_type[t] = by_type.get(t, 0) + 1
    print("\n  By Type:")
    for t, count in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"    {t:12s}: {count}")

    high_conf = [i for i in iocs if i.get("confidence", 0) >= 80]
    med_conf = [i for i in iocs if 50 <= i.get("confidence", 0) < 80]
    low_conf = [i for i in iocs if i.get("confidence", 0) < 50]
    print("\n  By Confidence:")
    print(f"    High (>=80) : {len(high_conf)}")
    print(f"    Medium      : {len(med_conf)}")
    print(f"    Low (<50)   : {len(low_conf)}")

    if high_conf:
        print("\n  High-Confidence IOCs:")
        for i in high_conf[:15]:
            print(f"    [{i['type']:8s}] {i['value'][:50]:50s} (confidence: {i.get('confidence', 0)})")


def main():
    parser = argparse.ArgumentParser(description="Threat intelligence lifecycle management agent")
    parser.add_argument("--source", required=True, help="IOC source file (JSON/CSV/text)")
    parser.add_argument("--vt-key", help="VirusTotal API key (or VT_API_KEY env)")
    parser.add_argument("--enrich", action="store_true", help="Enrich IOCs via VirusTotal")
    parser.add_argument("--min-confidence", type=int, default=0, help="Min confidence to include")
    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    vt_key = args.vt_key or os.environ.get("VT_API_KEY", "")

    raw_iocs = load_ioc_feed(args.source)
    print(f"[*] Loaded {len(raw_iocs)} raw IOCs from {args.source}")

    iocs = [normalize_ioc(ioc) for ioc in raw_iocs]
    iocs = [i for i in iocs if i.get("value")]

    # Deduplicate
    seen = set()
    unique_iocs = []
    for ioc in iocs:
        key = f"{ioc['type']}:{ioc['value']}"
        if key not in seen:
            seen.add(key)
            unique_iocs.append(ioc)
    iocs = unique_iocs
    print(f"[*] {len(iocs)} unique IOCs after dedup")

    enriched_count = 0
    if args.enrich and vt_key:
        print("[*] Enriching IOCs via VirusTotal...")
        for ioc in iocs[:100]:  # Rate limit
            enrichment = enrich_ioc_virustotal(ioc["value"], ioc["type"], vt_key)
            if enrichment:
                ioc["enrichment"] = enrichment
                enriched_count += 1
            ioc["confidence"] = calculate_confidence(ioc, enrichment)
    else:
        for ioc in iocs:
            ioc["confidence"] = calculate_confidence(ioc)

    iocs = [i for i in iocs if i.get("confidence", 0) >= args.min_confidence]
    iocs.sort(key=lambda x: -x.get("confidence", 0))

    format_summary(iocs, enriched_count)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "TI Lifecycle Manager",
        "source": args.source,
        "total_iocs": len(iocs),
        "enriched": enriched_count,
        "iocs": iocs,
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
