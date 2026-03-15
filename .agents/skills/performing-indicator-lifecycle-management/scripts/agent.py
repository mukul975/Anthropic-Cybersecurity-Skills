#!/usr/bin/env python3
"""Agent for performing indicator of compromise (IOC) lifecycle management."""

import json
import argparse
import csv
import re
import hashlib
from datetime import datetime, timedelta
from pathlib import Path


IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"),
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.I),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.I),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.I),
    "url": re.compile(r"https?://[^\s<>\"']+"),
    "email": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
    "cve": re.compile(r"CVE-\d{4}-\d{4,}", re.I),
}


def extract_iocs(text_file):
    """Extract IOCs from a text file or report."""
    text = Path(text_file).read_text(encoding="utf-8", errors="replace")
    extracted = {}
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = list(set(pattern.findall(text)))
        if matches:
            extracted[ioc_type] = matches[:100]
    total = sum(len(v) for v in extracted.values())
    return {"source": text_file, "total_iocs": total, "by_type": {k: len(v) for k, v in extracted.items()}, "indicators": extracted}


def ingest_ioc_feed(csv_file):
    """Ingest IOC feed from CSV and normalize."""
    with open(csv_file, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    iocs = []
    for row in rows:
        indicator = row.get("indicator", row.get("ioc", row.get("value", row.get("Indicator", ""))))
        ioc_type = row.get("type", row.get("ioc_type", row.get("Type", "")))
        if not ioc_type:
            for t, p in IOC_PATTERNS.items():
                if p.fullmatch(indicator.strip()):
                    ioc_type = t
                    break
        iocs.append({
            "indicator": indicator.strip(),
            "type": ioc_type,
            "source": row.get("source", row.get("feed", "")),
            "confidence": row.get("confidence", row.get("score", "")),
            "first_seen": row.get("first_seen", row.get("date", "")),
            "tags": row.get("tags", row.get("malware_family", "")),
        })
    return {"total_ingested": len(iocs), "by_type": _count_field(iocs, "type"), "iocs": iocs[:50]}


def check_expiration(ioc_db_file, ttl_days=90):
    """Check IOC database for expired indicators based on TTL."""
    with open(ioc_db_file, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    now = datetime.utcnow()
    expired = []
    active = []
    for row in rows:
        date_str = row.get("first_seen", row.get("date", row.get("added", "")))
        try:
            added = datetime.fromisoformat(date_str.replace("Z", "+00:00").replace("+00:00", ""))
        except (ValueError, AttributeError):
            active.append(row)
            continue
        age_days = (now - added).days
        if age_days > ttl_days:
            expired.append({**row, "age_days": age_days})
        else:
            active.append(row)
    return {
        "total": len(rows), "active": len(active), "expired": len(expired),
        "ttl_days": ttl_days, "expired_indicators": expired[:30],
    }


def deduplicate_iocs(csv_file):
    """Deduplicate IOCs and merge metadata from multiple sources."""
    with open(csv_file, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    seen = {}
    for row in rows:
        key = row.get("indicator", row.get("ioc", row.get("value", ""))).strip().lower()
        if key in seen:
            seen[key]["sources"].add(row.get("source", ""))
            seen[key]["count"] += 1
        else:
            seen[key] = {"indicator": key, "type": row.get("type", ""), "sources": {row.get("source", "")}, "count": 1, "first_row": row}
    unique = [{"indicator": v["indicator"], "type": v["type"], "sources": list(v["sources"]), "occurrences": v["count"]}
              for v in seen.values()]
    return {
        "original_count": len(rows), "unique_count": len(unique),
        "duplicates_removed": len(rows) - len(unique),
        "multi_source": [u for u in unique if u["occurrences"] > 1][:20],
        "unique_iocs": unique[:50],
    }


def generate_lifecycle_report(csv_file, ttl_days=90):
    """Generate full IOC lifecycle status report."""
    ingested = ingest_ioc_feed(csv_file)
    expiration = check_expiration(csv_file, ttl_days)
    dedup = deduplicate_iocs(csv_file)
    return {
        "generated": datetime.utcnow().isoformat(),
        "total_iocs": ingested["total_ingested"],
        "unique_iocs": dedup["unique_count"],
        "duplicates": dedup["duplicates_removed"],
        "active": expiration["active"],
        "expired": expiration["expired"],
        "by_type": ingested["by_type"],
        "ttl_days": ttl_days,
    }


def _count_field(items, field):
    counts = {}
    for item in items:
        val = item.get(field, "unknown")
        counts[val] = counts.get(val, 0) + 1
    return counts


def main():
    parser = argparse.ArgumentParser(description="IOC Lifecycle Management Agent")
    sub = parser.add_subparsers(dest="command")
    e = sub.add_parser("extract", help="Extract IOCs from text")
    e.add_argument("--file", required=True)
    i = sub.add_parser("ingest", help="Ingest IOC feed CSV")
    i.add_argument("--csv", required=True)
    x = sub.add_parser("expire", help="Check IOC expiration")
    x.add_argument("--csv", required=True)
    x.add_argument("--ttl", type=int, default=90, help="TTL in days")
    d = sub.add_parser("dedup", help="Deduplicate IOCs")
    d.add_argument("--csv", required=True)
    r = sub.add_parser("report", help="Full lifecycle report")
    r.add_argument("--csv", required=True)
    r.add_argument("--ttl", type=int, default=90)
    args = parser.parse_args()
    if args.command == "extract":
        result = extract_iocs(args.file)
    elif args.command == "ingest":
        result = ingest_ioc_feed(args.csv)
    elif args.command == "expire":
        result = check_expiration(args.csv, args.ttl)
    elif args.command == "dedup":
        result = deduplicate_iocs(args.csv)
    elif args.command == "report":
        result = generate_lifecycle_report(args.csv, args.ttl)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
