#!/usr/bin/env python3
"""Agent for performing AI-driven OSINT correlation.

Collects and normalizes OSINT data from multiple sources (Sherlock,
theHarvester, SpiderFoot, breach databases), performs cross-source
entity resolution and correlation, and generates unified intelligence
profiles with confidence scoring.
"""

import argparse
import csv
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    requests = None


# Confidence scoring weights for different correlation types
CORRELATION_WEIGHTS = {
    "exact_username_match": 0.85,
    "exact_email_match": 0.95,
    "domain_match": 0.60,
    "similar_username": 0.45,
    "same_ip_infrastructure": 0.70,
    "breach_email_match": 0.90,
    "co_registration_temporal": 0.40,
}


def load_sherlock_results(filepath):
    """Load and normalize Sherlock username enumeration results."""
    findings = []
    if not os.path.isfile(filepath):
        return findings

    # Sherlock outputs CSV with columns: username, name, url_user, exists, http_status
    try:
        with open(filepath, "r", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                status = row.get("exists", row.get("status", "")).strip().lower()
                if status in ("claimed", "true", "yes"):
                    findings.append({
                        "source": "sherlock",
                        "type": "social_profile",
                        "platform": row.get("name", row.get("platform", "")),
                        "url": row.get("url_user", row.get("url", "")),
                        "username": row.get("username", ""),
                        "collected_at": datetime.now(timezone.utc).isoformat(),
                    })
    except (csv.Error, KeyError):
        # Try line-by-line format (Sherlock text output)
        with open(filepath, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line.startswith("[+]") or line.startswith("http"):
                    url_match = re.search(r'(https?://\S+)', line)
                    if url_match:
                        url = url_match.group(1)
                        platform = url.split("/")[2].replace("www.", "").split(".")[0]
                        findings.append({
                            "source": "sherlock",
                            "type": "social_profile",
                            "platform": platform,
                            "url": url,
                            "collected_at": datetime.now(timezone.utc).isoformat(),
                        })
    return findings


def load_harvester_results(filepath):
    """Load and normalize theHarvester results."""
    findings = []
    if not os.path.isfile(filepath):
        return findings

    try:
        with open(filepath, "r") as f:
            data = json.load(f)
    except (json.JSONDecodeError, ValueError):
        return findings

    for email in data.get("emails", []):
        findings.append({
            "source": "theHarvester",
            "type": "email",
            "value": email,
            "collected_at": datetime.now(timezone.utc).isoformat(),
        })
    for host in data.get("hosts", []):
        findings.append({
            "source": "theHarvester",
            "type": "hostname",
            "value": host,
            "collected_at": datetime.now(timezone.utc).isoformat(),
        })
    for ip in data.get("ips", []):
        findings.append({
            "source": "theHarvester",
            "type": "ip_address",
            "value": ip,
            "collected_at": datetime.now(timezone.utc).isoformat(),
        })
    return findings


def load_spiderfoot_results(filepath):
    """Load and normalize SpiderFoot scan results."""
    findings = []
    if not os.path.isfile(filepath):
        return findings

    try:
        with open(filepath, "r") as f:
            data = json.load(f)
    except (json.JSONDecodeError, ValueError):
        return findings

    items = data if isinstance(data, list) else data.get("results", [])
    for item in items:
        findings.append({
            "source": "spiderfoot",
            "type": item.get("type", "unknown"),
            "value": item.get("data", item.get("value", "")),
            "module": item.get("module", ""),
            "collected_at": datetime.now(timezone.utc).isoformat(),
        })
    return findings


def load_breach_results(filepath):
    """Load and normalize breach/HIBP results."""
    findings = []
    if not os.path.isfile(filepath):
        return findings

    try:
        with open(filepath, "r") as f:
            data = json.load(f)
    except (json.JSONDecodeError, ValueError):
        return findings

    breaches = data if isinstance(data, list) else [data]
    for breach in breaches:
        findings.append({
            "source": "breach_database",
            "type": "breach_exposure",
            "breach_name": breach.get("Name", breach.get("name", "")),
            "breach_date": breach.get("BreachDate", breach.get("date", "")),
            "data_classes": breach.get("DataClasses", breach.get("data_types", [])),
            "collected_at": datetime.now(timezone.utc).isoformat(),
        })
    return findings


def normalize_all_sources(source_files):
    """Load and combine findings from all OSINT sources."""
    all_findings = []

    for source_type, filepath in source_files.items():
        if not filepath or not os.path.isfile(filepath):
            continue

        if source_type == "sherlock":
            all_findings.extend(load_sherlock_results(filepath))
        elif source_type == "harvester":
            all_findings.extend(load_harvester_results(filepath))
        elif source_type == "spiderfoot":
            all_findings.extend(load_spiderfoot_results(filepath))
        elif source_type == "breach":
            all_findings.extend(load_breach_results(filepath))
        elif source_type == "generic":
            try:
                with open(filepath, "r") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    all_findings.extend(data)
                elif isinstance(data, dict) and "findings" in data:
                    all_findings.extend(data["findings"])
            except (json.JSONDecodeError, ValueError):
                pass

    return all_findings


def extract_identifiers(findings):
    """Extract unique identifiers (usernames, emails, IPs, domains) from findings."""
    identifiers = {
        "usernames": set(),
        "emails": set(),
        "domains": set(),
        "ip_addresses": set(),
        "urls": set(),
    }

    for f in findings:
        ftype = f.get("type", "")
        value = f.get("value", "")
        username = f.get("username", "")
        url = f.get("url", "")

        if username:
            identifiers["usernames"].add(username.lower())
        if url:
            identifiers["urls"].add(url)

        if ftype == "email" and value:
            identifiers["emails"].add(value.lower())
            domain = value.split("@")[-1] if "@" in value else ""
            if domain:
                identifiers["domains"].add(domain.lower())
        elif ftype == "hostname" and value:
            identifiers["domains"].add(value.lower())
        elif ftype == "ip_address" and value:
            identifiers["ip_addresses"].add(value)
        elif ftype == "social_profile":
            platform_user = f.get("username", "")
            if platform_user:
                identifiers["usernames"].add(platform_user.lower())

    return {k: sorted(v) for k, v in identifiers.items()}


def correlate_findings(findings):
    """Perform cross-source correlation to identify linked entities."""
    entities = []
    source_map = defaultdict(list)

    # Group findings by identifiers
    for f in findings:
        username = f.get("username", "").lower()
        email = f.get("value", "").lower() if f.get("type") == "email" else ""
        url = f.get("url", "")

        if username:
            source_map[f"user:{username}"].append(f)
        if email:
            source_map[f"email:{email}"].append(f)
            # Also link by email username part
            email_user = email.split("@")[0] if "@" in email else ""
            if email_user:
                source_map[f"user:{email_user}"].append(f)

    # Build entities from correlated groups
    processed = set()
    for key, group_findings in source_map.items():
        if key in processed or len(group_findings) < 1:
            continue
        processed.add(key)

        sources_seen = set(f.get("source", "") for f in group_findings)
        platforms = [f.get("platform", "") for f in group_findings if f.get("platform")]
        urls = [f.get("url", "") for f in group_findings if f.get("url")]

        # Calculate confidence based on cross-source corroboration
        confidence = 0.5
        if len(sources_seen) > 1:
            confidence = min(0.95, 0.5 + 0.15 * len(sources_seen))
        if len(platforms) > 3:
            confidence = min(0.98, confidence + 0.1)

        identifier = key.split(":", 1)[1] if ":" in key else key
        entity = {
            "identifier": identifier,
            "identifier_type": key.split(":")[0] if ":" in key else "unknown",
            "confidence": round(confidence, 2),
            "sources": sorted(sources_seen),
            "source_count": len(sources_seen),
            "linked_accounts": [],
            "flags": [],
        }

        for f in group_findings:
            link = {
                "source": f.get("source", ""),
                "platform": f.get("platform", ""),
                "url": f.get("url", ""),
                "type": f.get("type", ""),
                "value": f.get("value", f.get("username", "")),
            }
            entity["linked_accounts"].append(link)

        # Risk assessment
        breach_findings = [f for f in group_findings if f.get("type") == "breach_exposure"]
        if breach_findings:
            entity["flags"].append(
                f"Exposed in {len(breach_findings)} breach(es)"
            )
            entity["risk_level"] = "high"
        elif len(sources_seen) >= 3:
            entity["risk_level"] = "medium"
        else:
            entity["risk_level"] = "low"

        entities.append(entity)

    # Sort by confidence descending
    entities.sort(key=lambda e: e["confidence"], reverse=True)
    return entities


def generate_report(findings, entities, target="unknown"):
    """Generate structured OSINT correlation report."""
    sources_used = sorted(set(f.get("source", "") for f in findings))
    identifier_summary = extract_identifiers(findings)

    report = {
        "meta": {
            "target": target,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "sources_used": sources_used,
            "total_findings": len(findings),
            "total_entities": len(entities),
        },
        "identifiers": identifier_summary,
        "entities": entities,
        "risk_summary": {
            "high_risk": sum(1 for e in entities if e.get("risk_level") == "high"),
            "medium_risk": sum(1 for e in entities if e.get("risk_level") == "medium"),
            "low_risk": sum(1 for e in entities if e.get("risk_level") == "low"),
        },
    }
    return report


def generate_markdown_report(report, output_path):
    """Generate a Markdown intelligence profile from the report."""
    md = "# OSINT Correlation Report\n\n"
    meta = report.get("meta", {})
    md += f"**Target:** {meta.get('target', 'N/A')}\n"
    md += f"**Generated:** {meta.get('generated_at', '')}\n"
    md += f"**Sources:** {', '.join(meta.get('sources_used', []))}\n"
    md += f"**Total Findings:** {meta.get('total_findings', 0)}\n"
    md += f"**Entities Identified:** {meta.get('total_entities', 0)}\n\n"

    risk = report.get("risk_summary", {})
    md += "## Risk Summary\n\n"
    md += "| Risk Level | Count |\n|-----------|-------|\n"
    md += f"| High | {risk.get('high_risk', 0)} |\n"
    md += f"| Medium | {risk.get('medium_risk', 0)} |\n"
    md += f"| Low | {risk.get('low_risk', 0)} |\n\n"

    md += "## Entity Profiles\n\n"
    for entity in report.get("entities", [])[:50]:
        eid = entity.get("identifier", "Unknown")
        conf = entity.get("confidence", 0)
        risk_level = entity.get("risk_level", "N/A")
        md += f"### {eid} (Confidence: {conf:.0%}, Risk: {risk_level})\n\n"
        md += "| Source | Platform | Value |\n|--------|----------|-------|\n"
        for link in entity.get("linked_accounts", []):
            md += (f"| {link.get('source', '')} | {link.get('platform', '')} "
                   f"| {link.get('value', '')} |\n")
        for flag in entity.get("flags", []):
            md += f"\n- WARNING: {flag}\n"
        md += "\n"

    with open(output_path, "w") as f:
        f.write(md)
    print(f"[*] Markdown report saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="AI-Driven OSINT Correlation Agent"
    )
    parser.add_argument("--target", default="unknown",
                        help="Target identifier (domain, username, etc.)")
    parser.add_argument("--sherlock", help="Sherlock results file (CSV or text)")
    parser.add_argument("--harvester", help="theHarvester results file (JSON)")
    parser.add_argument("--spiderfoot", help="SpiderFoot results file (JSON)")
    parser.add_argument("--breach", help="Breach/HIBP results file (JSON)")
    parser.add_argument("--generic", help="Generic normalized findings JSON")
    parser.add_argument("--normalize-only", action="store_true",
                        help="Only normalize data, skip correlation")
    parser.add_argument("--markdown", help="Output Markdown report path")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    args = parser.parse_args()

    print("[*] AI-Driven OSINT Correlation Agent")

    source_files = {
        "sherlock": args.sherlock,
        "harvester": args.harvester,
        "spiderfoot": args.spiderfoot,
        "breach": args.breach,
        "generic": args.generic,
    }

    active_sources = {k: v for k, v in source_files.items() if v}
    if not active_sources:
        parser.print_help()
        print("\n[!] Provide at least one data source file.")
        return

    print(f"[*] Loading data from {len(active_sources)} source(s): "
          f"{', '.join(active_sources.keys())}")

    findings = normalize_all_sources(source_files)
    print(f"[*] Normalized {len(findings)} findings")

    if args.normalize_only:
        output = json.dumps(findings, indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"[*] Normalized findings saved to {args.output}")
        else:
            print(output)
        return

    print("[*] Performing cross-source correlation...")
    entities = correlate_findings(findings)
    print(f"[*] Identified {len(entities)} entities")

    report = generate_report(findings, entities, target=args.target)

    output = json.dumps(report, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"[*] JSON report saved to {args.output}")
    else:
        print(output)

    if args.markdown:
        generate_markdown_report(report, args.markdown)


if __name__ == "__main__":
    main()
