#!/usr/bin/env python3
"""IOC Defanging and Sharing Pipeline Agent - Defangs, enriches, and shares IOCs in STIX format."""

import json
import logging
import argparse
import os
import re
from datetime import datetime

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"),
    "url": re.compile(r"https?://[^\s\"'<>]+"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "email": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
}

EXCLUSION_DOMAINS = {"example.com", "example.org", "example.net", "localhost", "schema.org",
                     "w3.org", "microsoft.com", "google.com", "github.com"}


def extract_iocs(text):
    """Extract IOCs from raw text."""
    results = {}
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = set(pattern.findall(text))
        if ioc_type == "domain":
            matches = {m for m in matches if m.split(".")[-1] not in {"py", "js", "json", "xml", "yml"}
                       and m not in EXCLUSION_DOMAINS and not any(excl in m for excl in EXCLUSION_DOMAINS)}
        results[ioc_type] = list(matches)
    logger.info("Extracted IOCs: %s", {k: len(v) for k, v in results.items()})
    return results


def defang_ioc(value, ioc_type):
    """Defang an IOC for safe sharing."""
    if ioc_type == "ipv4":
        return value.replace(".", "[.]")
    elif ioc_type in ("domain", "email"):
        return value.replace(".", "[.]")
    elif ioc_type == "url":
        return value.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")
    return value


def refang_ioc(value, ioc_type):
    """Refang a defanged IOC back to original form."""
    if ioc_type in ("ipv4", "domain", "email"):
        return value.replace("[.]", ".")
    elif ioc_type == "url":
        return value.replace("hxxp://", "http://").replace("hxxps://", "https://").replace("[.]", ".")
    return value


def enrich_ioc(value, ioc_type, vt_key=None, abuseipdb_key=None):
    """Enrich IOC with threat intelligence from VirusTotal and AbuseIPDB."""
    vt_key = vt_key or os.environ.get("VT_API_KEY", "")
    abuseipdb_key = abuseipdb_key or os.environ.get("ABUSEIPDB_KEY", "")
    enrichment = {"value": value, "type": ioc_type, "sources": []}
    if ioc_type in ("md5", "sha256") and vt_key:
        try:
            resp = requests.get(f"https://www.virustotal.com/api/v3/files/{value}",
                                headers={"x-apikey": vt_key}, timeout=10)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                enrichment["vt_malicious"] = data.get("malicious", 0)
                enrichment["sources"].append("virustotal")
        except requests.RequestException:
            pass
    elif ioc_type == "ipv4" and abuseipdb_key:
        try:
            resp = requests.get("https://api.abuseipdb.com/api/v2/check",
                                params={"ipAddress": value, "maxAgeInDays": 90},
                                headers={"Key": abuseipdb_key, "Accept": "application/json"}, timeout=10)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                enrichment["abuse_score"] = data.get("abuseConfidenceScore", 0)
                enrichment["sources"].append("abuseipdb")
        except requests.RequestException:
            pass
    return enrichment


def to_stix_bundle(iocs):
    """Convert IOCs to STIX 2.1 bundle for sharing."""
    objects = []
    stix_type_map = {"ipv4": "ipv4-addr", "domain": "domain-name", "url": "url",
                     "md5": "file", "sha256": "file", "email": "email-addr"}
    for ioc_type, values in iocs.items():
        for value in values:
            stype = stix_type_map.get(ioc_type)
            if not stype:
                continue
            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{hash(value) % (10**12):012d}",
                "created": datetime.utcnow().isoformat() + "Z",
                "pattern_type": "stix",
                "pattern": f"[{stype}:value = '{value}']" if stype != "file"
                           else f"[file:hashes.'{ioc_type.upper()}' = '{value}']",
                "valid_from": datetime.utcnow().isoformat() + "Z",
                "labels": ["malicious-activity"],
            }
            objects.append(indicator)
    bundle = {"type": "bundle", "id": f"bundle--{hash(str(iocs)) % (10**12):012d}",
              "objects": objects}
    logger.info("Created STIX bundle with %d indicators", len(objects))
    return bundle


def defang_all(iocs):
    """Defang all extracted IOCs."""
    defanged = {}
    for ioc_type, values in iocs.items():
        defanged[ioc_type] = [{"original": v, "defanged": defang_ioc(v, ioc_type)} for v in values]
    return defanged


def generate_report(iocs, defanged, stix_bundle):
    """Generate IOC sharing pipeline report."""
    total = sum(len(v) for v in iocs.values())
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "total_iocs": total,
        "by_type": {k: len(v) for k, v in iocs.items()},
        "defanged_iocs": defanged,
        "stix_indicator_count": len(stix_bundle.get("objects", [])),
        "stix_bundle": stix_bundle,
    }
    print(f"IOC PIPELINE REPORT: {total} IOCs extracted, {len(stix_bundle.get('objects', []))} STIX indicators")
    return report


def main():
    parser = argparse.ArgumentParser(description="IOC Defanging and Sharing Pipeline")
    parser.add_argument("--input-file", required=True, help="Text file containing IOCs")
    parser.add_argument("--enrich", action="store_true", help="Enrich IOCs with threat intel")
    parser.add_argument("--vt-key", default=os.environ.get("VT_API_KEY", ""), help="VirusTotal API key")
    parser.add_argument("--abuseipdb-key", default=os.environ.get("ABUSEIPDB_KEY", ""), help="AbuseIPDB API key")
    parser.add_argument("--output", default="ioc_pipeline_report.json")
    args = parser.parse_args()

    with open(args.input_file) as f:
        text = f.read()

    iocs = extract_iocs(text)
    defanged = defang_all(iocs)
    stix_bundle = to_stix_bundle(iocs)

    if args.enrich:
        enrichments = []
        for ioc_type, values in iocs.items():
            for value in values[:10]:
                enrichments.append(enrich_ioc(value, ioc_type, args.vt_key, args.abuseipdb_key))
        logger.info("Enriched %d IOCs", len(enrichments))

    report = generate_report(iocs, defanged, stix_bundle)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
