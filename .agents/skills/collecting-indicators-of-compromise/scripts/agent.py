#!/usr/bin/env python3
"""IOC Collection Agent - Extracts, enriches, and exports indicators of compromise."""

import json
import re
import hashlib
import logging
import argparse
from datetime import datetime

import requests
from stix2 import Indicator, Bundle

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")


def extract_iocs_from_text(text):
    """Extract IOCs (IPs, domains, hashes, URLs) from unstructured text."""
    iocs = {
        "ipv4": list(set(IPV4_PATTERN.findall(text))),
        "domain": list(set(DOMAIN_PATTERN.findall(text))),
        "sha256": list(set(SHA256_PATTERN.findall(text))),
        "md5": list(set(MD5_PATTERN.findall(text))),
        "url": list(set(URL_PATTERN.findall(text))),
    }
    total = sum(len(v) for v in iocs.values())
    logger.info("Extracted %d IOCs from text input", total)
    return iocs


def extract_iocs_from_file(file_path):
    """Extract IOCs from a file (text report, log file, etc.)."""
    with open(file_path, "r", errors="ignore") as f:
        content = f.read()
    return extract_iocs_from_text(content)


def enrich_ip_virustotal(ip_address, api_key):
    """Enrich an IP address using VirusTotal API."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}
    resp = requests.get(url, headers=headers, timeout=30)
    if resp.status_code == 200:
        data = resp.json()["data"]["attributes"]
        result = {
            "ip": ip_address,
            "malicious": data.get("last_analysis_stats", {}).get("malicious", 0),
            "country": data.get("country", "unknown"),
            "asn": data.get("asn", 0),
            "as_owner": data.get("as_owner", "unknown"),
        }
        logger.info("VT enrichment for %s: %d malicious detections", ip_address, result["malicious"])
        return result
    return {"ip": ip_address, "error": resp.status_code}


def enrich_hash_malwarebazaar(file_hash):
    """Enrich a file hash using MalwareBazaar API."""
    url = "https://mb-api.abuse.ch/api/v1/"
    resp = requests.post(url, data={"query": "get_info", "hash": file_hash}, timeout=30)
    result = resp.json()
    if result.get("query_status") == "ok":
        sample = result["data"][0]
        return {
            "hash": file_hash,
            "family": sample.get("signature", "unknown"),
            "file_type": sample.get("file_type", "unknown"),
            "tags": sample.get("tags", []),
            "first_seen": sample.get("first_seen"),
        }
    return {"hash": file_hash, "status": "not_found"}


def enrich_domain_abuseipdb(domain, api_key):
    """Check domain reputation via AbuseIPDB."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    resp = requests.get(url, headers=headers, params={"ipAddress": domain}, timeout=30)
    if resp.status_code == 200:
        data = resp.json()["data"]
        return {
            "domain": domain,
            "abuse_confidence": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", "unknown"),
        }
    return {"domain": domain, "error": resp.status_code}


def score_ioc(ioc_type, enrichment_data):
    """Assign confidence score (0-100) based on enrichment results."""
    if ioc_type == "ipv4":
        malicious_count = enrichment_data.get("malicious", 0)
        if malicious_count >= 10:
            return 95
        elif malicious_count >= 5:
            return 80
        elif malicious_count >= 1:
            return 60
        return 30
    elif ioc_type in ("sha256", "md5"):
        if enrichment_data.get("family") and enrichment_data["family"] != "unknown":
            return 95
        return 50
    return 50


def export_stix_bundle(iocs_with_scores, output_path):
    """Export IOCs as a STIX 2.1 bundle."""
    pattern_map = {
        "ipv4": lambda v: f"[ipv4-addr:value = '{v}']",
        "domain": lambda v: f"[domain-name:value = '{v}']",
        "url": lambda v: f"[url:value = '{v}']",
        "sha256": lambda v: f"[file:hashes.'SHA-256' = '{v}']",
        "md5": lambda v: f"[file:hashes.MD5 = '{v}']",
    }
    stix_indicators = []
    for ioc in iocs_with_scores:
        ioc_type = ioc["type"]
        pattern_fn = pattern_map.get(ioc_type)
        if pattern_fn:
            indicator = Indicator(
                name=f"{ioc_type}: {ioc['value']}",
                pattern=pattern_fn(ioc["value"]),
                pattern_type="stix",
                valid_from=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                confidence=ioc.get("confidence", 50),
                labels=[ioc_type],
            )
            stix_indicators.append(indicator)

    bundle = Bundle(objects=stix_indicators)
    with open(output_path, "w") as f:
        f.write(bundle.serialize(pretty=True))
    logger.info("STIX bundle exported: %d indicators to %s", len(stix_indicators), output_path)


def generate_ioc_report(iocs_with_scores):
    """Print a formatted IOC report."""
    lines = [
        "INDICATOR OF COMPROMISE REPORT",
        "=" * 40,
        f"Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        f"Total IOCs: {len(iocs_with_scores)}",
        "",
    ]
    for ioc_type in ["ipv4", "domain", "sha256", "md5", "url"]:
        typed = [i for i in iocs_with_scores if i["type"] == ioc_type]
        if typed:
            lines.append(f"\n{ioc_type.upper()} ({len(typed)}):")
            for ioc in typed[:10]:
                lines.append(f"  {ioc['value'][:60]:60s} Confidence: {ioc.get('confidence', 'N/A')}")
    print("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description="IOC Collection Agent")
    parser.add_argument("--input-file", help="File to extract IOCs from")
    parser.add_argument("--input-text", help="Text string to extract IOCs from")
    parser.add_argument("--vt-key", help="VirusTotal API key for enrichment")
    parser.add_argument("--output", default="ioc_bundle.json", help="STIX bundle output")
    args = parser.parse_args()

    raw_iocs = {}
    if args.input_file:
        raw_iocs = extract_iocs_from_file(args.input_file)
    elif args.input_text:
        raw_iocs = extract_iocs_from_text(args.input_text)

    iocs_with_scores = []
    for ioc_type, values in raw_iocs.items():
        for value in values:
            entry = {"type": ioc_type, "value": value, "confidence": 50}
            if ioc_type == "ipv4" and args.vt_key:
                enrichment = enrich_ip_virustotal(value, args.vt_key)
                entry["confidence"] = score_ioc("ipv4", enrichment)
                entry["enrichment"] = enrichment
            elif ioc_type in ("sha256", "md5"):
                enrichment = enrich_hash_malwarebazaar(value)
                entry["confidence"] = score_ioc(ioc_type, enrichment)
                entry["enrichment"] = enrichment
            iocs_with_scores.append(entry)

    generate_ioc_report(iocs_with_scores)
    export_stix_bundle(iocs_with_scores, args.output)


if __name__ == "__main__":
    main()
