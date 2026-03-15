#!/usr/bin/env python3
"""Agent for automating IOC enrichment with VirusTotal, AbuseIPDB, and STIX."""

import os
import re
import json
import time
import argparse
from datetime import datetime
from dataclasses import dataclass, field

import requests
from stix2 import Indicator, Bundle


RATE_LIMIT_DELAY = 0.25


@dataclass
class EnrichmentResult:
    ioc_value: str
    ioc_type: str
    vt_malicious: int = 0
    vt_total: int = 0
    vt_threat_label: str = ""
    abuse_confidence: int = 0
    abuse_reports: int = 0
    shodan_ports: list = field(default_factory=list)
    confidence_score: int = 0


def classify_ioc(value):
    """Auto-detect IOC type from value."""
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
        return "ip"
    if re.match(r"^[a-fA-F0-9]{64}$", value):
        return "sha256"
    if re.match(r"^[a-fA-F0-9]{32}$", value):
        return "md5"
    if re.match(r"^https?://", value):
        return "url"
    return "domain"


def enrich_ip_virustotal(ip, api_key):
    """Enrich an IP address via VirusTotal API v3."""
    resp = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": api_key},
    )
    if resp.status_code == 200:
        attrs = resp.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "total": sum(stats.values()),
            "country": attrs.get("country", ""),
            "asn": attrs.get("asn", 0),
            "as_owner": attrs.get("as_owner", ""),
        }
    return {}


def enrich_hash_virustotal(file_hash, api_key):
    """Enrich a file hash via VirusTotal API v3."""
    resp = requests.get(
        f"https://www.virustotal.com/api/v3/files/{file_hash}",
        headers={"x-apikey": api_key},
    )
    if resp.status_code == 200:
        attrs = resp.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        ptc = attrs.get("popular_threat_classification", {})
        return {
            "malicious": stats.get("malicious", 0),
            "total": sum(stats.values()),
            "threat_label": ptc.get("suggested_threat_label", ""),
            "type_description": attrs.get("type_description", ""),
        }
    return {}


def enrich_domain_virustotal(domain, api_key):
    """Enrich a domain via VirusTotal API v3."""
    resp = requests.get(
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers={"x-apikey": api_key},
    )
    if resp.status_code == 200:
        attrs = resp.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "total": sum(stats.values()),
            "registrar": attrs.get("registrar", ""),
        }
    return {}


def enrich_ip_abuseipdb(ip, api_key):
    """Check an IP against AbuseIPDB."""
    resp = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
    )
    if resp.status_code == 200:
        data = resp.json()["data"]
        return {
            "abuse_confidence": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
        }
    return {}


def compute_confidence(vt_result, abuse_result=None):
    """Calculate composite confidence score from enrichment sources."""
    vt_score = 0
    if vt_result.get("total", 0) > 0:
        vt_score = (vt_result["malicious"] / vt_result["total"]) * 60
    abuse_score = 0
    if abuse_result:
        abuse_score = (abuse_result.get("abuse_confidence", 0) / 100) * 40
    return min(int(vt_score + abuse_score), 100)


def enrich_ioc(value, ioc_type, vt_key, abuse_key=None):
    """Enrich a single IOC through all available sources."""
    result = EnrichmentResult(ioc_value=value, ioc_type=ioc_type)
    vt_data = {}
    if ioc_type == "ip":
        vt_data = enrich_ip_virustotal(value, vt_key)
        time.sleep(RATE_LIMIT_DELAY)
        if abuse_key:
            abuse_data = enrich_ip_abuseipdb(value, abuse_key)
            result.abuse_confidence = abuse_data.get("abuse_confidence", 0)
            result.abuse_reports = abuse_data.get("total_reports", 0)
    elif ioc_type in ("sha256", "md5"):
        vt_data = enrich_hash_virustotal(value, vt_key)
        time.sleep(RATE_LIMIT_DELAY)
    elif ioc_type == "domain":
        vt_data = enrich_domain_virustotal(value, vt_key)
        time.sleep(RATE_LIMIT_DELAY)

    result.vt_malicious = vt_data.get("malicious", 0)
    result.vt_total = vt_data.get("total", 0)
    result.vt_threat_label = vt_data.get("threat_label", "")
    abuse_dict = {"abuse_confidence": result.abuse_confidence} if ioc_type == "ip" else None
    result.confidence_score = compute_confidence(vt_data, abuse_dict)
    return result


def export_stix_indicators(results, output_path):
    """Export enriched IOCs as STIX 2.1 indicators."""
    pattern_map = {
        "ip": lambda v: f"[ipv4-addr:value = '{v}']",
        "domain": lambda v: f"[domain-name:value = '{v}']",
        "sha256": lambda v: f"[file:hashes.'SHA-256' = '{v}']",
        "md5": lambda v: f"[file:hashes.MD5 = '{v}']",
        "url": lambda v: f"[url:value = '{v}']",
    }
    indicators = []
    for r in results:
        pattern_fn = pattern_map.get(r.ioc_type)
        if pattern_fn:
            ind = Indicator(
                name=f"{r.ioc_type}: {r.ioc_value}",
                pattern=pattern_fn(r.ioc_value),
                pattern_type="stix",
                valid_from=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                confidence=r.confidence_score,
            )
            indicators.append(ind)
    bundle = Bundle(objects=indicators, allow_custom=True)
    with open(output_path, "w") as f:
        f.write(bundle.serialize(pretty=True))
    return len(indicators)


def main():
    parser = argparse.ArgumentParser(description="IOC Enrichment Automation Agent")
    parser.add_argument("--vt-key", default=os.getenv("VT_API_KEY"), help="VirusTotal API key")
    parser.add_argument("--abuse-key", default=os.getenv("ABUSEIPDB_KEY"), help="AbuseIPDB API key")
    parser.add_argument("--ioc-file", help="File with IOCs (one per line)")
    parser.add_argument("--ioc", help="Single IOC to enrich")
    parser.add_argument("--output", default="enrichment_results.json")
    parser.add_argument("--stix-output", help="Export as STIX bundle")
    args = parser.parse_args()

    iocs = []
    if args.ioc:
        iocs.append(args.ioc)
    if args.ioc_file:
        with open(args.ioc_file) as f:
            iocs.extend(line.strip() for line in f if line.strip() and not line.startswith("#"))

    results = []
    for ioc_val in iocs:
        ioc_type = classify_ioc(ioc_val)
        print(f"  Enriching {ioc_type}: {ioc_val}...")
        result = enrich_ioc(ioc_val, ioc_type, args.vt_key, args.abuse_key)
        results.append(result)
        verdict = "MALICIOUS" if result.confidence_score >= 70 else "SUSPICIOUS" if result.confidence_score >= 40 else "CLEAN"
        print(f"    VT: {result.vt_malicious}/{result.vt_total} | Confidence: {result.confidence_score} | {verdict}")

    report = {
        "enriched_at": datetime.utcnow().isoformat(),
        "total_iocs": len(results),
        "results": [r.__dict__ for r in results],
    }
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Results saved to {args.output}")

    if args.stix_output:
        count = export_stix_indicators(results, args.stix_output)
        print(f"[+] Exported {count} STIX indicators to {args.stix_output}")


if __name__ == "__main__":
    main()
