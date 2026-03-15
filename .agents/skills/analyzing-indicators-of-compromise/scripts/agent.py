#!/usr/bin/env python3
"""IOC analysis and enrichment agent using VirusTotal, AbuseIPDB, and MalwareBazaar APIs."""

import re
import os
import sys
import json
import hashlib
import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def classify_ioc(value):
    """Classify an IOC by type: ipv4, domain, url, sha256, sha1, md5, email."""
    value = value.strip()
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
        return "ipv4"
    if re.match(r"^[a-fA-F0-9]{64}$", value):
        return "sha256"
    if re.match(r"^[a-fA-F0-9]{40}$", value):
        return "sha1"
    if re.match(r"^[a-fA-F0-9]{32}$", value):
        return "md5"
    if re.match(r"^https?://", value):
        return "url"
    if re.match(r"^[^@]+@[^@]+\.[^@]+$", value):
        return "email"
    if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value):
        return "domain"
    return "unknown"


def defang_ioc(value):
    """Defang an IOC for safe documentation."""
    value = value.replace("http://", "hxxp://")
    value = value.replace("https://", "hxxps://")
    value = re.sub(r"\.(?=\w)", "[.]", value)
    return value


def refang_ioc(value):
    """Refang a defanged IOC for querying APIs."""
    value = value.replace("hxxp://", "http://")
    value = value.replace("hxxps://", "https://")
    value = value.replace("[.]", ".")
    value = value.replace("[://]", "://")
    return value


def is_private_ip(ip):
    """Check if an IP is RFC 1918 private."""
    octets = [int(o) for o in ip.split(".")]
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    if octets[0] == 127:
        return True
    return False


def query_virustotal_hash(sha256, api_key):
    """Query VirusTotal for a file hash."""
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    resp = requests.get(url, headers={"x-apikey": api_key})
    if resp.status_code == 200:
        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "sha256": sha256,
            "malicious": stats.get("malicious", 0),
            "total": sum(stats.values()),
            "type_description": data.get("type_description", ""),
            "popular_threat_name": data.get("popular_threat_classification", {}).get(
                "suggested_threat_label", ""),
            "tags": data.get("tags", []),
        }
    return None


def query_virustotal_domain(domain, api_key):
    """Query VirusTotal for domain reputation."""
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    resp = requests.get(url, headers={"x-apikey": api_key})
    if resp.status_code == 200:
        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "domain": domain,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "reputation": data.get("reputation", 0),
            "registrar": data.get("registrar", ""),
            "creation_date": data.get("creation_date", ""),
        }
    return None


def query_abuseipdb(ip, api_key, max_age_days=90):
    """Query AbuseIPDB for IP reputation."""
    url = "https://api.abuseipdb.com/api/v2/check"
    resp = requests.get(url, headers={"Key": api_key, "Accept": "application/json"},
                        params={"ipAddress": ip, "maxAgeInDays": max_age_days})
    if resp.status_code == 200:
        data = resp.json().get("data", {})
        return {
            "ip": ip,
            "abuse_confidence": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
            "domain": data.get("domain", ""),
            "is_tor": data.get("isTor", False),
        }
    return None


def query_malwarebazaar(sha256):
    """Query MalwareBazaar for file hash information."""
    url = "https://mb-api.abuse.ch/api/v1/"
    resp = requests.post(url, data={"query": "get_info", "hash": sha256})
    if resp.status_code == 200:
        result = resp.json()
        if result.get("query_status") == "ok" and result.get("data"):
            entry = result["data"][0]
            return {
                "sha256": sha256,
                "signature": entry.get("signature", ""),
                "tags": entry.get("tags", []),
                "file_type": entry.get("file_type", ""),
                "reporter": entry.get("reporter", ""),
                "first_seen": entry.get("first_seen", ""),
            }
    return None


def score_ioc(vt_result=None, abuse_result=None, mb_result=None):
    """Assign a confidence score and disposition to an IOC."""
    score = 0
    reasons = []
    if vt_result:
        malicious = vt_result.get("malicious", 0)
        if malicious >= 15:
            score += 40
            reasons.append(f"VT: {malicious} detections (high)")
        elif malicious >= 5:
            score += 20
            reasons.append(f"VT: {malicious} detections (moderate)")
        elif malicious > 0:
            score += 5
            reasons.append(f"VT: {malicious} detections (low)")
    if abuse_result:
        abuse_score = abuse_result.get("abuse_confidence", 0)
        if abuse_score >= 70:
            score += 30
            reasons.append(f"AbuseIPDB: {abuse_score}% confidence")
        elif abuse_score >= 30:
            score += 15
            reasons.append(f"AbuseIPDB: {abuse_score}% confidence")
    if mb_result:
        score += 30
        reasons.append(f"MalwareBazaar: {mb_result.get('signature', 'known malware')}")

    if score >= 70:
        disposition = "BLOCK"
    elif score >= 40:
        disposition = "MONITOR"
    else:
        disposition = "INVESTIGATE"

    return {"score": score, "disposition": disposition, "reasons": reasons}


def enrich_ioc(value, vt_key=None, abuse_key=None):
    """Enrich a single IOC with multi-source intelligence."""
    ioc_type = classify_ioc(value)
    result = {
        "ioc": value,
        "type": ioc_type,
        "defanged": defang_ioc(value),
        "enrichment": {},
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    }
    if not HAS_REQUESTS:
        result["error"] = "requests library not installed"
        return result
    if ioc_type == "ipv4" and is_private_ip(value):
        result["note"] = "RFC 1918 private IP - skipping external enrichment"
        return result
    if ioc_type in ("sha256", "sha1", "md5") and vt_key:
        result["enrichment"]["virustotal"] = query_virustotal_hash(value, vt_key)
        result["enrichment"]["malwarebazaar"] = query_malwarebazaar(value)
    elif ioc_type == "ipv4":
        if abuse_key:
            result["enrichment"]["abuseipdb"] = query_abuseipdb(value, abuse_key)
        if vt_key:
            result["enrichment"]["virustotal"] = query_virustotal_domain(value, vt_key)
    elif ioc_type == "domain" and vt_key:
        result["enrichment"]["virustotal"] = query_virustotal_domain(value, vt_key)

    scoring = score_ioc(
        result["enrichment"].get("virustotal"),
        result["enrichment"].get("abuseipdb"),
        result["enrichment"].get("malwarebazaar"),
    )
    result["score"] = scoring["score"]
    result["disposition"] = scoring["disposition"]
    result["reasons"] = scoring["reasons"]
    return result


if __name__ == "__main__":
    print("=" * 60)
    print("IOC Analysis & Enrichment Agent")
    print("VirusTotal, AbuseIPDB, MalwareBazaar integration")
    print("=" * 60)

    demo_iocs = [
        "185.220.101.42",
        "evil-domain.com",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "http://malicious-site.com/payload.exe",
        "192.168.1.100",
    ]

    print("\n--- IOC Classification & Defanging ---")
    for ioc in demo_iocs:
        ioc_type = classify_ioc(ioc)
        defanged = defang_ioc(ioc)
        private = " (private)" if ioc_type == "ipv4" and is_private_ip(ioc) else ""
        print(f"  {ioc_type:8s} | {defanged}{private}")

    vt_key = os.environ.get("VT_API_KEY")
    abuse_key = os.environ.get("ABUSEIPDB_API_KEY")

    if vt_key or abuse_key:
        print("\n--- Enrichment (live API queries) ---")
        for ioc in demo_iocs:
            result = enrich_ioc(ioc, vt_key, abuse_key)
            print(f"\n  {result['ioc']} ({result['type']})")
            print(f"    Disposition: {result.get('disposition', 'N/A')} "
                  f"(score: {result.get('score', 0)})")
            for reason in result.get("reasons", []):
                print(f"    - {reason}")
    else:
        print("\n[*] Set VT_API_KEY and/or ABUSEIPDB_API_KEY environment variables for live enrichment.")
