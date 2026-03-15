#!/usr/bin/env python3
"""Agent for performing IOC enrichment automation.

Orchestrates multi-source IOC lookups across VirusTotal, AbuseIPDB,
Shodan, and GreyNoise to provide contextual scoring and disposition.
"""

import requests
import json
import sys
import time
from dataclasses import dataclass, field


@dataclass
class EnrichmentResult:
    ioc_value: str
    ioc_type: str
    virustotal: dict = field(default_factory=dict)
    abuseipdb: dict = field(default_factory=dict)
    shodan_data: dict = field(default_factory=dict)
    greynoise: dict = field(default_factory=dict)
    risk_score: float = 0.0
    disposition: str = "Unknown"


class IOCEnrichmentAgent:
    """Multi-source IOC enrichment engine."""

    def __init__(self, vt_key, abuseipdb_key="", shodan_key="", greynoise_key=""):
        self.vt_key = vt_key
        self.abuseipdb_key = abuseipdb_key
        self.shodan_key = shodan_key
        self.greynoise_key = greynoise_key

    def _vt_lookup(self, endpoint):
        """Query VirusTotal API v3."""
        headers = {"x-apikey": self.vt_key}
        resp = requests.get(f"https://www.virustotal.com/api/v3/{endpoint}",
                            headers=headers, timeout=15)
        if resp.status_code == 200:
            return resp.json().get("data", {}).get("attributes", {})
        return {"error": resp.status_code}

    def enrich_ip(self, ip_address):
        """Enrich an IP address from multiple sources."""
        result = EnrichmentResult(ioc_value=ip_address, ioc_type="ip")

        vt_data = self._vt_lookup(f"ip_addresses/{ip_address}")
        if "error" not in vt_data:
            stats = vt_data.get("last_analysis_stats", {})
            result.virustotal = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "total": sum(stats.values()) if stats else 0,
                "country": vt_data.get("country", "Unknown"),
                "as_owner": vt_data.get("as_owner", "Unknown"),
                "reputation": vt_data.get("reputation", 0),
            }

        if self.abuseipdb_key:
            try:
                resp = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                    params={"ipAddress": ip_address, "maxAgeInDays": 90},
                    timeout=10,
                )
                data = resp.json().get("data", {})
                result.abuseipdb = {
                    "confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "is_tor": data.get("isTor", False),
                    "isp": data.get("isp", "Unknown"),
                }
            except requests.RequestException:
                pass

        if self.shodan_key:
            try:
                resp = requests.get(
                    f"https://api.shodan.io/shodan/host/{ip_address}",
                    params={"key": self.shodan_key}, timeout=10,
                )
                if resp.status_code == 200:
                    host = resp.json()
                    result.shodan_data = {
                        "ports": host.get("ports", []),
                        "os": host.get("os"),
                        "org": host.get("org", "Unknown"),
                        "vulns": host.get("vulns", []),
                    }
            except requests.RequestException:
                pass

        if self.greynoise_key:
            try:
                resp = requests.get(
                    f"https://api.greynoise.io/v3/community/{ip_address}",
                    headers={"key": self.greynoise_key}, timeout=10,
                )
                gn = resp.json()
                result.greynoise = {
                    "classification": gn.get("classification", "unknown"),
                    "noise": gn.get("noise", False),
                    "riot": gn.get("riot", False),
                    "name": gn.get("name", "Unknown"),
                }
            except requests.RequestException:
                pass

        result.risk_score = self._score_ip(result)
        result.disposition = self._disposition(result.risk_score)
        return result

    def enrich_domain(self, domain):
        """Enrich a domain from VirusTotal."""
        result = EnrichmentResult(ioc_value=domain, ioc_type="domain")
        vt_data = self._vt_lookup(f"domains/{domain}")
        if "error" not in vt_data:
            stats = vt_data.get("last_analysis_stats", {})
            result.virustotal = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "reputation": vt_data.get("reputation", 0),
                "registrar": vt_data.get("registrar", "Unknown"),
            }
        result.risk_score = min(result.virustotal.get("malicious", 0) * 5, 100)
        result.disposition = self._disposition(result.risk_score)
        return result

    def enrich_hash(self, file_hash):
        """Enrich a file hash from VirusTotal."""
        result = EnrichmentResult(ioc_value=file_hash, ioc_type="hash")
        vt_data = self._vt_lookup(f"files/{file_hash}")
        if "error" not in vt_data:
            stats = vt_data.get("last_analysis_stats", {})
            total = sum(stats.values()) if stats else 1
            result.virustotal = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "total": total,
                "type": vt_data.get("type_description", "Unknown"),
                "threat_label": vt_data.get("popular_threat_classification", {}).get(
                    "suggested_threat_label", "Unknown"),
            }
            detection_rate = stats.get("malicious", 0) / max(total, 1)
            result.risk_score = min(detection_rate * 100, 100)
        result.disposition = self._disposition(result.risk_score)
        return result

    def _score_ip(self, result):
        score = 0
        vt = result.virustotal
        if isinstance(vt, dict) and "malicious" in vt:
            score += min(vt["malicious"] * 3, 30)
        abuse = result.abuseipdb
        if isinstance(abuse, dict) and "confidence_score" in abuse:
            score += abuse["confidence_score"] * 0.3
        gn = result.greynoise
        if isinstance(gn, dict):
            if gn.get("classification") == "malicious":
                score += 20
            elif gn.get("riot"):
                score -= 20
        return min(max(score, 0), 100)

    def _disposition(self, score):
        if score >= 70:
            return "MALICIOUS"
        elif score >= 40:
            return "SUSPICIOUS"
        elif score >= 10:
            return "LOW_RISK"
        return "CLEAN"

    def enrich_batch(self, iocs, delay=1):
        """Enrich a list of IOCs with rate limiting."""
        results = []
        for ioc in iocs:
            ioc_type = ioc.get("type", "ip")
            value = ioc.get("value", "")
            if ioc_type == "ip":
                results.append(self.enrich_ip(value))
            elif ioc_type == "domain":
                results.append(self.enrich_domain(value))
            elif ioc_type == "hash":
                results.append(self.enrich_hash(value))
            time.sleep(delay)
        return results

    def generate_report(self, results):
        """Generate enrichment report from results."""
        report = {"iocs": [], "summary": {}}
        for r in results:
            report["iocs"].append({
                "value": r.ioc_value,
                "type": r.ioc_type,
                "risk_score": r.risk_score,
                "disposition": r.disposition,
                "virustotal": r.virustotal,
                "abuseipdb": r.abuseipdb,
                "shodan": r.shodan_data,
                "greynoise": r.greynoise,
            })
        report["summary"] = {
            "total": len(results),
            "malicious": sum(1 for r in results if r.disposition == "MALICIOUS"),
            "suspicious": sum(1 for r in results if r.disposition == "SUSPICIOUS"),
            "clean": sum(1 for r in results if r.disposition == "CLEAN"),
        }
        return report


def main():
    if len(sys.argv) < 3:
        print("Usage: agent.py <vt_api_key> <ioc_type> <ioc_value> [abuseipdb_key] [shodan_key]")
        sys.exit(1)

    vt_key = sys.argv[1]
    ioc_type = sys.argv[2]
    ioc_value = sys.argv[3]
    abuse_key = sys.argv[4] if len(sys.argv) > 4 else ""
    shodan_key = sys.argv[5] if len(sys.argv) > 5 else ""

    agent = IOCEnrichmentAgent(vt_key, abuse_key, shodan_key)
    if ioc_type == "ip":
        result = agent.enrich_ip(ioc_value)
    elif ioc_type == "domain":
        result = agent.enrich_domain(ioc_value)
    elif ioc_type == "hash":
        result = agent.enrich_hash(ioc_value)
    else:
        print(f"Unknown IOC type: {ioc_type}")
        sys.exit(1)

    report = agent.generate_report([result])
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
