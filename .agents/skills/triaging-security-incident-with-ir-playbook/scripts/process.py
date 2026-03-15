#!/usr/bin/env python3
"""
Security Incident Triage Automation Script

Automates incident triage workflow:
- Enriches IOCs with threat intelligence APIs
- Calculates severity based on asset criticality and threat level
- Selects appropriate IR playbook
- Creates incident tickets
- Generates triage report

Requirements:
    pip install requests pyyaml
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Optional

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("incident_triage")

# Incident type to playbook mapping
PLAYBOOK_MAP = {
    "malware": {"playbook": "malware_ir_v2", "team": "malware_analysis"},
    "ransomware": {"playbook": "ransomware_ir_v3", "team": "ransomware_response"},
    "phishing": {"playbook": "phishing_ir_v2", "team": "email_security"},
    "unauthorized_access": {"playbook": "access_compromise_v2", "team": "identity_response"},
    "data_exfiltration": {"playbook": "data_breach_v2", "team": "data_protection"},
    "ddos": {"playbook": "ddos_response_v1", "team": "network_operations"},
    "insider_threat": {"playbook": "insider_threat_v2", "team": "insider_risk"},
    "account_compromise": {"playbook": "account_compromise_v2", "team": "identity_response"},
    "web_attack": {"playbook": "web_attack_v2", "team": "application_security"},
    "privilege_escalation": {"playbook": "privesc_ir_v1", "team": "identity_response"},
    "lateral_movement": {"playbook": "lateral_movement_v1", "team": "network_defense"},
    "supply_chain": {"playbook": "supply_chain_v1", "team": "third_party_risk"},
}

# Severity calculation weights
SEVERITY_WEIGHTS = {
    "asset_criticality": {"critical": 4, "high": 3, "medium": 2, "low": 1},
    "data_sensitivity": {"pii_phi": 4, "pci": 3, "confidential": 2, "public": 1},
    "threat_status": {"active": 4, "confirmed": 3, "attempted": 2, "recon": 1},
    "scope": {"enterprise": 4, "department": 3, "single_system": 2, "single_user": 1},
}


class IOCEnricher:
    """Enrich IOCs with external threat intelligence sources."""

    def __init__(self, vt_api_key: str = "", abuseipdb_key: str = ""):
        self.vt_api_key = vt_api_key or os.getenv("VT_API_KEY", "")
        self.abuseipdb_key = abuseipdb_key or os.getenv("ABUSEIPDB_KEY", "")

    def enrich_ip(self, ip_address: str) -> dict:
        result = {"ip": ip_address, "sources": {}}

        # VirusTotal
        if self.vt_api_key:
            try:
                resp = requests.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
                    headers={"x-apikey": self.vt_api_key},
                    timeout=10,
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    result["sources"]["virustotal"] = {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "reputation": data.get("reputation", 0),
                        "country": data.get("country", "unknown"),
                        "as_owner": data.get("as_owner", "unknown"),
                    }
                    logger.info(f"VT enrichment for {ip_address}: {stats.get('malicious', 0)} malicious")
            except Exception as e:
                logger.warning(f"VT enrichment failed for {ip_address}: {e}")

        # AbuseIPDB
        if self.abuseipdb_key:
            try:
                resp = requests.get(
                    f"https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip_address, "maxAgeInDays": 90},
                    headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                    timeout=10,
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    result["sources"]["abuseipdb"] = {
                        "abuse_confidence": data.get("abuseConfidenceScore", 0),
                        "total_reports": data.get("totalReports", 0),
                        "country_code": data.get("countryCode", ""),
                        "isp": data.get("isp", ""),
                        "is_tor": data.get("isTor", False),
                    }
                    logger.info(f"AbuseIPDB for {ip_address}: confidence={data.get('abuseConfidenceScore', 0)}%")
            except Exception as e:
                logger.warning(f"AbuseIPDB enrichment failed for {ip_address}: {e}")

        # Calculate overall threat score
        vt_malicious = result.get("sources", {}).get("virustotal", {}).get("malicious", 0)
        abuse_score = result.get("sources", {}).get("abuseipdb", {}).get("abuse_confidence", 0)
        result["threat_score"] = min(100, (vt_malicious * 5) + abuse_score)
        result["threat_level"] = (
            "critical" if result["threat_score"] >= 80
            else "high" if result["threat_score"] >= 50
            else "medium" if result["threat_score"] >= 20
            else "low"
        )
        return result

    def enrich_hash(self, file_hash: str) -> dict:
        result = {"hash": file_hash, "sources": {}}
        if self.vt_api_key:
            try:
                resp = requests.get(
                    f"https://www.virustotal.com/api/v3/files/{file_hash}",
                    headers={"x-apikey": self.vt_api_key},
                    timeout=10,
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    result["sources"]["virustotal"] = {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "detection_names": list(
                            name for eng, det in data.get("last_analysis_results", {}).items()
                            if det.get("category") == "malicious"
                            for name in [det.get("result", "")]
                        )[:10],
                        "file_type": data.get("type_description", ""),
                        "file_name": data.get("meaningful_name", ""),
                    }
            except Exception as e:
                logger.warning(f"VT hash enrichment failed: {e}")
        return result

    def enrich_domain(self, domain: str) -> dict:
        result = {"domain": domain, "sources": {}}
        if self.vt_api_key:
            try:
                resp = requests.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}",
                    headers={"x-apikey": self.vt_api_key},
                    timeout=10,
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    result["sources"]["virustotal"] = {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "reputation": data.get("reputation", 0),
                        "creation_date": data.get("creation_date", ""),
                        "registrar": data.get("registrar", ""),
                    }
            except Exception as e:
                logger.warning(f"VT domain enrichment failed: {e}")
        return result


class SeverityCalculator:
    """Calculate incident severity based on multiple factors."""

    @staticmethod
    def calculate(asset_criticality: str, data_sensitivity: str,
                  threat_status: str, scope: str) -> dict:
        score = (
            SEVERITY_WEIGHTS["asset_criticality"].get(asset_criticality, 1)
            + SEVERITY_WEIGHTS["data_sensitivity"].get(data_sensitivity, 1)
            + SEVERITY_WEIGHTS["threat_status"].get(threat_status, 1)
            + SEVERITY_WEIGHTS["scope"].get(scope, 1)
        )
        if score >= 13:
            severity, priority, response_time = "Critical", "P1", "15 minutes"
        elif score >= 10:
            severity, priority, response_time = "High", "P2", "30 minutes"
        elif score >= 6:
            severity, priority, response_time = "Medium", "P3", "2 hours"
        else:
            severity, priority, response_time = "Low", "P4", "24 hours"

        return {
            "score": score,
            "max_score": 16,
            "severity": severity,
            "priority": priority,
            "response_time_sla": response_time,
            "factors": {
                "asset_criticality": asset_criticality,
                "data_sensitivity": data_sensitivity,
                "threat_status": threat_status,
                "scope": scope,
            },
        }


class PlaybookSelector:
    """Select appropriate IR playbook based on incident type."""

    @staticmethod
    def select(incident_type: str) -> dict:
        playbook = PLAYBOOK_MAP.get(incident_type.lower())
        if not playbook:
            return {
                "playbook": "generic_ir_v1",
                "team": "general_ir",
                "note": f"No specific playbook for type '{incident_type}', using generic",
            }
        return playbook


class TheHiveClient:
    """Create and manage incidents in TheHive."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.api_key = api_key

    def _headers(self):
        return {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

    def create_case(self, title: str, description: str, severity: int,
                    tags: list, custom_fields: dict = None) -> dict:
        payload = {
            "title": title,
            "description": description,
            "severity": severity,
            "tlp": 2,
            "pap": 2,
            "tags": tags,
        }
        if custom_fields:
            payload["customFields"] = custom_fields
        try:
            resp = requests.post(
                f"{self.base_url}/api/v1/case",
                headers=self._headers(),
                json=payload,
                timeout=10,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error(f"Failed to create TheHive case: {e}")
            return {"error": str(e)}


def generate_triage_report(alert_data: dict, enrichment: dict,
                           severity: dict, playbook: dict, output_path: str):
    """Generate a triage assessment report."""
    report = {
        "triage_report": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "analyst": os.getenv("USERNAME", os.getenv("USER", "unknown")),
            "alert_data": alert_data,
            "enrichment_results": enrichment,
            "severity_assessment": severity,
            "playbook_assignment": playbook,
            "decision": "escalate" if severity["priority"] in ("P1", "P2") else "investigate",
        }
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info(f"Triage report saved to: {output_path}")
    return report


def main():
    parser = argparse.ArgumentParser(description="Security Incident Triage Automation")
    parser.add_argument("--alert-source", required=True, help="Source of the alert (e.g., SIEM, EDR)")
    parser.add_argument("--alert-name", required=True, help="Alert rule name or title")
    parser.add_argument("--incident-type", required=True,
                        choices=list(PLAYBOOK_MAP.keys()),
                        help="Classified incident type")
    parser.add_argument("--src-ip", help="Source IP address to enrich")
    parser.add_argument("--dest-ip", help="Destination IP address")
    parser.add_argument("--file-hash", help="File hash (SHA256) to enrich")
    parser.add_argument("--domain", help="Domain to enrich")
    parser.add_argument("--asset-criticality", default="medium",
                        choices=["critical", "high", "medium", "low"])
    parser.add_argument("--data-sensitivity", default="confidential",
                        choices=["pii_phi", "pci", "confidential", "public"])
    parser.add_argument("--threat-status", default="confirmed",
                        choices=["active", "confirmed", "attempted", "recon"])
    parser.add_argument("--scope", default="single_system",
                        choices=["enterprise", "department", "single_system", "single_user"])
    parser.add_argument("--output-dir", default="./triage_output")
    parser.add_argument("--thehive-url", default=os.getenv("THEHIVE_URL", ""))
    parser.add_argument("--thehive-key", default=os.getenv("THEHIVE_API_KEY", ""))

    args = parser.parse_args()
    os.makedirs(args.output_dir, exist_ok=True)

    # Enrich IOCs
    enricher = IOCEnricher()
    enrichment = {}
    if args.src_ip:
        enrichment["src_ip"] = enricher.enrich_ip(args.src_ip)
    if args.file_hash:
        enrichment["file_hash"] = enricher.enrich_hash(args.file_hash)
    if args.domain:
        enrichment["domain"] = enricher.enrich_domain(args.domain)

    # Calculate severity
    severity = SeverityCalculator.calculate(
        args.asset_criticality, args.data_sensitivity,
        args.threat_status, args.scope,
    )
    logger.info(f"Severity: {severity['severity']} ({severity['priority']}) - Score: {severity['score']}/{severity['max_score']}")

    # Select playbook
    playbook = PlaybookSelector.select(args.incident_type)
    logger.info(f"Playbook: {playbook['playbook']} - Team: {playbook['team']}")

    # Create ticket in TheHive if configured
    if args.thehive_url and args.thehive_key:
        thehive = TheHiveClient(args.thehive_url, args.thehive_key)
        severity_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        case = thehive.create_case(
            title=f"[{severity['priority']}] {args.alert_name}",
            description=f"Triage: {args.incident_type} incident from {args.alert_source}",
            severity=severity_map.get(severity["severity"], 2),
            tags=[args.incident_type, severity["priority"], "triage-complete"],
            custom_fields={"playbook": {"string": playbook["playbook"]}},
        )
        logger.info(f"TheHive case created: {case}")

    # Generate report
    alert_data = {
        "source": args.alert_source,
        "name": args.alert_name,
        "type": args.incident_type,
        "src_ip": args.src_ip,
        "dest_ip": args.dest_ip,
    }
    report_path = os.path.join(args.output_dir, f"triage_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    generate_triage_report(alert_data, enrichment, severity, playbook, report_path)

    print(f"\nTriage Complete")
    print(f"Severity: {severity['severity']} ({severity['priority']})")
    print(f"Playbook: {playbook['playbook']}")
    print(f"Response SLA: {severity['response_time_sla']}")
    print(f"Report: {report_path}")


if __name__ == "__main__":
    main()
