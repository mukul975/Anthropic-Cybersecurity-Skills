#!/usr/bin/env python3
"""Agent for triaging security incidents using NIST SP 800-61 and SANS PICERL frameworks."""

import requests
import json
import sys
import argparse
import hashlib
from datetime import datetime, timezone


NIST_CATEGORIES = {
    "unauthorized_access": "Unauthorized Access",
    "dos": "Denial of Service",
    "malicious_code": "Malicious Code",
    "improper_usage": "Improper Usage",
    "reconnaissance": "Reconnaissance",
    "web_attack": "Web Application Attack",
}

SEVERITY_MATRIX = {
    "P1": {"label": "Critical", "ack_sla": "15 min", "contain_sla": "1 hour",
            "criteria": "Crown jewel compromise, active exfiltration, ransomware spreading"},
    "P2": {"label": "High", "ack_sla": "30 min", "contain_sla": "4 hours",
            "criteria": "Production compromise, confirmed malware, privileged account takeover"},
    "P3": {"label": "Medium", "ack_sla": "2 hours", "contain_sla": "24 hours",
            "criteria": "Non-production compromise, failed exploitation, single endpoint malware"},
    "P4": {"label": "Low", "ack_sla": "8 hours", "contain_sla": "72 hours",
            "criteria": "Reconnaissance, policy violation, benign true positive"},
}


def classify_incident(alert_data):
    """Classify incident type based on alert indicators."""
    print("[*] Classifying incident type...")
    alert_name = alert_data.get("alert_name", "").lower()
    process = alert_data.get("process", "").lower()
    event_code = alert_data.get("event_code", "")

    if any(kw in alert_name for kw in ["malware", "ransomware", "trojan", "cryptominer"]):
        category = "malicious_code"
    elif any(kw in alert_name for kw in ["brute force", "credential", "password spray"]):
        category = "unauthorized_access"
    elif any(kw in alert_name for kw in ["dos", "flood", "resource exhaustion"]):
        category = "dos"
    elif any(kw in alert_name for kw in ["sql injection", "xss", "ssrf", "xxe"]):
        category = "web_attack"
    elif any(kw in alert_name for kw in ["scan", "enum", "recon", "discovery"]):
        category = "reconnaissance"
    elif "powershell" in process and "encoded" in alert_name.lower():
        category = "malicious_code"
    else:
        category = "unauthorized_access"

    classification = NIST_CATEGORIES.get(category, "Unknown")
    print(f"  [+] Classification: {classification} ({category})")
    return category, classification


def assess_severity(alert_data, asset_criticality="medium"):
    """Calculate incident severity based on threat and asset context."""
    print("\n[*] Assessing severity...")
    threat_score = 0

    alert_severity = alert_data.get("severity", "").lower()
    if alert_severity in ("critical", "high"):
        threat_score += 3
    elif alert_severity == "medium":
        threat_score += 2
    else:
        threat_score += 1

    confidence = alert_data.get("confidence", 50)
    if confidence >= 80:
        threat_score += 2
    elif confidence >= 50:
        threat_score += 1

    asset_scores = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    asset_score = asset_scores.get(asset_criticality, 1)

    total = threat_score + asset_score
    if total >= 7:
        priority = "P1"
    elif total >= 5:
        priority = "P2"
    elif total >= 3:
        priority = "P3"
    else:
        priority = "P4"

    sev_info = SEVERITY_MATRIX[priority]
    print(f"  [+] Priority: {priority} - {sev_info['label']}")
    print(f"  [+] ACK SLA: {sev_info['ack_sla']} | Containment SLA: {sev_info['contain_sla']}")
    return priority, sev_info


def check_virustotal(api_key, indicator, indicator_type="ip"):
    """Check an indicator against VirusTotal."""
    print(f"\n[*] Checking VirusTotal for {indicator_type}: {indicator}...")
    base_urls = {
        "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}",
        "hash": f"https://www.virustotal.com/api/v3/files/{indicator}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{indicator}",
    }
    url = base_urls.get(indicator_type)
    if not url:
        return {}
    try:
        headers = {"x-apikey": api_key}
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            if indicator_type in ("ip", "domain"):
                malicious = data.get("last_analysis_stats", {}).get("malicious", 0)
                total = sum(data.get("last_analysis_stats", {}).values())
                print(f"  [+] VT Result: {malicious}/{total} vendors flagged as malicious")
                return {"malicious": malicious, "total": total}
            elif indicator_type == "hash":
                malicious = data.get("last_analysis_stats", {}).get("malicious", 0)
                name = data.get("meaningful_name", "Unknown")
                print(f"  [+] VT Result: {name} - {malicious} detections")
                return {"name": name, "malicious": malicious}
        elif resp.status_code == 404:
            print(f"  [-] Not found in VirusTotal")
        else:
            print(f"  [-] VT API error: {resp.status_code}")
    except requests.RequestException as e:
        print(f"  [-] VT request failed: {e}")
    return {}


def build_mitre_mapping(category, process_info=""):
    """Map incident to MITRE ATT&CK techniques."""
    mappings = {
        "malicious_code": [
            {"technique": "T1059.001", "name": "PowerShell"},
            {"technique": "T1204.002", "name": "User Execution: Malicious File"},
        ],
        "unauthorized_access": [
            {"technique": "T1110", "name": "Brute Force"},
            {"technique": "T1078", "name": "Valid Accounts"},
        ],
        "reconnaissance": [
            {"technique": "T1046", "name": "Network Service Discovery"},
            {"technique": "T1595", "name": "Active Scanning"},
        ],
        "web_attack": [
            {"technique": "T1190", "name": "Exploit Public-Facing Application"},
        ],
    }
    techniques = mappings.get(category, [])
    if techniques:
        print(f"\n[*] MITRE ATT&CK mapping:")
        for t in techniques:
            print(f"  - {t['technique']}: {t['name']}")
    return techniques


def generate_triage_record(alert_data, classification, priority, sev_info,
                            ti_results, mitre, output_path):
    """Generate a structured incident triage report."""
    triage_time = datetime.now(timezone.utc)
    alert_time = alert_data.get("timestamp", triage_time.isoformat())

    record = {
        "ticket_id": f"INC-{triage_time.strftime('%Y')}-{hash(str(alert_data)) % 10000:04d}",
        "triage_analyst": alert_data.get("analyst", "automated"),
        "triage_time": triage_time.isoformat(),
        "alert_time": alert_time,
        "classification": {
            "type": classification[1],
            "category": classification[0],
            "priority": priority,
            "severity_label": sev_info["label"],
            "confidence": alert_data.get("confidence", "Unknown"),
        },
        "affected_scope": {
            "assets": alert_data.get("affected_hosts", []),
            "users": alert_data.get("affected_users", []),
            "business_unit": alert_data.get("business_unit", "Unknown"),
        },
        "evidence": {
            "alert_source": alert_data.get("source", "Unknown"),
            "alert_name": alert_data.get("alert_name", "Unknown"),
            "raw_indicators": alert_data.get("indicators", {}),
        },
        "enrichment": {
            "threat_intel": ti_results,
            "mitre_attack": mitre,
        },
        "recommended_actions": [],
        "sla": {
            "acknowledge_by": sev_info["ack_sla"],
            "contain_by": sev_info["contain_sla"],
        },
    }

    if priority in ("P1", "P2"):
        record["recommended_actions"] = [
            "Isolate affected endpoint via EDR",
            "Disable compromised user account",
            "Preserve volatile evidence (memory dump)",
            "Escalate to Tier 2 IR team",
        ]
    else:
        record["recommended_actions"] = [
            "Monitor for additional indicators",
            "Review related alerts for the past 7 days",
            "Document findings and close if benign",
        ]

    with open(output_path, "w") as f:
        json.dump(record, f, indent=2)
    print(f"\n[*] Triage record saved to {output_path}")
    print(f"[*] Ticket: {record['ticket_id']} | Priority: {priority} ({sev_info['label']})")
    return record


def main():
    parser = argparse.ArgumentParser(description="Security Incident Triage Agent")
    parser.add_argument("--alert-name", required=True, help="Name of the triggering alert")
    parser.add_argument("--source", default="SIEM", help="Alert source system")
    parser.add_argument("--severity", default="high", help="Alert severity")
    parser.add_argument("--confidence", type=int, default=75, help="Alert confidence (0-100)")
    parser.add_argument("--host", help="Affected hostname")
    parser.add_argument("--src-ip", help="Source IP address")
    parser.add_argument("--user", help="Affected username")
    parser.add_argument("--process", default="", help="Suspicious process name")
    parser.add_argument("--asset-criticality", default="medium",
                        choices=["critical", "high", "medium", "low"])
    parser.add_argument("--vt-key", help="VirusTotal API key for threat intel")
    parser.add_argument("--indicator", help="IOC to check (IP, hash, or domain)")
    parser.add_argument("--indicator-type", default="ip", choices=["ip", "hash", "domain"])
    parser.add_argument("-o", "--output", default="triage_record.json")
    args = parser.parse_args()

    alert_data = {
        "alert_name": args.alert_name,
        "source": args.source,
        "severity": args.severity,
        "confidence": args.confidence,
        "affected_hosts": [args.host] if args.host else [],
        "affected_users": [args.user] if args.user else [],
        "process": args.process,
        "indicators": {"src_ip": args.src_ip},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    print("[*] Security Incident Triage\n")
    classification = classify_incident(alert_data)
    priority, sev_info = assess_severity(alert_data, args.asset_criticality)
    mitre = build_mitre_mapping(classification[0], args.process)

    ti_results = {}
    if args.vt_key and args.indicator:
        ti_results = check_virustotal(args.vt_key, args.indicator, args.indicator_type)

    generate_triage_record(alert_data, classification, priority, sev_info,
                           ti_results, mitre, args.output)


if __name__ == "__main__":
    main()
