#!/usr/bin/env python3
"""Palo Alto NGFW Agent - audits security policies, threat prevention, and App-ID usage via XML API."""

import json
import argparse
import logging
import subprocess
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def pan_api_request(firewall_ip, api_key, cmd_type, cmd):
    url = f"https://{firewall_ip}/api/?type={cmd_type}&cmd={cmd}&key={api_key}"
    result = subprocess.run(["curl", "-s", "-k", url], capture_output=True, text=True)
    return result.stdout


def get_security_rules(fw_ip, api_key):
    cmd = "<show><running><security-policy></security-policy></running></show>"
    xml_data = pan_api_request(fw_ip, api_key, "op", cmd)
    rules = []
    try:
        root = ET.fromstring(xml_data)
        for entry in root.iter("entry"):
            rule = {
                "name": entry.get("name", ""),
                "source_zone": [z.text for z in entry.findall(".//from/member")] or ["any"],
                "dest_zone": [z.text for z in entry.findall(".//to/member")] or ["any"],
                "application": [a.text for a in entry.findall(".//application/member")] or ["any"],
                "action": entry.findtext(".//action", ""),
                "log_end": entry.findtext(".//log-end", "no"),
                "profile_group": entry.findtext(".//profile-setting/group/member", ""),
            }
            rules.append(rule)
    except ET.ParseError:
        logger.error("Failed to parse security rules XML")
    return rules


def audit_security_rules(rules):
    findings = []
    for rule in rules:
        name = rule["name"]
        if "any" in rule["application"]:
            findings.append({"rule": name, "issue": "Uses any application instead of App-ID", "severity": "high"})
        if not rule.get("profile_group"):
            findings.append({"rule": name, "issue": "No security profile group attached", "severity": "high"})
        if rule["log_end"] != "yes":
            findings.append({"rule": name, "issue": "End logging not enabled", "severity": "medium"})
        if rule["action"] == "allow" and "any" in rule["source_zone"] and "any" in rule["dest_zone"]:
            findings.append({"rule": name, "issue": "Allow any-to-any zones", "severity": "critical"})
    return findings


def calculate_appid_coverage(rules):
    total = len(rules)
    appid_rules = sum(1 for r in rules if "any" not in r["application"])
    return {"total_rules": total, "appid_enabled": appid_rules,
            "coverage_percent": round(appid_rules / max(total, 1) * 100, 1)}


def check_system_health(fw_ip, api_key):
    cmd = "<show><system><info></info></system></show>"
    xml_data = pan_api_request(fw_ip, api_key, "op", cmd)
    info = {}
    try:
        root = ET.fromstring(xml_data)
        info["hostname"] = root.findtext(".//hostname", "")
        info["model"] = root.findtext(".//model", "")
        info["sw_version"] = root.findtext(".//sw-version", "")
        info["threat_version"] = root.findtext(".//threat-version", "")
        info["app_version"] = root.findtext(".//app-version", "")
    except ET.ParseError:
        pass
    return info


def generate_report(rules, findings, appid, health):
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "system_health": health,
        "total_rules": len(rules),
        "appid_coverage": appid,
        "security_findings": findings,
        "total_findings": len(findings),
        "critical_findings": sum(1 for f in findings if f.get("severity") == "critical"),
    }


def main():
    parser = argparse.ArgumentParser(description="Palo Alto NGFW Audit Agent")
    parser.add_argument("--firewall", required=True, help="Firewall IP/hostname")
    parser.add_argument("--api-key", required=True, help="PAN-OS API key")
    parser.add_argument("--output", default="panos_ngfw_report.json")
    args = parser.parse_args()

    health = check_system_health(args.firewall, args.api_key)
    rules = get_security_rules(args.firewall, args.api_key)
    findings = audit_security_rules(rules)
    appid = calculate_appid_coverage(rules)
    report = generate_report(rules, findings, appid, health)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("PAN-OS: %d rules, App-ID %.1f%%, %d findings",
                len(rules), appid["coverage_percent"], len(findings))
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
