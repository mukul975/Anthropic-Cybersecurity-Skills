#!/usr/bin/env python3
"""Active Directory Vulnerability Assessment Analyzer.

Parses PingCastle and BloodHound output to generate consolidated
AD security assessment reports with prioritized remediation actions.
"""

import argparse
import csv
import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path


RISK_WEIGHTS = {
    "kerberoastable_admin": 10,
    "unconstrained_delegation": 9,
    "as_rep_roastable": 8,
    "password_never_expires_admin": 8,
    "adminsdholder_modified": 8,
    "dcsync_non_dc": 9,
    "gpo_abuse_path": 7,
    "stale_admin_account": 6,
    "ldap_signing_disabled": 6,
    "ntlm_not_restricted": 5,
    "excessive_domain_admins": 7,
    "sid_history_present": 6,
    "trust_sid_filtering_disabled": 7,
    "unsupported_os_dc": 9,
    "password_policy_weak": 5,
}


def parse_pingcastle_xml(xml_path):
    """Parse PingCastle HTML/XML health check report."""
    findings = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for risk in root.iter("RiskRule"):
            finding = {
                "source": "PingCastle",
                "category": risk.findtext("Category", ""),
                "rule_id": risk.findtext("RiskId", ""),
                "title": risk.findtext("Rationale", ""),
                "description": risk.findtext("Detail", ""),
                "points": int(risk.findtext("Points", "0")),
            }
            findings.append(finding)
    except ET.ParseError:
        print(f"[-] Could not parse PingCastle XML: {xml_path}")
        print("    Try exporting PingCastle results as XML format")
    return findings


def parse_bloodhound_json(json_path):
    """Parse BloodHound CE exported data for critical findings."""
    findings = []
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        nodes = data.get("nodes", [])
        edges = data.get("edges", [])
    elif isinstance(data, list):
        nodes = data
        edges = []
    else:
        return findings

    for node in nodes:
        props = node.get("properties", node.get("Properties", {}))
        kind = node.get("kind", node.get("label", ""))

        if kind == "User":
            if props.get("hasspn", False) and props.get("admincount", False):
                findings.append({
                    "source": "BloodHound",
                    "category": "Kerberos",
                    "rule_id": "kerberoastable_admin",
                    "title": f"Kerberoastable admin account: {props.get('name', 'unknown')}",
                    "description": f"User {props.get('name')} has SPN set and is in admin group",
                    "risk_weight": RISK_WEIGHTS["kerberoastable_admin"],
                })
            if props.get("dontreqpreauth", False):
                findings.append({
                    "source": "BloodHound",
                    "category": "Kerberos",
                    "rule_id": "as_rep_roastable",
                    "title": f"AS-REP roastable account: {props.get('name', 'unknown')}",
                    "description": f"User {props.get('name')} has Kerberos pre-auth disabled",
                    "risk_weight": RISK_WEIGHTS["as_rep_roastable"],
                })
            if props.get("pwdneverexpires", False) and props.get("admincount", False):
                findings.append({
                    "source": "BloodHound",
                    "category": "Privileged Accounts",
                    "rule_id": "password_never_expires_admin",
                    "title": f"Admin with non-expiring password: {props.get('name', 'unknown')}",
                    "description": f"Privileged user {props.get('name')} has password set to never expire",
                    "risk_weight": RISK_WEIGHTS["password_never_expires_admin"],
                })

        elif kind == "Computer":
            if props.get("unconstraineddelegation", False):
                name = props.get("name", "unknown")
                if "DC" not in name.upper():
                    findings.append({
                        "source": "BloodHound",
                        "category": "Kerberos",
                        "rule_id": "unconstrained_delegation",
                        "title": f"Unconstrained delegation on non-DC: {name}",
                        "description": f"Computer {name} has unconstrained delegation enabled",
                        "risk_weight": RISK_WEIGHTS["unconstrained_delegation"],
                    })

    return findings


def consolidate_findings(pingcastle_findings, bloodhound_findings):
    """Merge and deduplicate findings from multiple tools."""
    all_findings = pingcastle_findings + bloodhound_findings

    for finding in all_findings:
        if "risk_weight" not in finding:
            points = finding.get("points", 0)
            if points >= 30:
                finding["risk_weight"] = 10
            elif points >= 20:
                finding["risk_weight"] = 8
            elif points >= 10:
                finding["risk_weight"] = 6
            elif points >= 5:
                finding["risk_weight"] = 4
            else:
                finding["risk_weight"] = 2

        rule_id = finding.get("rule_id", "")
        if rule_id in RISK_WEIGHTS:
            finding["risk_weight"] = max(finding["risk_weight"], RISK_WEIGHTS[rule_id])

    all_findings.sort(key=lambda f: f.get("risk_weight", 0), reverse=True)
    return all_findings


def generate_report(findings, output_path):
    """Generate consolidated AD assessment report."""
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "critical": len([f for f in findings if f.get("risk_weight", 0) >= 9]),
        "high": len([f for f in findings if 7 <= f.get("risk_weight", 0) < 9]),
        "medium": len([f for f in findings if 4 <= f.get("risk_weight", 0) < 7]),
        "low": len([f for f in findings if f.get("risk_weight", 0) < 4]),
        "findings": findings,
        "categories": {},
    }

    for f in findings:
        cat = f.get("category", "Other")
        if cat not in report["categories"]:
            report["categories"][cat] = 0
        report["categories"][cat] += 1

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    print(f"[+] AD Assessment Report: {output_path}")
    print(f"    Total findings: {report['total_findings']}")
    print(f"    Critical: {report['critical']}")
    print(f"    High: {report['high']}")
    print(f"    Medium: {report['medium']}")
    print(f"    Low: {report['low']}")
    print(f"    Categories: {json.dumps(report['categories'], indent=6)}")
    return report


def main():
    parser = argparse.ArgumentParser(description="AD Vulnerability Assessment Analyzer")
    parser.add_argument("--pingcastle", help="PingCastle XML report path")
    parser.add_argument("--bloodhound", help="BloodHound JSON export path")
    parser.add_argument("--output", default="ad_assessment_report.json", help="Output report path")
    args = parser.parse_args()

    pc_findings = []
    bh_findings = []

    if args.pingcastle:
        print(f"[*] Parsing PingCastle report: {args.pingcastle}")
        pc_findings = parse_pingcastle_xml(args.pingcastle)
        print(f"    Found {len(pc_findings)} PingCastle findings")

    if args.bloodhound:
        print(f"[*] Parsing BloodHound data: {args.bloodhound}")
        bh_findings = parse_bloodhound_json(args.bloodhound)
        print(f"    Found {len(bh_findings)} BloodHound findings")

    if not pc_findings and not bh_findings:
        print("[-] No input files provided. Use --pingcastle and/or --bloodhound")
        parser.print_help()
        sys.exit(1)

    findings = consolidate_findings(pc_findings, bh_findings)
    generate_report(findings, args.output)


if __name__ == "__main__":
    main()
