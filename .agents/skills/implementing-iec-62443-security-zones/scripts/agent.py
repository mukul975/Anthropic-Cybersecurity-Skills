#!/usr/bin/env python3
"""Agent for designing and auditing IEC 62443 security zones and conduits."""

import json
import argparse
from datetime import datetime
from collections import Counter


PURDUE_LEVELS = {
    0: {"name": "Process", "description": "Sensors, actuators, field devices"},
    1: {"name": "Basic Control", "description": "PLCs, RTUs, safety systems"},
    2: {"name": "Area Supervisory", "description": "HMIs, engineering workstations"},
    3: {"name": "Site Operations", "description": "Historians, OPC servers, MES"},
    3.5: {"name": "DMZ", "description": "IT/OT demilitarized zone"},
    4: {"name": "Enterprise", "description": "ERP, email, business systems"},
    5: {"name": "External", "description": "Internet, cloud, vendors"},
}

SECURITY_LEVELS = {
    "SL1": "Protection against casual or coincidental violation",
    "SL2": "Protection against intentional violation using simple means",
    "SL3": "Protection against sophisticated attack with moderate resources",
    "SL4": "Protection against state-sponsored attack with extended resources",
}


def audit_zone_architecture(zones_path):
    """Audit IEC 62443 zone architecture for compliance."""
    with open(zones_path) as f:
        architecture = json.load(f)
    zones = architecture.get("zones", [])
    conduits = architecture.get("conduits", [])
    findings = []

    for zone in zones:
        zone_name = zone.get("name", "")
        sl_target = zone.get("sl_target", zone.get("security_level", ""))
        sl_achieved = zone.get("sl_achieved", zone.get("current_sl", ""))
        purdue_level = zone.get("purdue_level", -1)

        if not sl_target:
            findings.append({"zone": zone_name, "issue": "No SL-T defined",
                             "severity": "CRITICAL"})
        if sl_target and sl_achieved:
            t = int(sl_target.replace("SL", ""))
            a = int(sl_achieved.replace("SL", ""))
            if a < t:
                findings.append({
                    "zone": zone_name,
                    "issue": f"SL gap: target={sl_target} achieved={sl_achieved}",
                    "severity": "HIGH",
                })

        if not zone.get("assets"):
            findings.append({"zone": zone_name, "issue": "No assets documented",
                             "severity": "MEDIUM"})

        if purdue_level in (0, 1) and sl_target in ("SL1", ""):
            findings.append({
                "zone": zone_name,
                "issue": f"Low SL for Purdue Level {purdue_level}",
                "severity": "HIGH",
                "recommendation": "Critical control zones should target SL3+",
            })

    for conduit in conduits:
        src = conduit.get("source_zone", "")
        dst = conduit.get("destination_zone", "")
        controls = conduit.get("security_controls", [])

        if not controls:
            findings.append({
                "conduit": f"{src} -> {dst}",
                "issue": "No security controls on conduit",
                "severity": "CRITICAL",
            })

        if not conduit.get("firewall", False):
            findings.append({
                "conduit": f"{src} -> {dst}",
                "issue": "No firewall on conduit",
                "severity": "HIGH",
            })

        if conduit.get("allows_remote_access", False) and \
                not conduit.get("requires_mfa", False):
            findings.append({
                "conduit": f"{src} -> {dst}",
                "issue": "Remote access conduit without MFA",
                "severity": "CRITICAL",
            })

    # Check for direct Level 5 to Level 0/1 conduit
    for conduit in conduits:
        src_level = conduit.get("source_purdue_level", -1)
        dst_level = conduit.get("destination_purdue_level", -1)
        if (src_level >= 4 and dst_level <= 1) or (dst_level >= 4 and src_level <= 1):
            if not conduit.get("passes_through_dmz", False):
                findings.append({
                    "conduit": f"{conduit.get('source_zone')} -> {conduit.get('destination_zone')}",
                    "issue": "Direct IT-to-OT conduit bypassing DMZ",
                    "severity": "CRITICAL",
                })

    return findings


def generate_zone_template(facility_name, zone_count=5):
    """Generate IEC 62443 zone template based on Purdue model."""
    zones = [
        {"name": f"{facility_name}_Level0_Field",
         "purdue_level": 0, "sl_target": "SL2",
         "description": "Field instruments, sensors, actuators",
         "assets": ["PLC I/O modules", "Sensors", "Actuators"]},
        {"name": f"{facility_name}_Level1_Control",
         "purdue_level": 1, "sl_target": "SL3",
         "description": "PLCs, RTUs, safety controllers",
         "assets": ["PLCs", "Safety Controllers", "RTUs"]},
        {"name": f"{facility_name}_Level2_Supervisory",
         "purdue_level": 2, "sl_target": "SL3",
         "description": "HMI, engineering workstations",
         "assets": ["HMI Stations", "Engineering Workstations"]},
        {"name": f"{facility_name}_Level3_Operations",
         "purdue_level": 3, "sl_target": "SL2",
         "description": "Historian, OPC, MES",
         "assets": ["Historian Server", "OPC Gateway", "MES"]},
        {"name": f"{facility_name}_DMZ",
         "purdue_level": 3.5, "sl_target": "SL3",
         "description": "IT/OT demilitarized zone",
         "assets": ["Data Diode", "Patch Server", "AV Update Server"]},
    ]

    conduits = [
        {"source_zone": zones[0]["name"], "destination_zone": zones[1]["name"],
         "protocols": ["Modbus", "PROFINET"], "firewall": True,
         "security_controls": ["Protocol-aware firewall", "DPI"]},
        {"source_zone": zones[1]["name"], "destination_zone": zones[2]["name"],
         "protocols": ["EtherNet/IP", "OPC UA"], "firewall": True,
         "security_controls": ["Industrial firewall", "Allowlist"]},
        {"source_zone": zones[2]["name"], "destination_zone": zones[3]["name"],
         "protocols": ["OPC UA", "SQL"], "firewall": True,
         "security_controls": ["Firewall", "Network monitoring"]},
        {"source_zone": zones[3]["name"], "destination_zone": zones[4]["name"],
         "protocols": ["HTTPS", "SFTP"], "firewall": True,
         "security_controls": ["Data diode", "Firewall", "IDS"]},
    ]

    return {"zones": zones, "conduits": conduits}


def assess_sl_requirements(risk_assessment_path):
    """Map risk assessment results to IEC 62443 Security Level targets."""
    with open(risk_assessment_path) as f:
        assessment = json.load(f)
    zones = assessment.get("zones", [])
    recommendations = []
    for zone in zones:
        threat_level = zone.get("threat_level", "medium").lower()
        impact = zone.get("impact", "medium").lower()
        if threat_level == "high" and impact in ("high", "critical"):
            sl = "SL4"
        elif threat_level == "high" or impact == "high":
            sl = "SL3"
        elif threat_level == "medium":
            sl = "SL2"
        else:
            sl = "SL1"
        recommendations.append({
            "zone": zone.get("name", ""),
            "threat_level": threat_level,
            "impact": impact,
            "recommended_sl": sl,
            "sl_description": SECURITY_LEVELS[sl],
        })
    return recommendations


def main():
    parser = argparse.ArgumentParser(description="IEC 62443 Security Zones Agent")
    parser.add_argument("--zones", help="Zone architecture JSON to audit")
    parser.add_argument("--risk-assessment", help="Risk assessment JSON for SL mapping")
    parser.add_argument("--facility", help="Facility name for template generation")
    parser.add_argument("--action", choices=["audit", "template", "sl-map", "full"],
                        default="full")
    parser.add_argument("--output", default="iec62443_zones_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "results": {}}

    if args.action in ("audit", "full") and args.zones:
        findings = audit_zone_architecture(args.zones)
        report["results"]["audit"] = findings
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        print(f"[+] Zone audit: {len(findings)} findings, {critical} critical")

    if args.action in ("template", "full") and args.facility:
        template = generate_zone_template(args.facility)
        report["results"]["template"] = template
        print(f"[+] Template: {len(template['zones'])} zones, {len(template['conduits'])} conduits")

    if args.action in ("sl-map", "full") and args.risk_assessment:
        recommendations = assess_sl_requirements(args.risk_assessment)
        report["results"]["sl_recommendations"] = recommendations
        print(f"[+] SL recommendations for {len(recommendations)} zones")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
