#!/usr/bin/env python3
"""Agent for performing oil & gas sector cybersecurity assessment based on IEC 62443 and NIST frameworks."""

import json
import argparse
import csv
from datetime import datetime
from pathlib import Path


IEC62443_SECURITY_LEVELS = {
    "SL1": "Protection against casual or coincidental violation",
    "SL2": "Protection against intentional violation using simple means",
    "SL3": "Protection against sophisticated attacks with moderate resources",
    "SL4": "Protection against state-sponsored attacks with extensive resources",
}

OT_ASSET_CATEGORIES = {
    "SCADA": {"criticality": "CRITICAL", "zone": "Level 2", "purdue": 2},
    "DCS": {"criticality": "CRITICAL", "zone": "Level 1-2", "purdue": 2},
    "PLC": {"criticality": "HIGH", "zone": "Level 1", "purdue": 1},
    "RTU": {"criticality": "HIGH", "zone": "Level 1", "purdue": 1},
    "HMI": {"criticality": "HIGH", "zone": "Level 2", "purdue": 2},
    "EWS": {"criticality": "MEDIUM", "zone": "Level 2", "purdue": 2},
    "Historian": {"criticality": "MEDIUM", "zone": "Level 3", "purdue": 3},
    "SIS": {"criticality": "CRITICAL", "zone": "Level 0-1", "purdue": 1},
    "Firewall_OT": {"criticality": "HIGH", "zone": "DMZ", "purdue": 3.5},
}


def assess_network_segmentation(asset_file):
    """Assess OT/IT network segmentation based on asset inventory."""
    with open(asset_file, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        assets = list(reader)
    zones = {}
    findings = []
    for asset in assets:
        zone = asset.get("zone", asset.get("network_zone", "unknown"))
        atype = asset.get("type", asset.get("asset_type", "unknown"))
        zones.setdefault(zone, []).append(asset)
        expected = OT_ASSET_CATEGORIES.get(atype, {})
        if expected and expected.get("zone") and zone != expected["zone"]:
            findings.append({
                "asset": asset.get("name", asset.get("hostname", "")),
                "type": atype, "current_zone": zone,
                "expected_zone": expected["zone"],
                "issue": "ZONE_MISMATCH",
            })
    dmz_exists = any("dmz" in z.lower() for z in zones.keys())
    if not dmz_exists:
        findings.append({"issue": "NO_DMZ", "severity": "CRITICAL", "recommendation": "Implement IT/OT DMZ"})
    return {
        "total_assets": len(assets),
        "zones": {z: len(a) for z, a in zones.items()},
        "zone_mismatches": len([f for f in findings if f.get("issue") == "ZONE_MISMATCH"]),
        "dmz_present": dmz_exists,
        "findings": findings[:20],
    }


def assess_iec62443_compliance(assessment_csv):
    """Assess IEC 62443 compliance from questionnaire responses."""
    with open(assessment_csv, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    requirements = {}
    for row in rows:
        req_id = row.get("requirement", row.get("control", ""))
        sl_achieved = int(row.get("sl_achieved", row.get("score", 0)))
        sl_target = int(row.get("sl_target", row.get("target", 2)))
        zone = row.get("zone", row.get("scope", ""))
        requirements.setdefault(zone, []).append({
            "requirement": req_id, "achieved": sl_achieved,
            "target": sl_target, "gap": sl_target - sl_achieved,
            "compliant": sl_achieved >= sl_target,
        })
    zone_scores = {}
    for zone, reqs in requirements.items():
        compliant = sum(1 for r in reqs if r["compliant"])
        zone_scores[zone] = {
            "total_requirements": len(reqs), "compliant": compliant,
            "non_compliant": len(reqs) - compliant,
            "compliance_pct": round(compliant / len(reqs) * 100, 1),
        }
    return {
        "framework": "IEC 62443",
        "zone_compliance": zone_scores,
        "overall_compliance": round(sum(z["compliance_pct"] for z in zone_scores.values()) / max(len(zone_scores), 1), 1),
        "critical_gaps": [r for reqs in requirements.values() for r in reqs if r["gap"] >= 2],
    }


def assess_safety_systems(asset_file):
    """Assess Safety Instrumented System (SIS) security posture."""
    with open(asset_file, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        assets = list(reader)
    sis_assets = [a for a in assets if a.get("type", "").upper() in ("SIS", "ESD", "F&G", "HIPPS")]
    findings = []
    for asset in sis_assets:
        if asset.get("network_connected", "").lower() in ("yes", "true", "1"):
            findings.append({"asset": asset.get("name"), "issue": "SIS_NETWORK_CONNECTED", "severity": "CRITICAL"})
        if asset.get("remote_access", "").lower() in ("yes", "true", "1"):
            findings.append({"asset": asset.get("name"), "issue": "SIS_REMOTE_ACCESS", "severity": "CRITICAL"})
        if asset.get("shared_controller", "").lower() in ("yes", "true", "1"):
            findings.append({"asset": asset.get("name"), "issue": "SIS_SHARED_CONTROLLER", "severity": "HIGH"})
    return {
        "total_sis_assets": len(sis_assets),
        "findings": findings,
        "sis_isolated": len(sis_assets) - len(set(f["asset"] for f in findings)),
        "recommendation": "SIS must be air-gapped from process control and IT networks per IEC 61511",
    }


def generate_assessment_report(asset_file, assessment_csv=None):
    """Generate comprehensive oil & gas cybersecurity assessment report."""
    report = {
        "generated": datetime.utcnow().isoformat(),
        "framework": "IEC 62443 / NIST CSF / API 1164",
        "network_segmentation": assess_network_segmentation(asset_file),
        "safety_systems": assess_safety_systems(asset_file),
    }
    if assessment_csv:
        report["iec62443_compliance"] = assess_iec62443_compliance(assessment_csv)
    return report


def main():
    parser = argparse.ArgumentParser(description="Oil & Gas Cybersecurity Assessment Agent")
    sub = parser.add_subparsers(dest="command")
    n = sub.add_parser("network", help="Assess network segmentation")
    n.add_argument("--assets", required=True, help="Asset inventory CSV")
    c = sub.add_parser("compliance", help="IEC 62443 compliance check")
    c.add_argument("--csv", required=True)
    s = sub.add_parser("safety", help="SIS security assessment")
    s.add_argument("--assets", required=True)
    r = sub.add_parser("report", help="Full assessment report")
    r.add_argument("--assets", required=True)
    r.add_argument("--compliance-csv", help="IEC 62443 assessment CSV")
    args = parser.parse_args()
    if args.command == "network":
        result = assess_network_segmentation(args.assets)
    elif args.command == "compliance":
        result = assess_iec62443_compliance(args.csv)
    elif args.command == "safety":
        result = assess_safety_systems(args.assets)
    elif args.command == "report":
        result = generate_assessment_report(args.assets, args.compliance_csv)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
