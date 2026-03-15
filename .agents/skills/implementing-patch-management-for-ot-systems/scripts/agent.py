#!/usr/bin/env python3
"""OT Patch Management Agent - tracks ICS/SCADA patch status and risk assessment."""

import json
import argparse
import logging
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

OT_PATCH_SLA = {"critical": 30, "high": 60, "medium": 120, "low": 365}


def load_data(filepath):
    with open(filepath) as f:
        return json.load(f)


def assess_patch_risk(patch, asset):
    risk_factors = []
    if asset.get("type", "").lower() in ("plc", "rtu", "safety_controller"):
        risk_factors.append({"factor": "Safety-critical device", "impact": "high"})
    if asset.get("requires_downtime"):
        risk_factors.append({"factor": "Requires process downtime", "impact": "high"})
    if not asset.get("test_environment_available"):
        risk_factors.append({"factor": "No test environment", "impact": "medium"})
    if not patch.get("vendor_validated"):
        risk_factors.append({"factor": "Not vendor validated", "impact": "high"})
    score = sum(3 if r["impact"] == "high" else 1 for r in risk_factors)
    return {"patch_id": patch.get("id"), "asset": asset.get("name"), "risk_score": score,
            "risk_level": "high" if score >= 6 else "medium" if score >= 3 else "low"}


def check_compliance(assets, patches):
    now = datetime.utcnow()
    results = []
    for asset in assets:
        for patch in patches:
            if patch.get("asset_id") == asset.get("id") and patch.get("status") == "missing":
                severity = patch.get("severity", "medium").lower()
                published = datetime.fromisoformat(patch["published_date"].replace("Z", "+00:00")).replace(tzinfo=None)
                age = (now - published).days
                sla = OT_PATCH_SLA.get(severity, 120)
                results.append({
                    "asset": asset.get("name"), "patch_id": patch.get("id"),
                    "severity": severity, "age_days": age, "sla_days": sla,
                    "sla_status": "within_sla" if age <= sla else "sla_breached",
                    "vendor_validated": patch.get("vendor_validated", False),
                })
    return results


def generate_report(compliance, assets):
    breached = [c for c in compliance if c["sla_status"] == "sla_breached"]
    return {
        "timestamp": datetime.utcnow().isoformat(), "total_assets": len(assets),
        "missing_patches": len(compliance), "sla_breaches": len(breached),
        "compliance_rate": round((1 - len(breached) / max(len(compliance), 1)) * 100, 1),
        "sla_thresholds": OT_PATCH_SLA,
        "top_overdue": sorted(breached, key=lambda x: x["age_days"], reverse=True)[:15],
    }


def main():
    parser = argparse.ArgumentParser(description="OT Patch Management Agent")
    parser.add_argument("--assets", required=True, help="OT asset inventory JSON")
    parser.add_argument("--patches", required=True, help="Patch data JSON")
    parser.add_argument("--output", default="ot_patch_report.json")
    args = parser.parse_args()
    assets = load_data(args.assets)
    patches = load_data(args.patches)
    compliance = check_compliance(assets, patches)
    report = generate_report(compliance, assets)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("OT patches: %d missing, %d breaches, %.1f%% compliant",
                report["missing_patches"], report["sla_breaches"], report["compliance_rate"])
    print(json.dumps(report, indent=2, default=str))

if __name__ == "__main__":
    main()
