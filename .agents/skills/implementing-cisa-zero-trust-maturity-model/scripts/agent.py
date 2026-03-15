#!/usr/bin/env python3
"""CISA Zero Trust Maturity Model assessment agent for organizational ZT posture evaluation."""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

PILLARS = ["Identity", "Devices", "Networks", "Applications", "Data"]
MATURITY_LEVELS = ["Traditional", "Initial", "Advanced", "Optimal"]
CROSS_CUTTING = ["Visibility & Analytics", "Automation & Orchestration", "Governance"]

PILLAR_CONTROLS = {
    "Identity": [
        "MFA enforced for all users",
        "Phishing-resistant MFA (FIDO2/PIV)",
        "Continuous identity validation",
        "Identity lifecycle management",
        "Privileged access management",
        "Just-in-time access provisioning",
    ],
    "Devices": [
        "Device inventory and compliance",
        "EDR deployed on all endpoints",
        "Device health attestation",
        "Real-time posture assessment",
        "Automated remediation for non-compliant devices",
    ],
    "Networks": [
        "Microsegmentation implemented",
        "Encrypted DNS (DoH/DoT)",
        "Network traffic encrypted in transit",
        "Software-defined perimeter",
        "Network access based on identity",
    ],
    "Applications": [
        "Application inventory maintained",
        "Application-level access controls",
        "Continuous application security testing",
        "Secure API gateway",
        "Application isolation and sandboxing",
    ],
    "Data": [
        "Data classification implemented",
        "Data loss prevention controls",
        "Encryption at rest for sensitive data",
        "Data access logging and monitoring",
        "Automated data lifecycle management",
    ],
}


def assess_control(control: str, implemented: bool, maturity: str) -> dict:
    """Assess a single control's implementation status and maturity."""
    level_scores = {"Traditional": 0, "Initial": 1, "Advanced": 2, "Optimal": 3}
    return {
        "control": control,
        "implemented": implemented,
        "maturity_level": maturity,
        "score": level_scores.get(maturity, 0) if implemented else 0,
    }


def assess_pillar(pillar: str, responses: Dict[str, dict]) -> dict:
    """Assess a single CISA ZT pillar based on control responses."""
    controls = PILLAR_CONTROLS.get(pillar, [])
    assessed = []
    for control in controls:
        resp = responses.get(control, {"implemented": False, "maturity": "Traditional"})
        assessed.append(assess_control(control, resp["implemented"], resp["maturity"]))
    max_score = len(controls) * 3
    actual_score = sum(c["score"] for c in assessed)
    pct = (actual_score / max_score * 100) if max_score else 0
    implemented_count = sum(1 for c in assessed if c["implemented"])
    if pct >= 75:
        level = "Optimal"
    elif pct >= 50:
        level = "Advanced"
    elif pct >= 25:
        level = "Initial"
    else:
        level = "Traditional"
    return {
        "pillar": pillar,
        "controls_assessed": len(assessed),
        "controls_implemented": implemented_count,
        "score": actual_score,
        "max_score": max_score,
        "percentage": round(pct, 1),
        "maturity_level": level,
        "controls": assessed,
    }


def load_assessment_data(data_path: str) -> dict:
    """Load assessment responses from JSON file."""
    with open(data_path, "r") as f:
        return json.load(f)


def compute_overall_maturity(pillar_results: List[dict]) -> dict:
    """Compute overall zero trust maturity from pillar assessments."""
    total_score = sum(p["score"] for p in pillar_results)
    total_max = sum(p["max_score"] for p in pillar_results)
    pct = (total_score / total_max * 100) if total_max else 0
    if pct >= 75:
        level = "Optimal"
    elif pct >= 50:
        level = "Advanced"
    elif pct >= 25:
        level = "Initial"
    else:
        level = "Traditional"
    return {"overall_score": total_score, "max_score": total_max,
            "percentage": round(pct, 1), "maturity_level": level}


def generate_recommendations(pillar_results: List[dict]) -> List[dict]:
    """Generate prioritized recommendations based on assessment gaps."""
    recs = []
    for pillar in pillar_results:
        for control in pillar["controls"]:
            if not control["implemented"]:
                recs.append({
                    "pillar": pillar["pillar"],
                    "control": control["control"],
                    "priority": "HIGH" if pillar["percentage"] < 50 else "MEDIUM",
                    "action": f"Implement: {control['control']}",
                })
    recs.sort(key=lambda r: 0 if r["priority"] == "HIGH" else 1)
    return recs


def generate_report(data_path: str) -> dict:
    """Generate CISA Zero Trust Maturity assessment report."""
    data = load_assessment_data(data_path)
    pillar_results = []
    for pillar in PILLARS:
        responses = data.get(pillar, {})
        pillar_results.append(assess_pillar(pillar, responses))
    overall = compute_overall_maturity(pillar_results)
    recs = generate_recommendations(pillar_results)
    return {
        "analysis_date": datetime.utcnow().isoformat(),
        "framework": "CISA Zero Trust Maturity Model v2.0",
        "overall_maturity": overall,
        "pillars": pillar_results,
        "recommendations": recs[:20],
        "recommendation_count": len(recs),
    }


def main():
    parser = argparse.ArgumentParser(description="CISA Zero Trust Maturity Model Assessment")
    parser.add_argument("--data", required=True, help="Path to assessment data JSON")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--output", default="ztmm_report.json")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    report = generate_report(args.data)
    out_path = os.path.join(args.output_dir, args.output)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", out_path)
    print(json.dumps(report["overall_maturity"], indent=2))


if __name__ == "__main__":
    main()
