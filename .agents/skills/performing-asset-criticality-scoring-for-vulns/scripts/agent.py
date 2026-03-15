#!/usr/bin/env python3
"""Asset criticality scoring agent for vulnerability prioritization."""

import json
import sys
import argparse
import csv
from datetime import datetime


CRITICALITY_WEIGHTS = {
    "data_sensitivity": 0.25,
    "business_function": 0.20,
    "regulatory_scope": 0.15,
    "network_exposure": 0.20,
    "recoverability": 0.10,
    "user_count": 0.10,
}

DATA_SENSITIVITY_SCORES = {
    "public": 1, "internal": 2, "confidential": 3,
    "restricted": 4, "pci": 5, "phi": 5, "pii": 4,
}

BUSINESS_FUNCTION_SCORES = {
    "test": 1, "development": 2, "staging": 2,
    "internal-tool": 3, "customer-facing": 4,
    "revenue-generating": 5, "critical-infrastructure": 5,
}

REGULATORY_SCOPE_SCORES = {
    "none": 1, "internal-policy": 2, "soc2": 3,
    "gdpr": 4, "pci-dss": 5, "hipaa": 5, "fedramp": 5,
}

NETWORK_EXPOSURE_SCORES = {
    "air-gapped": 1, "internal-only": 2, "vpn-accessible": 3,
    "dmz": 4, "internet-facing": 5,
}

RECOVERABILITY_SCORES = {
    "auto-recovery": 1, "backup-available": 2,
    "manual-recovery": 3, "extended-downtime": 4,
    "no-recovery": 5,
}


def load_asset_inventory(csv_path):
    """Load asset inventory from CSV file."""
    assets = []
    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            assets.append(row)
    return assets


def calculate_criticality_score(asset):
    """Calculate weighted criticality score for a single asset."""
    scores = {}
    scores["data_sensitivity"] = DATA_SENSITIVITY_SCORES.get(
        asset.get("data_classification", "internal").lower(), 2)
    scores["business_function"] = BUSINESS_FUNCTION_SCORES.get(
        asset.get("business_function", "internal-tool").lower(), 3)
    scores["regulatory_scope"] = REGULATORY_SCOPE_SCORES.get(
        asset.get("regulatory_scope", "none").lower(), 1)
    scores["network_exposure"] = NETWORK_EXPOSURE_SCORES.get(
        asset.get("network_exposure", "internal-only").lower(), 2)
    scores["recoverability"] = RECOVERABILITY_SCORES.get(
        asset.get("recoverability", "backup-available").lower(), 2)

    user_count = int(asset.get("user_count", 0))
    if user_count > 10000:
        scores["user_count"] = 5
    elif user_count > 1000:
        scores["user_count"] = 4
    elif user_count > 100:
        scores["user_count"] = 3
    elif user_count > 10:
        scores["user_count"] = 2
    else:
        scores["user_count"] = 1

    weighted_score = sum(
        scores[factor] * weight
        for factor, weight in CRITICALITY_WEIGHTS.items()
    )

    if weighted_score >= 4.0:
        tier = 1
        tier_name = "Crown Jewel"
    elif weighted_score >= 3.0:
        tier = 2
        tier_name = "Business Critical"
    elif weighted_score >= 2.0:
        tier = 3
        tier_name = "Important"
    elif weighted_score >= 1.5:
        tier = 4
        tier_name = "Standard"
    else:
        tier = 5
        tier_name = "Low Impact"

    return {
        "asset": asset.get("hostname", asset.get("name", "unknown")),
        "factor_scores": scores,
        "weighted_score": round(weighted_score, 2),
        "tier": tier,
        "tier_name": tier_name,
    }


def calculate_risk_adjusted_priority(criticality_tier, cvss_score):
    """Combine CVSS score with asset criticality for risk-adjusted priority."""
    tier_multipliers = {1: 1.5, 2: 1.3, 3: 1.0, 4: 0.8, 5: 0.5}
    multiplier = tier_multipliers.get(criticality_tier, 1.0)
    adjusted = min(cvss_score * multiplier, 10.0)
    return round(adjusted, 1)


def generate_sla_matrix(criticality_tier):
    """Generate remediation SLA based on asset criticality tier."""
    sla_matrix = {
        1: {"critical": "24h", "high": "72h", "medium": "7d", "low": "30d"},
        2: {"critical": "48h", "high": "7d", "medium": "14d", "low": "60d"},
        3: {"critical": "7d", "high": "14d", "medium": "30d", "low": "90d"},
        4: {"critical": "14d", "high": "30d", "medium": "60d", "low": "180d"},
        5: {"critical": "30d", "high": "60d", "medium": "90d", "low": "365d"},
    }
    return sla_matrix.get(criticality_tier, sla_matrix[3])


def run_audit(args):
    """Execute asset criticality scoring audit."""
    print(f"\n{'='*60}")
    print(f"  ASSET CRITICALITY SCORING FOR VULNERABILITY PRIORITIZATION")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    report = {}

    if args.inventory:
        assets = load_asset_inventory(args.inventory)
        scored = [calculate_criticality_score(a) for a in assets]
        scored.sort(key=lambda x: x["weighted_score"], reverse=True)

        report["scored_assets"] = scored
        tier_counts = {}
        for s in scored:
            tier_counts[s["tier_name"]] = tier_counts.get(s["tier_name"], 0) + 1
        report["tier_distribution"] = tier_counts

        print(f"--- ASSET CRITICALITY SCORES ({len(scored)} assets) ---")
        for s in scored[:20]:
            print(f"  Tier {s['tier']} ({s['tier_name']}): {s['asset']} "
                  f"— score {s['weighted_score']}")

        print(f"\n--- TIER DISTRIBUTION ---")
        for tier_name, count in sorted(tier_counts.items()):
            print(f"  {tier_name}: {count} assets")

        print(f"\n--- REMEDIATION SLA MATRIX ---")
        for tier in range(1, 6):
            sla = generate_sla_matrix(tier)
            print(f"  Tier {tier}: Critical={sla['critical']} High={sla['high']} "
                  f"Medium={sla['medium']} Low={sla['low']}")

    if args.cvss_score and args.asset_tier:
        adjusted = calculate_risk_adjusted_priority(args.asset_tier, args.cvss_score)
        sla = generate_sla_matrix(args.asset_tier)
        report["risk_adjustment"] = {
            "original_cvss": args.cvss_score,
            "asset_tier": args.asset_tier,
            "adjusted_priority": adjusted,
            "sla": sla,
        }
        print(f"\n--- RISK-ADJUSTED PRIORITY ---")
        print(f"  CVSS: {args.cvss_score} x Tier {args.asset_tier} = {adjusted}")
        print(f"  SLA: {sla}")

    return report


def main():
    parser = argparse.ArgumentParser(description="Asset Criticality Scoring Agent")
    parser.add_argument("--inventory", help="CSV file with asset inventory")
    parser.add_argument("--cvss-score", type=float, help="CVSS score to adjust")
    parser.add_argument("--asset-tier", type=int, choices=[1, 2, 3, 4, 5],
                        help="Asset criticality tier (1=highest)")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
