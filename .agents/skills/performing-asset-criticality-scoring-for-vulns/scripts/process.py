#!/usr/bin/env python3
"""
Asset Criticality Scoring Engine

Calculates multi-factor criticality scores for assets and
applies SLA modifiers to vulnerability remediation timelines.

Requirements:
    pip install pandas

Usage:
    python process.py score --csv assets.csv --output scored_assets.csv
    python process.py apply --assets scored_assets.csv --vulns vulns.csv --output adjusted.csv
"""

import argparse
import sys

import pandas as pd


WEIGHTS = {
    "business_function": 0.25,
    "data_sensitivity": 0.25,
    "regulatory_scope": 0.15,
    "network_exposure": 0.15,
    "recoverability": 0.10,
    "user_population": 0.10,
}

TIERS = [
    (4.5, 1, "Crown Jewels", -0.50),
    (3.5, 2, "High Value", -0.25),
    (2.5, 3, "Standard", 0.00),
    (1.5, 4, "Low Impact", 0.25),
    (1.0, 5, "Minimal", 0.50),
]

BASE_SLA = {"Critical": 14, "High": 30, "Medium": 60, "Low": 90}


def score_assets(df):
    """Calculate criticality scores for all assets."""
    scores = []
    for _, row in df.iterrows():
        weighted = sum(
            row.get(factor, 3) * weight
            for factor, weight in WEIGHTS.items()
        )
        score = round(weighted, 2)

        tier, label, sla_mod = 5, "Minimal", 0.50
        for threshold, t, l, s in TIERS:
            if score >= threshold:
                tier, label, sla_mod = t, l, s
                break

        scores.append({
            **row.to_dict(),
            "criticality_score": score,
            "tier": tier,
            "tier_label": label,
            "sla_modifier": sla_mod,
        })

    return pd.DataFrame(scores).sort_values("criticality_score", ascending=False)


def apply_to_vulns(assets_df, vulns_df):
    """Apply asset criticality to vulnerability SLAs."""
    asset_map = {}
    for _, row in assets_df.iterrows():
        asset_map[row.get("asset_id", "")] = {
            "tier": row["tier"],
            "label": row["tier_label"],
            "sla_modifier": row["sla_modifier"],
        }

    results = []
    for _, vuln in vulns_df.iterrows():
        asset_id = vuln.get("asset_id", "")
        asset = asset_map.get(asset_id, {"tier": 3, "label": "Standard", "sla_modifier": 0})
        severity = vuln.get("severity", "Medium")
        base_sla = BASE_SLA.get(severity, 60)
        adjusted_sla = max(1, int(base_sla * (1 + asset["sla_modifier"])))

        results.append({
            **vuln.to_dict(),
            "asset_tier": asset["tier"],
            "asset_label": asset["label"],
            "base_sla_days": base_sla,
            "adjusted_sla_days": adjusted_sla,
        })

    return pd.DataFrame(results)


def main():
    parser = argparse.ArgumentParser(description="Asset Criticality Scoring Engine")
    subparsers = parser.add_subparsers(dest="command")

    s_p = subparsers.add_parser("score", help="Score assets")
    s_p.add_argument("--csv", required=True)
    s_p.add_argument("--output", default="scored_assets.csv")

    a_p = subparsers.add_parser("apply", help="Apply to vulnerabilities")
    a_p.add_argument("--assets", required=True)
    a_p.add_argument("--vulns", required=True)
    a_p.add_argument("--output", default="adjusted_vulns.csv")

    args = parser.parse_args()

    if args.command == "score":
        df = pd.read_csv(args.csv)
        scored = score_assets(df)
        scored.to_csv(args.output, index=False)
        print(f"[+] Scored {len(scored)} assets to {args.output}")
        print(scored["tier_label"].value_counts().to_string())

    elif args.command == "apply":
        assets = pd.read_csv(args.assets)
        vulns = pd.read_csv(args.vulns)
        result = apply_to_vulns(assets, vulns)
        result.to_csv(args.output, index=False)
        print(f"[+] Applied criticality to {len(result)} vulnerabilities")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
