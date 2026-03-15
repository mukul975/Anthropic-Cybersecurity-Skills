#!/usr/bin/env python3
"""
BAS Results Analyzer and Control Effectiveness Calculator

Processes Breach and Attack Simulation results to calculate
security control effectiveness scores and identify gaps.

Requirements:
    pip install pandas

Usage:
    python process.py analyze --csv bas_results.csv --output control_scores.csv
    python process.py gaps --csv bas_results.csv --output gaps.csv
    python process.py trend --dir results/ --output trend.csv
"""

import argparse
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import pandas as pd


CONTROL_TECHNIQUE_MAP = {
    "email_gateway": ["T1566.001", "T1566.002", "T1566.003"],
    "edr": ["T1059.001", "T1059.003", "T1003.001", "T1055", "T1547.001",
            "T1053.005", "T1027", "T1140"],
    "ngfw_proxy": ["T1071.001", "T1071.004", "T1048.001", "T1048.003",
                   "T1572", "T1090"],
    "siem": ["T1087", "T1018", "T1069", "T1021.002", "T1021.001"],
    "dlp": ["T1048", "T1567", "T1041", "T1560"],
    "ndr": ["T1071", "T1021", "T1040", "T1046"],
    "waf": ["T1190", "T1210"],
    "pam": ["T1078", "T1134", "T1098"],
}


def analyze_control_effectiveness(df):
    """Calculate control effectiveness from BAS results."""
    scores = []

    for control, techniques in CONTROL_TECHNIQUE_MAP.items():
        relevant = df[df["technique_id"].isin(techniques)]
        if len(relevant) == 0:
            continue

        total = len(relevant)
        prevented = len(relevant[relevant["result"] == "prevented"])
        detected = len(relevant[relevant["result"] == "detected"])
        missed = len(relevant[relevant["result"] == "missed"])

        scores.append({
            "control": control,
            "total_tests": total,
            "prevented": prevented,
            "detected": detected,
            "missed": missed,
            "prevention_rate": round(prevented / total * 100, 1),
            "detection_rate": round(detected / total * 100, 1),
            "effectiveness": round((prevented + detected) / total * 100, 1),
            "gap_rate": round(missed / total * 100, 1),
        })

    return pd.DataFrame(scores).sort_values("effectiveness", ascending=True)


def identify_gaps(df):
    """Identify attack techniques that bypass all controls."""
    missed = df[df["result"] == "missed"].copy()
    if len(missed) == 0:
        print("[+] No gaps found - all attacks were prevented or detected!")
        return pd.DataFrame()

    gaps = missed.groupby(["technique_id", "technique_name"]).agg(
        miss_count=("result", "count"),
        targets=("target", lambda x: ", ".join(x.unique())),
    ).reset_index().sort_values("miss_count", ascending=False)

    return gaps


def print_summary(scores_df, gaps_df):
    """Print analysis summary."""
    print(f"\n{'=' * 70}")
    print("BAS CONTROL EFFECTIVENESS REPORT")
    print(f"{'=' * 70}")

    print(f"\nControl Scores:")
    for _, row in scores_df.iterrows():
        status = "PASS" if row["effectiveness"] >= 80 else "WARN" if row["effectiveness"] >= 60 else "FAIL"
        print(f"  [{status}] {row['control']:<15} "
              f"Effectiveness: {row['effectiveness']}% "
              f"(Prevent: {row['prevention_rate']}% | "
              f"Detect: {row['detection_rate']}% | "
              f"Miss: {row['gap_rate']}%)")

    if len(gaps_df) > 0:
        print(f"\nTop Security Gaps (attacks that bypass controls):")
        for _, row in gaps_df.head(10).iterrows():
            print(f"  {row['technique_id']}: {row['technique_name']} "
                  f"({row['miss_count']} misses)")


def main():
    parser = argparse.ArgumentParser(description="BAS Results Analyzer")
    subparsers = parser.add_subparsers(dest="command")

    a_p = subparsers.add_parser("analyze", help="Analyze control effectiveness")
    a_p.add_argument("--csv", required=True)
    a_p.add_argument("--output", default="control_scores.csv")

    g_p = subparsers.add_parser("gaps", help="Identify security gaps")
    g_p.add_argument("--csv", required=True)
    g_p.add_argument("--output", default="gaps.csv")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    df = pd.read_csv(args.csv)

    if args.command == "analyze":
        scores = analyze_control_effectiveness(df)
        gaps = identify_gaps(df)
        print_summary(scores, gaps)
        scores.to_csv(args.output, index=False)
        print(f"\n[+] Control scores saved to {args.output}")

    elif args.command == "gaps":
        gaps = identify_gaps(df)
        gaps.to_csv(args.output, index=False)
        print(f"[+] {len(gaps)} gaps saved to {args.output}")


if __name__ == "__main__":
    main()
