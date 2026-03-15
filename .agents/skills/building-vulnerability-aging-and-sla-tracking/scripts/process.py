#!/usr/bin/env python3
"""
Vulnerability Aging and SLA Tracking Engine

Calculates vulnerability aging, SLA compliance, and generates
escalation reports and KPI dashboards.

Requirements:
    pip install pandas

Usage:
    python process.py analyze --csv vulns.csv --output aging_report.csv
    python process.py kpis --csv vulns.csv
    python process.py escalations --csv vulns.csv --output escalations.csv
"""

import argparse
import sys
from datetime import datetime, timedelta

import pandas as pd


SLA_DAYS = {
    "Critical": 14,
    "High": 30,
    "Medium": 60,
    "Low": 90,
}


def calculate_aging(df, sla_config=None):
    """Add aging and SLA columns to vulnerability dataframe."""
    sla = sla_config or SLA_DAYS
    today = pd.Timestamp.now()

    df["discovery_date"] = pd.to_datetime(df["discovery_date"])
    df["remediation_date"] = pd.to_datetime(df["remediation_date"], errors="coerce")

    df["age_days"] = df.apply(
        lambda r: (r["remediation_date"] - r["discovery_date"]).days
        if pd.notna(r["remediation_date"])
        else (today - r["discovery_date"]).days,
        axis=1
    )

    df["sla_days"] = df["severity"].map(sla).fillna(90).astype(int)
    df["sla_deadline"] = df["discovery_date"] + pd.to_timedelta(df["sla_days"], unit="D")
    df["is_open"] = df["remediation_date"].isna()
    df["is_overdue"] = df["is_open"] & (df["age_days"] > df["sla_days"])
    df["days_overdue"] = df.apply(
        lambda r: max(0, r["age_days"] - r["sla_days"]) if r["is_overdue"] else 0,
        axis=1
    )
    df["sla_pct_elapsed"] = (df["age_days"] / df["sla_days"] * 100).round(1)
    df["within_sla"] = df.apply(
        lambda r: r["age_days"] <= r["sla_days"]
        if pd.notna(r["remediation_date"]) else None,
        axis=1
    )

    return df


def generate_kpis(df):
    """Generate KPI summary."""
    open_df = df[df["is_open"]]
    closed_df = df[~df["is_open"]]

    print(f"\n{'=' * 60}")
    print("VULNERABILITY AGING KPI REPORT")
    print(f"{'=' * 60}")
    print(f"Report Date:           {datetime.now().strftime('%Y-%m-%d')}")
    print(f"Total Vulnerabilities: {len(df)}")
    print(f"Open:                  {len(open_df)}")
    print(f"Closed:                {len(closed_df)}")
    print(f"Overdue:               {open_df['is_overdue'].sum()}")

    if len(closed_df) > 0:
        mttr = closed_df["age_days"].mean()
        sla_rate = closed_df["within_sla"].mean() * 100
        print(f"\nMTTR (all):            {mttr:.1f} days")
        print(f"SLA Compliance Rate:   {sla_rate:.1f}%")

        for sev in ["Critical", "High", "Medium", "Low"]:
            sev_df = closed_df[closed_df["severity"] == sev]
            if len(sev_df) > 0:
                print(f"  {sev} MTTR: {sev_df['age_days'].mean():.1f}d "
                      f"| SLA: {sev_df['within_sla'].mean() * 100:.1f}%")

    print(f"\nOpen Vulnerabilities by Age:")
    bins = [0, 7, 14, 30, 60, 90, float("inf")]
    labels = ["0-7d", "8-14d", "15-30d", "31-60d", "61-90d", "90+d"]
    if len(open_df) > 0:
        open_df = open_df.copy()
        open_df["age_bucket"] = pd.cut(open_df["age_days"], bins=bins, labels=labels)
        print(open_df["age_bucket"].value_counts().sort_index().to_string())

    print(f"\nOverdue by Severity:")
    overdue = open_df[open_df["is_overdue"]]
    if len(overdue) > 0:
        print(overdue.groupby("severity")["days_overdue"].agg(["count", "mean", "max"]).to_string())


def generate_escalations(df):
    """Generate escalation list."""
    open_df = df[df["is_open"]].copy()
    escalations = []

    for _, row in open_df.iterrows():
        pct = row["sla_pct_elapsed"]
        if pct >= 120:
            level = "VP/CTO Escalation"
        elif pct >= 100:
            level = "CISO Notification"
        elif pct >= 75:
            level = "Manager Escalation"
        elif pct >= 50:
            level = "Owner Reminder"
        else:
            continue

        escalations.append({
            "cve_id": row.get("cve_id", ""),
            "severity": row["severity"],
            "asset": row.get("asset", ""),
            "owner": row.get("owner", ""),
            "age_days": row["age_days"],
            "sla_days": row["sla_days"],
            "days_overdue": row["days_overdue"],
            "sla_pct": pct,
            "escalation_level": level,
        })

    return pd.DataFrame(escalations).sort_values("sla_pct", ascending=False)


def main():
    parser = argparse.ArgumentParser(description="Vulnerability Aging and SLA Tracker")
    subparsers = parser.add_subparsers(dest="command")

    analyze_p = subparsers.add_parser("analyze", help="Calculate aging metrics")
    analyze_p.add_argument("--csv", required=True)
    analyze_p.add_argument("--output", default="aging_report.csv")

    subparsers.add_parser("kpis", help="Generate KPI summary").add_argument("--csv", required=True)

    esc_p = subparsers.add_parser("escalations", help="Generate escalation list")
    esc_p.add_argument("--csv", required=True)
    esc_p.add_argument("--output", default="escalations.csv")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    df = pd.read_csv(args.csv)
    df = calculate_aging(df)

    if args.command == "analyze":
        df.to_csv(args.output, index=False)
        print(f"[+] Aging report saved to {args.output}")
        generate_kpis(df)
    elif args.command == "kpis":
        generate_kpis(df)
    elif args.command == "escalations":
        esc_df = generate_escalations(df)
        esc_df.to_csv(args.output, index=False)
        print(f"[+] {len(esc_df)} escalations saved to {args.output}")
        if len(esc_df) > 0:
            print(esc_df["escalation_level"].value_counts().to_string())


if __name__ == "__main__":
    main()
