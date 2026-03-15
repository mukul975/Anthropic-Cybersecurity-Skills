#!/usr/bin/env python3
"""
Vulnerability Remediation SLA Tracking Engine

Calculates SLA deadlines, monitors compliance, generates breach
notifications, and produces executive reporting dashboards.

Requirements:
    pip install pandas jinja2

Usage:
    python process.py calculate --vulns vulns.csv --assets assets.csv --output sla_assignments.csv
    python process.py monitor --sla-csv sla_assignments.csv --report sla_report.html
"""

import argparse
import json
import sys
from datetime import datetime, timedelta

import pandas as pd


class SLACalculator:
    """Calculate remediation SLA deadlines based on severity and asset tier."""

    DEFAULT_SLA_MATRIX = {
        ("Critical", "Tier1"): 2,
        ("Critical", "Tier2"): 3,
        ("Critical", "Tier3"): 7,
        ("High", "Tier1"): 7,
        ("High", "Tier2"): 14,
        ("High", "Tier3"): 30,
        ("Medium", "Tier1"): 30,
        ("Medium", "Tier2"): 45,
        ("Medium", "Tier3"): 60,
        ("Low", "Tier1"): 90,
        ("Low", "Tier2"): 90,
        ("Low", "Tier3"): 90,
    }

    SLA_ACCELERATORS = {
        "in_cisa_kev": 0.5,
        "exploit_available": 0.5,
        "internet_facing": 0.5,
        "epss_high": 0.5,
    }

    def __init__(self, sla_matrix: dict = None):
        self.sla_matrix = sla_matrix or self.DEFAULT_SLA_MATRIX

    def get_severity_label(self, cvss_score: float) -> str:
        """Map CVSS score to severity label."""
        if cvss_score >= 9.0:
            return "Critical"
        elif cvss_score >= 7.0:
            return "High"
        elif cvss_score >= 4.0:
            return "Medium"
        elif cvss_score > 0:
            return "Low"
        return "Info"

    def calculate_sla(self, severity: str, tier: str, accelerators: dict = None) -> int:
        """Calculate SLA days based on severity, tier, and accelerators."""
        base_sla = self.sla_matrix.get((severity, tier), 90)

        if accelerators:
            for accel, factor in self.SLA_ACCELERATORS.items():
                if accelerators.get(accel, False):
                    base_sla = int(base_sla * factor)

        return max(base_sla, 1)

    def assign_slas(self, vulns_df: pd.DataFrame, assets_df: pd.DataFrame) -> pd.DataFrame:
        """Assign SLA deadlines to all vulnerabilities."""
        merged = vulns_df.merge(
            assets_df[["hostname", "tier", "internet_facing"]],
            on="hostname", how="left"
        )

        results = []
        for _, row in merged.iterrows():
            severity = row.get("severity", self.get_severity_label(float(row.get("cvss_score", 0))))
            tier = row.get("tier", "Tier3")

            accelerators = {
                "in_cisa_kev": row.get("in_cisa_kev", False),
                "exploit_available": row.get("exploit_available", False),
                "internet_facing": row.get("internet_facing", False),
                "epss_high": float(row.get("epss_score", 0)) > 0.5,
            }

            sla_days = self.calculate_sla(severity, tier, accelerators)
            discovery_date = pd.to_datetime(row.get("discovery_date", datetime.now()))
            deadline = discovery_date + timedelta(days=sla_days)

            results.append({
                **row.to_dict(),
                "severity": severity,
                "sla_days": sla_days,
                "discovery_date": discovery_date.isoformat(),
                "sla_deadline": deadline.isoformat(),
                "days_remaining": (deadline - datetime.now()).days,
                "sla_status": self._get_sla_status(deadline, row.get("remediated_date")),
            })

        return pd.DataFrame(results)

    def _get_sla_status(self, deadline: datetime, remediated_date=None) -> str:
        """Determine SLA status."""
        now = datetime.now()
        if remediated_date and pd.notna(remediated_date):
            rem_date = pd.to_datetime(remediated_date)
            if isinstance(deadline, str):
                deadline = pd.to_datetime(deadline)
            return "compliant" if rem_date <= deadline else "breached_remediated"

        if isinstance(deadline, str):
            deadline = pd.to_datetime(deadline)

        days_remaining = (deadline - now).days
        if days_remaining < 0:
            return "breached"
        elif days_remaining <= 3:
            return "critical"
        elif days_remaining <= 7:
            return "warning"
        return "on_track"


class SLAMonitor:
    """Monitor SLA compliance and generate reports."""

    def __init__(self, sla_df: pd.DataFrame):
        self.sla_df = sla_df

    def get_compliance_summary(self) -> dict:
        """Calculate overall SLA compliance metrics."""
        total = len(self.sla_df)
        status_counts = self.sla_df["sla_status"].value_counts().to_dict()

        compliant = status_counts.get("compliant", 0) + status_counts.get("on_track", 0)
        breached = status_counts.get("breached", 0) + status_counts.get("breached_remediated", 0)
        warning = status_counts.get("warning", 0) + status_counts.get("critical", 0)

        remediated = self.sla_df[self.sla_df["sla_status"].isin(["compliant", "breached_remediated"])]
        if not remediated.empty:
            mttr_data = remediated.copy()
            mttr_data["disc"] = pd.to_datetime(mttr_data["discovery_date"])
            mttr_data["rem"] = pd.to_datetime(mttr_data.get("remediated_date", datetime.now()))
            avg_mttr = (mttr_data["rem"] - mttr_data["disc"]).dt.days.mean()
        else:
            avg_mttr = 0

        return {
            "total_vulns": total,
            "compliant": compliant,
            "compliance_rate": f"{compliant / max(total, 1) * 100:.1f}%",
            "breached": breached,
            "breach_rate": f"{breached / max(total, 1) * 100:.1f}%",
            "at_risk": warning,
            "avg_mttr_days": round(avg_mttr, 1),
            "by_severity": self.sla_df.groupby("severity")["sla_status"].value_counts().to_dict(),
        }

    def get_breach_list(self) -> pd.DataFrame:
        """Get list of SLA-breached vulnerabilities."""
        return self.sla_df[self.sla_df["sla_status"] == "breached"].sort_values("days_remaining")

    def generate_report(self, output_path: str):
        """Generate SLA compliance HTML report."""
        summary = self.get_compliance_summary()
        breaches = self.get_breach_list().head(30)

        by_sev = self.sla_df.groupby("severity").agg(
            total=("sla_status", "count"),
            compliant=("sla_status", lambda x: (x.isin(["compliant", "on_track"])).sum()),
            breached=("sla_status", lambda x: (x.isin(["breached", "breached_remediated"])).sum()),
        ).reset_index()
        by_sev["rate"] = (by_sev["compliant"] / by_sev["total"] * 100).round(1)

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>SLA Compliance Dashboard - {datetime.now().strftime('%Y-%m-%d')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #0f3460; color: white; padding: 20px; border-radius: 8px; }}
        .metrics {{ display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }}
        .card {{ background: white; padding: 20px; border-radius: 8px; flex: 1; min-width: 180px;
                 box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
        .card h3 {{ margin: 0; font-size: 2em; }}
        .green {{ border-top: 4px solid #27ae60; }}
        .red {{ border-top: 4px solid #e74c3c; }}
        .yellow {{ border-top: 4px solid #f39c12; }}
        table {{ width: 100%; border-collapse: collapse; background: white; margin: 15px 0;
                 box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        th {{ background: #2c3e50; color: white; padding: 10px; text-align: left; }}
        td {{ padding: 8px 10px; border-bottom: 1px solid #eee; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Vulnerability Remediation SLA Dashboard</h1>
        <p>Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
    </div>
    <div class="metrics">
        <div class="card green"><h3>{summary['compliance_rate']}</h3><p>SLA Compliance</p></div>
        <div class="card red"><h3>{summary['breached']}</h3><p>SLA Breaches</p></div>
        <div class="card yellow"><h3>{summary['at_risk']}</h3><p>At Risk</p></div>
        <div class="card"><h3>{summary['avg_mttr_days']}d</h3><p>Avg MTTR</p></div>
    </div>

    <h2>Compliance by Severity</h2>
    <table>
        <tr><th>Severity</th><th>Total</th><th>Compliant</th><th>Breached</th><th>Rate</th></tr>
        {''.join(f"<tr><td>{r.severity}</td><td>{r.total}</td><td>{r.compliant}</td><td>{r.breached}</td><td>{r.rate}%</td></tr>" for r in by_sev.itertuples())}
    </table>

    <h2>Active SLA Breaches (Top 30)</h2>
    <table>
        <tr><th>Host</th><th>CVE</th><th>Severity</th><th>SLA Days</th><th>Days Overdue</th></tr>
        {''.join(f"<tr><td>{r.hostname if hasattr(r,'hostname') else ''}</td><td>{r.cve if hasattr(r,'cve') else ''}</td><td>{r.severity}</td><td>{r.sla_days}</td><td>{abs(r.days_remaining)}</td></tr>" for r in breaches.itertuples())}
    </table>
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[+] SLA report saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Vulnerability Remediation SLA Engine")
    subparsers = parser.add_subparsers(dest="command")

    calc_p = subparsers.add_parser("calculate", help="Assign SLA deadlines")
    calc_p.add_argument("--vulns", required=True, help="Vulnerabilities CSV")
    calc_p.add_argument("--assets", required=True, help="Assets CSV")
    calc_p.add_argument("--output", required=True, help="Output SLA CSV")

    mon_p = subparsers.add_parser("monitor", help="Monitor SLA compliance")
    mon_p.add_argument("--sla-csv", required=True, help="SLA assignments CSV")
    mon_p.add_argument("--report", default="sla_report.html", help="HTML report output")

    args = parser.parse_args()

    if args.command == "calculate":
        calc = SLACalculator()
        vulns = pd.read_csv(args.vulns)
        assets = pd.read_csv(args.assets)
        result = calc.assign_slas(vulns, assets)
        result.to_csv(args.output, index=False)
        print(f"[+] SLA assignments saved to: {args.output}")
        print(f"    Total: {len(result)}, Breached: {len(result[result['sla_status']=='breached'])}")

    elif args.command == "monitor":
        sla_df = pd.read_csv(args.sla_csv)
        monitor = SLAMonitor(sla_df)
        summary = monitor.get_compliance_summary()
        print(f"\n=== SLA Compliance Summary ===")
        print(f"Compliance Rate: {summary['compliance_rate']}")
        print(f"Breaches: {summary['breached']}")
        print(f"Avg MTTR: {summary['avg_mttr_days']} days")
        monitor.generate_report(args.report)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
