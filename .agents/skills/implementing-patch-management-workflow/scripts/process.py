#!/usr/bin/env python3
"""
Patch Management Workflow Automation

Tracks patch compliance, generates deployment plans, and monitors
patch installation success across the enterprise.

Requirements:
    pip install requests pandas jinja2 pyyaml

Usage:
    python process.py compliance --scan-csv scan_results.csv --asset-csv assets.csv
    python process.py plan --patches patches.csv --rings rings.yaml
    python process.py report --compliance-csv compliance.csv
"""

import argparse
import csv
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import yaml


class PatchComplianceTracker:
    """Track and report patch compliance across the enterprise."""

    SLA_MAP = {
        "Critical": 2,
        "High": 7,
        "Medium": 30,
        "Low": 90,
    }

    def __init__(self):
        self.assets = pd.DataFrame()
        self.patches = pd.DataFrame()
        self.compliance = pd.DataFrame()

    def load_assets(self, asset_file: str):
        """Load asset inventory from CSV."""
        self.assets = pd.read_csv(asset_file)
        required = {"hostname", "ip_address", "os", "tier"}
        if not required.issubset(set(self.assets.columns)):
            raise ValueError(f"Asset CSV must contain columns: {required}")
        print(f"[+] Loaded {len(self.assets)} assets")

    def load_scan_results(self, scan_file: str):
        """Load vulnerability scan results showing missing patches."""
        self.patches = pd.read_csv(scan_file)
        required = {"hostname", "plugin_id", "severity", "cve", "plugin_name"}
        if not required.issubset(set(self.patches.columns)):
            raise ValueError(f"Scan CSV must contain columns: {required}")
        print(f"[+] Loaded {len(self.patches)} patch findings")

    def calculate_compliance(self) -> pd.DataFrame:
        """Calculate patch compliance by host and severity."""
        if self.patches.empty:
            return pd.DataFrame()

        # Merge with asset data
        merged = self.patches.merge(
            self.assets[["hostname", "tier", "os"]],
            on="hostname", how="left"
        )

        # Calculate per-host compliance
        host_compliance = []
        for hostname, group in merged.groupby("hostname"):
            tier = group["tier"].iloc[0] if "tier" in group.columns else "Unknown"
            os_name = group["os"].iloc[0] if "os" in group.columns else "Unknown"

            critical = len(group[group["severity"] == "Critical"])
            high = len(group[group["severity"] == "High"])
            medium = len(group[group["severity"] == "Medium"])
            low = len(group[group["severity"] == "Low"])
            total = critical + high + medium + low

            # Compliance score: weighted by severity
            max_score = 100
            penalty = critical * 10 + high * 5 + medium * 2 + low * 0.5
            score = max(0, max_score - penalty)

            host_compliance.append({
                "hostname": hostname,
                "tier": tier,
                "os": os_name,
                "critical_missing": critical,
                "high_missing": high,
                "medium_missing": medium,
                "low_missing": low,
                "total_missing": total,
                "compliance_score": round(score, 1),
                "compliant": total == 0,
            })

        self.compliance = pd.DataFrame(host_compliance)
        self.compliance = self.compliance.sort_values("compliance_score")
        return self.compliance

    def get_summary(self) -> dict:
        """Generate compliance summary statistics."""
        if self.compliance.empty:
            self.calculate_compliance()

        total_hosts = len(self.compliance)
        compliant = len(self.compliance[self.compliance["compliant"]])
        avg_score = self.compliance["compliance_score"].mean()

        by_tier = {}
        for tier, group in self.compliance.groupby("tier"):
            by_tier[tier] = {
                "total": len(group),
                "compliant": len(group[group["compliant"]]),
                "rate": f"{len(group[group['compliant']]) / len(group) * 100:.1f}%",
                "avg_score": round(group["compliance_score"].mean(), 1),
            }

        return {
            "total_hosts": total_hosts,
            "compliant_hosts": compliant,
            "compliance_rate": f"{compliant / max(total_hosts, 1) * 100:.1f}%",
            "average_score": round(avg_score, 1),
            "total_missing_patches": int(self.compliance["total_missing"].sum()),
            "critical_patches_missing": int(self.compliance["critical_missing"].sum()),
            "by_tier": by_tier,
        }


class DeploymentPlanner:
    """Generate phased patch deployment plans."""

    DEFAULT_RINGS = {
        "ring0": {"name": "Lab/Test", "percentage": 0, "soak_hours": 48},
        "ring1": {"name": "IT Early Adopters", "percentage": 5, "soak_hours": 72},
        "ring2": {"name": "Business Pilot", "percentage": 15, "soak_hours": 120},
        "ring3": {"name": "General Deployment", "percentage": 50, "soak_hours": 168},
        "ring4": {"name": "Mission Critical", "percentage": 30, "soak_hours": 0},
    }

    def __init__(self, rings_config: dict = None):
        self.rings = rings_config or self.DEFAULT_RINGS

    def create_deployment_plan(self, patches: list, assets: pd.DataFrame,
                               start_date: datetime = None) -> dict:
        """Create a phased deployment plan for patches."""
        start = start_date or datetime.now()
        plan = {
            "plan_id": f"PATCH-{start.strftime('%Y%m%d-%H%M')}",
            "created": start.isoformat(),
            "patches": patches,
            "rings": [],
        }

        current_date = start
        for ring_id, ring_config in self.rings.items():
            ring_hosts = self._assign_ring_hosts(
                assets, ring_id, ring_config["percentage"]
            )

            ring_plan = {
                "ring": ring_id,
                "name": ring_config["name"],
                "start_date": current_date.isoformat(),
                "end_date": (current_date + timedelta(hours=ring_config["soak_hours"])).isoformat(),
                "soak_hours": ring_config["soak_hours"],
                "host_count": len(ring_hosts),
                "hosts": ring_hosts,
                "status": "pending",
                "success_criteria": {
                    "max_failure_rate": 5,
                    "required_services_up": True,
                    "no_critical_incidents": True,
                },
            }
            plan["rings"].append(ring_plan)
            current_date += timedelta(hours=ring_config["soak_hours"])

        plan["estimated_completion"] = current_date.isoformat()
        return plan

    def _assign_ring_hosts(self, assets: pd.DataFrame, ring_id: str,
                           percentage: int) -> list:
        """Assign hosts to deployment rings based on tier and percentage."""
        if assets.empty or percentage == 0:
            return []

        ring_map = {
            "ring0": lambda df: df[df["tier"] == "test"],
            "ring1": lambda df: df[df["tier"].isin(["dev", "it"])].sample(
                frac=min(percentage / 100, 1.0), random_state=42
            ) if len(df[df["tier"].isin(["dev", "it"])]) > 0 else pd.DataFrame(),
            "ring2": lambda df: df[df["tier"] == "staging"],
            "ring3": lambda df: df[df["tier"] == "production"].sample(
                frac=0.6, random_state=42
            ) if len(df[df["tier"] == "production"]) > 0 else pd.DataFrame(),
            "ring4": lambda df: df[df["tier"].isin(["production", "critical"])],
        }

        selector = ring_map.get(ring_id)
        if selector:
            try:
                selected = selector(assets)
                return selected["hostname"].tolist() if not selected.empty else []
            except (KeyError, ValueError):
                return []
        return []

    def export_plan(self, plan: dict, output_path: str):
        """Export deployment plan to JSON."""
        with open(output_path, "w") as f:
            json.dump(plan, f, indent=2, default=str)
        print(f"[+] Deployment plan exported to: {output_path}")


def generate_compliance_report(summary: dict, compliance_df: pd.DataFrame,
                                output_path: str):
    """Generate HTML compliance report."""
    top_noncompliant = compliance_df.head(20)

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Patch Compliance Report - {datetime.now().strftime('%Y-%m-%d')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #1a1a2e; color: white; padding: 20px; border-radius: 8px; }}
        .metrics {{ display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }}
        .card {{ background: white; padding: 20px; border-radius: 8px; flex: 1; min-width: 200px;
                 box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
        .card h3 {{ margin: 0; font-size: 2em; }}
        .card p {{ margin: 5px 0 0; color: #666; }}
        .green {{ border-top: 4px solid #27ae60; }}
        .red {{ border-top: 4px solid #e74c3c; }}
        .orange {{ border-top: 4px solid #e67e22; }}
        table {{ width: 100%; border-collapse: collapse; background: white; margin: 15px 0;
                 border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        th {{ background: #2c3e50; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #eee; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Patch Compliance Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
    </div>
    <div class="metrics">
        <div class="card green"><h3>{summary['compliance_rate']}</h3><p>Compliance Rate</p></div>
        <div class="card orange"><h3>{summary['total_hosts']}</h3><p>Total Hosts</p></div>
        <div class="card red"><h3>{summary['total_missing_patches']}</h3><p>Missing Patches</p></div>
        <div class="card red"><h3>{summary['critical_patches_missing']}</h3><p>Critical Missing</p></div>
    </div>

    <h2>Compliance by Tier</h2>
    <table>
        <tr><th>Tier</th><th>Total</th><th>Compliant</th><th>Rate</th><th>Avg Score</th></tr>
        {''.join(f"<tr><td>{tier}</td><td>{data['total']}</td><td>{data['compliant']}</td><td>{data['rate']}</td><td>{data['avg_score']}</td></tr>" for tier, data in summary['by_tier'].items())}
    </table>

    <h2>Top Non-Compliant Hosts</h2>
    <table>
        <tr><th>Hostname</th><th>Tier</th><th>OS</th><th>Critical</th><th>High</th><th>Medium</th><th>Score</th></tr>
        {''.join(f"<tr><td>{r.hostname}</td><td>{r.tier}</td><td>{r.os}</td><td>{r.critical_missing}</td><td>{r.high_missing}</td><td>{r.medium_missing}</td><td>{r.compliance_score}</td></tr>" for r in top_noncompliant.itertuples())}
    </table>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] Report saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Patch Management Workflow Automation")
    subparsers = parser.add_subparsers(dest="command")

    comp_parser = subparsers.add_parser("compliance", help="Calculate patch compliance")
    comp_parser.add_argument("--scan-csv", required=True, help="Vulnerability scan results CSV")
    comp_parser.add_argument("--asset-csv", required=True, help="Asset inventory CSV")
    comp_parser.add_argument("--output", default=None, help="Output compliance CSV")
    comp_parser.add_argument("--report", default=None, help="Output HTML report")

    plan_parser = subparsers.add_parser("plan", help="Create deployment plan")
    plan_parser.add_argument("--patches", required=True, help="Patches CSV")
    plan_parser.add_argument("--assets", required=True, help="Assets CSV")
    plan_parser.add_argument("--rings", default=None, help="Rings config YAML")
    plan_parser.add_argument("--output", default="deployment_plan.json")

    args = parser.parse_args()

    if args.command == "compliance":
        tracker = PatchComplianceTracker()
        tracker.load_assets(args.asset_csv)
        tracker.load_scan_results(args.scan_csv)
        compliance = tracker.calculate_compliance()
        summary = tracker.get_summary()

        print("\n=== Patch Compliance Summary ===")
        print(f"Total Hosts:         {summary['total_hosts']}")
        print(f"Compliant:           {summary['compliant_hosts']}")
        print(f"Compliance Rate:     {summary['compliance_rate']}")
        print(f"Missing Patches:     {summary['total_missing_patches']}")
        print(f"Critical Missing:    {summary['critical_patches_missing']}")

        if args.output:
            compliance.to_csv(args.output, index=False)
            print(f"[+] Compliance data saved to: {args.output}")

        if args.report:
            generate_compliance_report(summary, compliance, args.report)

    elif args.command == "plan":
        rings = None
        if args.rings:
            with open(args.rings) as f:
                rings = yaml.safe_load(f)

        planner = DeploymentPlanner(rings)
        assets = pd.read_csv(args.assets)
        patches_df = pd.read_csv(args.patches)
        patches = patches_df.to_dict(orient="records")

        plan = planner.create_deployment_plan(patches, assets)
        planner.export_plan(plan, args.output)

        print(f"\n=== Deployment Plan ===")
        for ring in plan["rings"]:
            print(f"  {ring['name']}: {ring['host_count']} hosts, "
                  f"soak: {ring['soak_hours']}h, start: {ring['start_date'][:10]}")
        print(f"Estimated completion: {plan['estimated_completion'][:10]}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
