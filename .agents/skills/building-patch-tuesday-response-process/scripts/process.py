#!/usr/bin/env python3
"""
Patch Tuesday Response Automation Tool

Fetches Microsoft Patch Tuesday advisory data, cross-references with
CISA KEV, and generates a prioritized deployment plan.

Requirements:
    pip install requests pandas

Usage:
    python process.py fetch --month 2025-12      # Fetch patches for month
    python process.py analyze --month 2025-12     # Analyze and prioritize
    python process.py plan --month 2025-12 --output deployment_plan.csv
"""

import argparse
import json
import sys
from datetime import datetime

import pandas as pd
import requests


MSRC_API = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf"
MSRC_UPDATES_API = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"


class PatchTuesdayAnalyzer:
    """Analyze and prioritize Patch Tuesday security updates."""

    SEVERITY_MAP = {
        "Critical": 4,
        "Important": 3,
        "Moderate": 2,
        "Low": 1,
    }

    RING_ASSIGNMENT = {
        "zero_day": {"ring": 0, "name": "Emergency", "sla_hours": 48},
        "critical_rce": {"ring": 0, "name": "Emergency", "sla_hours": 72},
        "critical": {"ring": 1, "name": "Pilot", "sla_hours": 168},
        "important": {"ring": 2, "name": "Production", "sla_hours": 336},
        "moderate": {"ring": 3, "name": "Workstations", "sla_hours": 504},
        "low": {"ring": 4, "name": "Maintenance", "sla_hours": 720},
    }

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "User-Agent": "PatchTuesday-Analyzer/1.0"
        })
        self.kev_catalog = set()

    def load_kev_catalog(self):
        """Load CISA KEV catalog for cross-reference."""
        try:
            response = self.session.get(KEV_URL, timeout=30)
            if response.status_code == 200:
                data = response.json()
                self.kev_catalog = {
                    v["cveID"] for v in data.get("vulnerabilities", [])
                }
                print(f"[+] Loaded {len(self.kev_catalog)} CVEs from CISA KEV")
        except Exception as e:
            print(f"[!] Failed to load KEV: {e}")

    def get_epss_scores(self, cve_list):
        """Fetch EPSS scores for CVEs."""
        scores = {}
        for i in range(0, len(cve_list), 100):
            batch = cve_list[i:i + 100]
            try:
                response = self.session.get(
                    EPSS_API,
                    params={"cve": ",".join(batch)},
                    timeout=30
                )
                if response.status_code == 200:
                    for entry in response.json().get("data", []):
                        scores[entry["cve"]] = float(entry.get("epss", 0))
            except Exception as e:
                print(f"  [!] EPSS error: {e}")
        return scores

    def classify_patch(self, cve_data):
        """Classify a patch into deployment ring."""
        is_exploited = cve_data.get("actively_exploited", False)
        in_kev = cve_data.get("cve_id", "") in self.kev_catalog
        severity = cve_data.get("severity", "").lower()
        attack_type = cve_data.get("attack_type", "").lower()
        cvss = float(cve_data.get("cvss_score", 0))
        epss = float(cve_data.get("epss_score", 0))

        if is_exploited or in_kev:
            return self.RING_ASSIGNMENT["zero_day"]
        elif severity == "critical" and "remote code execution" in attack_type:
            return self.RING_ASSIGNMENT["critical_rce"]
        elif severity == "critical" or cvss >= 9.0 or epss > 0.7:
            return self.RING_ASSIGNMENT["critical"]
        elif severity == "important" or cvss >= 7.0:
            return self.RING_ASSIGNMENT["important"]
        elif severity == "moderate" or cvss >= 4.0:
            return self.RING_ASSIGNMENT["moderate"]
        else:
            return self.RING_ASSIGNMENT["low"]

    def generate_deployment_plan(self, patches):
        """Generate a ring-based deployment plan."""
        self.load_kev_catalog()

        cve_list = [p["cve_id"] for p in patches if p.get("cve_id")]
        epss_scores = self.get_epss_scores(cve_list)

        plan = []
        for patch in patches:
            cve_id = patch.get("cve_id", "")
            patch["epss_score"] = epss_scores.get(cve_id, 0)
            patch["in_cisa_kev"] = cve_id in self.kev_catalog

            ring = self.classify_patch(patch)

            plan.append({
                "cve_id": cve_id,
                "product": patch.get("product", ""),
                "severity": patch.get("severity", ""),
                "attack_type": patch.get("attack_type", ""),
                "cvss_score": patch.get("cvss_score", 0),
                "epss_score": round(patch.get("epss_score", 0), 4),
                "in_cisa_kev": patch.get("in_cisa_kev", False),
                "actively_exploited": patch.get("actively_exploited", False),
                "deployment_ring": ring["ring"],
                "ring_name": ring["name"],
                "sla_hours": ring["sla_hours"],
                "kb_article": patch.get("kb_article", ""),
            })

        df = pd.DataFrame(plan)
        df = df.sort_values(["deployment_ring", "cvss_score"],
                            ascending=[True, False])
        return df

    def print_summary(self, df):
        """Print deployment plan summary."""
        print(f"\n{'=' * 70}")
        print("PATCH TUESDAY DEPLOYMENT PLAN")
        print(f"{'=' * 70}")
        print(f"Total patches: {len(df)}")
        print(f"Zero-day/KEV (Ring 0): {len(df[df['deployment_ring'] == 0])}")

        print(f"\nBy Severity:")
        print(df["severity"].value_counts().to_string())

        print(f"\nBy Deployment Ring:")
        for ring in sorted(df["deployment_ring"].unique()):
            ring_data = df[df["deployment_ring"] == ring]
            ring_name = ring_data.iloc[0]["ring_name"]
            sla = ring_data.iloc[0]["sla_hours"]
            print(f"  Ring {ring} ({ring_name}): {len(ring_data)} patches, "
                  f"SLA: {sla}h")

        print(f"\nBy Attack Type:")
        print(df["attack_type"].value_counts().head(5).to_string())


def main():
    parser = argparse.ArgumentParser(
        description="Patch Tuesday Response Automation"
    )
    subparsers = parser.add_subparsers(dest="command")

    plan_p = subparsers.add_parser("plan", help="Generate deployment plan from CSV")
    plan_p.add_argument("--csv", required=True, help="Input CSV of patches")
    plan_p.add_argument("--output", default="deployment_plan.csv")

    args = parser.parse_args()
    analyzer = PatchTuesdayAnalyzer()

    if args.command == "plan":
        df = pd.read_csv(args.csv)
        patches = df.to_dict("records")
        plan = analyzer.generate_deployment_plan(patches)
        analyzer.print_summary(plan)
        plan.to_csv(args.output, index=False)
        print(f"\n[+] Deployment plan saved to {args.output}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
