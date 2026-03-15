#!/usr/bin/env python3
"""
CVSS Vulnerability Prioritization Engine

Calculates CVSS v4.0 base scores, enriches with EPSS threat intelligence,
and generates risk-weighted prioritization for vulnerability remediation.

Requirements:
    pip install requests pandas

Usage:
    python process.py score --cve CVE-2024-3094
    python process.py prioritize --csv vulns.csv --output prioritized.csv
    python process.py enrich --csv vulns.csv
"""

import argparse
import json
import math
import sys
from datetime import datetime

import pandas as pd
import requests


class CVSSv4Calculator:
    """CVSS v4.0 Base Score Calculator."""

    # CVSS v4.0 metric value mappings
    METRIC_VALUES = {
        "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
        "AC": {"L": 0.0, "H": 0.1},
        "AT": {"N": 0.0, "P": 0.1},
        "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
        "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
        "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
        "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
        "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
        "SC": {"H": 0.0, "L": 0.1, "N": 0.2},
        "SI": {"H": 0.0, "L": 0.1, "N": 0.2},
        "SA": {"H": 0.0, "L": 0.1, "N": 0.2},
    }

    # Severity thresholds
    SEVERITY_RATINGS = [
        (0.0, 0.0, "None"),
        (0.1, 3.9, "Low"),
        (4.0, 6.9, "Medium"),
        (7.0, 8.9, "High"),
        (9.0, 10.0, "Critical"),
    ]

    @staticmethod
    def parse_vector(vector_string: str) -> dict:
        """Parse a CVSS v4.0 vector string into metric components."""
        metrics = {}
        parts = vector_string.replace("CVSS:4.0/", "").replace("CVSS:3.1/", "").split("/")
        for part in parts:
            if ":" in part:
                key, value = part.split(":", 1)
                metrics[key] = value
        return metrics

    @staticmethod
    def get_severity(score: float) -> str:
        """Map a numeric CVSS score to its severity rating."""
        for low, high, rating in CVSSv4Calculator.SEVERITY_RATINGS:
            if low <= score <= high:
                return rating
        return "Unknown"

    @classmethod
    def estimate_base_score(cls, vector_string: str) -> float:
        """
        Estimate CVSS v4.0 base score from a vector string.
        Note: Full CVSS v4.0 scoring uses complex lookup tables from FIRST.
        This implements a simplified scoring approximation.
        """
        metrics = cls.parse_vector(vector_string)

        # Exploitability sub-score
        av = cls.METRIC_VALUES["AV"].get(metrics.get("AV", "N"), 0)
        ac = cls.METRIC_VALUES["AC"].get(metrics.get("AC", "L"), 0)
        at = cls.METRIC_VALUES["AT"].get(metrics.get("AT", "N"), 0)
        pr = cls.METRIC_VALUES["PR"].get(metrics.get("PR", "N"), 0)
        ui = cls.METRIC_VALUES["UI"].get(metrics.get("UI", "N"), 0)

        exploitability = 1.0 - (av + ac + at + pr + ui) / 1.0

        # Vulnerable system impact
        vc = cls.METRIC_VALUES["VC"].get(metrics.get("VC", "N"), 0.2)
        vi = cls.METRIC_VALUES["VI"].get(metrics.get("VI", "N"), 0.2)
        va = cls.METRIC_VALUES["VA"].get(metrics.get("VA", "N"), 0.2)

        vuln_impact = 1.0 - (vc + vi + va) / 0.6

        # Subsequent system impact
        sc = cls.METRIC_VALUES["SC"].get(metrics.get("SC", "N"), 0.2)
        si = cls.METRIC_VALUES["SI"].get(metrics.get("SI", "N"), 0.2)
        sa = cls.METRIC_VALUES["SA"].get(metrics.get("SA", "N"), 0.2)

        subseq_impact = 1.0 - (sc + si + sa) / 0.6

        # Combined impact (weighted)
        total_impact = 0.6 * vuln_impact + 0.4 * max(subseq_impact, 0)

        if total_impact <= 0:
            return 0.0

        # Approximate base score
        score = min(10.0, (exploitability * 4.0 + total_impact * 6.0))
        return round(score, 1)


class VulnerabilityEnricher:
    """Enrich vulnerability data with EPSS scores and CISA KEV status."""

    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EPSS_API = "https://api.first.org/data/v1/epss"
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self):
        self.kev_cache = None
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "CVSS-Prioritization-Tool/1.0"})

    def get_nvd_data(self, cve_id: str) -> dict:
        """Fetch CVE details from NVD API v2.0."""
        try:
            response = self.session.get(
                self.NVD_API, params={"cveId": cve_id}, timeout=30
            )
            if response.status_code == 200:
                data = response.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    cve_data = vulns[0].get("cve", {})
                    metrics = cve_data.get("metrics", {})

                    # Try CVSS v4.0 first, then v3.1
                    cvss_data = {}
                    if "cvssMetricV40" in metrics:
                        m = metrics["cvssMetricV40"][0]["cvssData"]
                        cvss_data = {
                            "version": "4.0",
                            "vector": m.get("vectorString", ""),
                            "base_score": m.get("baseScore", 0),
                            "severity": m.get("baseSeverity", ""),
                        }
                    elif "cvssMetricV31" in metrics:
                        m = metrics["cvssMetricV31"][0]["cvssData"]
                        cvss_data = {
                            "version": "3.1",
                            "vector": m.get("vectorString", ""),
                            "base_score": m.get("baseScore", 0),
                            "severity": m.get("baseSeverity", ""),
                        }

                    descriptions = cve_data.get("descriptions", [])
                    desc = next(
                        (d["value"] for d in descriptions if d["lang"] == "en"),
                        ""
                    )

                    return {
                        "cve_id": cve_id,
                        "description": desc[:300],
                        "published": cve_data.get("published", ""),
                        "cvss": cvss_data,
                    }
        except Exception as e:
            print(f"  [!] NVD API error for {cve_id}: {e}")
        return {}

    def get_epss_score(self, cve_id: str) -> dict:
        """Fetch EPSS score for a CVE from FIRST API."""
        try:
            response = self.session.get(
                self.EPSS_API, params={"cve": cve_id}, timeout=15
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("data"):
                    entry = data["data"][0]
                    return {
                        "epss_score": float(entry.get("epss", 0)),
                        "epss_percentile": float(entry.get("percentile", 0)),
                    }
        except Exception as e:
            print(f"  [!] EPSS API error for {cve_id}: {e}")
        return {"epss_score": 0.0, "epss_percentile": 0.0}

    def load_kev_catalog(self) -> set:
        """Load CISA Known Exploited Vulnerabilities catalog."""
        if self.kev_cache is not None:
            return self.kev_cache

        try:
            response = self.session.get(self.CISA_KEV_URL, timeout=30)
            if response.status_code == 200:
                data = response.json()
                self.kev_cache = {
                    v["cveID"] for v in data.get("vulnerabilities", [])
                }
                print(f"[+] Loaded {len(self.kev_cache)} CVEs from CISA KEV catalog")
                return self.kev_cache
        except Exception as e:
            print(f"[!] Failed to load CISA KEV: {e}")
        self.kev_cache = set()
        return self.kev_cache

    def is_in_kev(self, cve_id: str) -> bool:
        """Check if a CVE is in the CISA KEV catalog."""
        kev = self.load_kev_catalog()
        return cve_id in kev

    def enrich_cve(self, cve_id: str) -> dict:
        """Fully enrich a CVE with NVD, EPSS, and KEV data."""
        result = {"cve_id": cve_id}

        nvd = self.get_nvd_data(cve_id)
        if nvd:
            result.update({
                "description": nvd.get("description", ""),
                "published": nvd.get("published", ""),
                "cvss_version": nvd.get("cvss", {}).get("version", ""),
                "cvss_vector": nvd.get("cvss", {}).get("vector", ""),
                "cvss_base_score": nvd.get("cvss", {}).get("base_score", 0),
                "cvss_severity": nvd.get("cvss", {}).get("severity", ""),
            })

        epss = self.get_epss_score(cve_id)
        result.update(epss)

        result["in_cisa_kev"] = self.is_in_kev(cve_id)

        return result


class VulnerabilityPrioritizer:
    """Risk-weighted vulnerability prioritization engine."""

    def __init__(self, weights: dict = None):
        self.weights = weights or {
            "cvss": 0.25,
            "epss": 0.25,
            "asset_criticality": 0.20,
            "kev": 0.15,
            "exposure": 0.15,
        }

    def calculate_priority_score(self, vuln: dict) -> float:
        """Calculate composite priority score for a vulnerability."""
        cvss_score = float(vuln.get("cvss_base_score", 0)) / 10.0
        epss_score = float(vuln.get("epss_score", 0))
        asset_crit = float(vuln.get("asset_criticality", 3)) / 5.0
        kev_score = 1.0 if vuln.get("in_cisa_kev", False) else 0.0
        exposure = float(vuln.get("exposure_score", 3)) / 5.0

        priority = (
            cvss_score * self.weights["cvss"] +
            epss_score * self.weights["epss"] +
            asset_crit * self.weights["asset_criticality"] +
            kev_score * self.weights["kev"] +
            exposure * self.weights["exposure"]
        )

        return round(priority * 10, 2)

    def assign_sla(self, priority_score: float, cvss_score: float,
                   in_kev: bool = False) -> dict:
        """Assign remediation SLA based on priority score."""
        if in_kev or priority_score >= 8.0:
            return {"level": "P1-Emergency", "sla_days": 2, "sla": "48 hours"}
        elif priority_score >= 6.5 or cvss_score >= 9.0:
            return {"level": "P2-Critical", "sla_days": 7, "sla": "7 days"}
        elif priority_score >= 5.0 or cvss_score >= 7.0:
            return {"level": "P3-High", "sla_days": 14, "sla": "14 days"}
        elif priority_score >= 3.0 or cvss_score >= 4.0:
            return {"level": "P4-Medium", "sla_days": 30, "sla": "30 days"}
        else:
            return {"level": "P5-Low", "sla_days": 90, "sla": "90 days"}

    def prioritize(self, vulnerabilities: list) -> pd.DataFrame:
        """Prioritize a list of vulnerabilities and return sorted DataFrame."""
        results = []
        for vuln in vulnerabilities:
            score = self.calculate_priority_score(vuln)
            sla = self.assign_sla(
                score,
                float(vuln.get("cvss_base_score", 0)),
                vuln.get("in_cisa_kev", False)
            )

            results.append({
                **vuln,
                "priority_score": score,
                "priority_level": sla["level"],
                "sla_days": sla["sla_days"],
                "remediation_sla": sla["sla"],
            })

        df = pd.DataFrame(results)
        df = df.sort_values("priority_score", ascending=False)
        return df


def main():
    parser = argparse.ArgumentParser(description="CVSS Vulnerability Prioritization Engine")
    subparsers = parser.add_subparsers(dest="command")

    # Score a single CVE
    score_parser = subparsers.add_parser("score", help="Score and enrich a single CVE")
    score_parser.add_argument("--cve", required=True, help="CVE identifier (e.g., CVE-2024-3094)")

    # Prioritize a CSV of vulnerabilities
    pri_parser = subparsers.add_parser("prioritize", help="Prioritize vulnerabilities from CSV")
    pri_parser.add_argument("--csv", required=True, help="Input CSV with cve_id column")
    pri_parser.add_argument("--output", required=True, help="Output CSV with priorities")

    # Enrich a CSV with EPSS/KEV data
    enrich_parser = subparsers.add_parser("enrich", help="Enrich CVE list with EPSS and KEV")
    enrich_parser.add_argument("--csv", required=True, help="Input CSV with cve_id column")
    enrich_parser.add_argument("--output", default=None, help="Output enriched CSV")

    args = parser.parse_args()

    if args.command == "score":
        enricher = VulnerabilityEnricher()
        print(f"[*] Scoring {args.cve}...")

        result = enricher.enrich_cve(args.cve)
        print(f"\n{'='*60}")
        print(f"CVE:             {result.get('cve_id')}")
        print(f"Description:     {result.get('description', 'N/A')[:200]}")
        print(f"Published:       {result.get('published', 'N/A')}")
        print(f"CVSS Version:    {result.get('cvss_version', 'N/A')}")
        print(f"CVSS Vector:     {result.get('cvss_vector', 'N/A')}")
        print(f"CVSS Base Score: {result.get('cvss_base_score', 'N/A')}")
        print(f"CVSS Severity:   {result.get('cvss_severity', 'N/A')}")
        print(f"EPSS Score:      {result.get('epss_score', 0):.4f} ({result.get('epss_percentile', 0)*100:.1f}th percentile)")
        print(f"In CISA KEV:     {'Yes' if result.get('in_cisa_kev') else 'No'}")

        prioritizer = VulnerabilityPrioritizer()
        priority = prioritizer.calculate_priority_score(result)
        sla = prioritizer.assign_sla(
            priority, float(result.get("cvss_base_score", 0)),
            result.get("in_cisa_kev", False)
        )
        print(f"\nPriority Score:  {priority}")
        print(f"Priority Level:  {sla['level']}")
        print(f"Remediation SLA: {sla['sla']}")

    elif args.command == "prioritize":
        df = pd.read_csv(args.csv)
        if "cve_id" not in df.columns:
            print("[-] CSV must contain 'cve_id' column")
            sys.exit(1)

        enricher = VulnerabilityEnricher()
        enriched = []
        for _, row in df.iterrows():
            cve = row["cve_id"]
            print(f"[*] Processing {cve}...")
            data = enricher.enrich_cve(cve)
            data.update(row.to_dict())
            enriched.append(data)

        prioritizer = VulnerabilityPrioritizer()
        result_df = prioritizer.prioritize(enriched)
        result_df.to_csv(args.output, index=False)
        print(f"\n[+] Prioritized results saved to: {args.output}")

        print("\n=== Priority Summary ===")
        print(result_df["priority_level"].value_counts().to_string())

    elif args.command == "enrich":
        df = pd.read_csv(args.csv)
        enricher = VulnerabilityEnricher()

        enriched = []
        for _, row in df.iterrows():
            cve = row.get("cve_id", "")
            if cve:
                print(f"[*] Enriching {cve}...")
                data = enricher.enrich_cve(cve)
                data.update(row.to_dict())
                enriched.append(data)

        result_df = pd.DataFrame(enriched)
        output = args.output or args.csv.replace(".csv", "_enriched.csv")
        result_df.to_csv(output, index=False)
        print(f"[+] Enriched data saved to: {output}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
