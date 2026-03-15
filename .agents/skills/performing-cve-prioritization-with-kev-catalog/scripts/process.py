#!/usr/bin/env python3
"""
CISA KEV-Based CVE Prioritization Engine

Fetches the CISA Known Exploited Vulnerabilities catalog,
enriches with EPSS scores, and prioritizes against scan results.

Requirements:
    pip install requests pandas

Usage:
    python process.py fetch                              # Download KEV catalog
    python process.py check --cve CVE-2024-3094          # Check single CVE
    python process.py prioritize --csv vulns.csv --output prioritized.csv
    python process.py stats                              # KEV catalog statistics
"""

import argparse
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import requests


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_CACHE = "kev_catalog.json"


class KEVPrioritizer:
    """CISA KEV-based vulnerability prioritization engine."""

    def __init__(self):
        self.kev_catalog = {}
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "KEV-Prioritizer/1.0"})

    def fetch_kev(self, cache_file=KEV_CACHE):
        """Download and cache the KEV catalog."""
        print("[*] Fetching CISA KEV catalog...")
        response = self.session.get(KEV_URL, timeout=30)
        response.raise_for_status()
        data = response.json()

        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln["cveID"]
            self.kev_catalog[cve_id] = {
                "vendor": vuln.get("vendorProject", ""),
                "product": vuln.get("product", ""),
                "name": vuln.get("vulnerabilityName", ""),
                "date_added": vuln.get("dateAdded", ""),
                "description": vuln.get("shortDescription", ""),
                "action": vuln.get("requiredAction", ""),
                "due_date": vuln.get("dueDate", ""),
                "ransomware_use": vuln.get("knownRansomwareCampaignUse", "Unknown"),
            }

        with open(cache_file, "w") as f:
            json.dump(data, f)

        print(f"[+] Loaded {len(self.kev_catalog)} CVEs from KEV catalog")
        print(f"    Version: {data.get('catalogVersion', 'N/A')}")
        print(f"    Released: {data.get('dateReleased', 'N/A')}")
        return self.kev_catalog

    def load_cached_kev(self, cache_file=KEV_CACHE):
        """Load KEV catalog from local cache."""
        if not Path(cache_file).exists():
            return self.fetch_kev(cache_file)

        with open(cache_file) as f:
            data = json.load(f)

        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln["cveID"]
            self.kev_catalog[cve_id] = {
                "vendor": vuln.get("vendorProject", ""),
                "product": vuln.get("product", ""),
                "name": vuln.get("vulnerabilityName", ""),
                "date_added": vuln.get("dateAdded", ""),
                "description": vuln.get("shortDescription", ""),
                "action": vuln.get("requiredAction", ""),
                "due_date": vuln.get("dueDate", ""),
                "ransomware_use": vuln.get("knownRansomwareCampaignUse", "Unknown"),
            }
        print(f"[+] Loaded {len(self.kev_catalog)} CVEs from cache")
        return self.kev_catalog

    def get_epss_batch(self, cve_list):
        """Fetch EPSS scores for a batch of CVEs."""
        scores = {}
        batch_size = 100
        for i in range(0, len(cve_list), batch_size):
            batch = cve_list[i:i + batch_size]
            try:
                response = self.session.get(
                    EPSS_API, params={"cve": ",".join(batch)}, timeout=30
                )
                if response.status_code == 200:
                    for entry in response.json().get("data", []):
                        scores[entry["cve"]] = {
                            "epss": float(entry.get("epss", 0)),
                            "percentile": float(entry.get("percentile", 0)),
                        }
            except Exception as e:
                print(f"  [!] EPSS batch error: {e}")
        return scores

    def prioritize(self, vulnerabilities):
        """Prioritize vulnerabilities using KEV + EPSS + CVSS."""
        cve_list = [v.get("cve_id", "") for v in vulnerabilities if v.get("cve_id")]
        epss_scores = self.get_epss_batch(cve_list)

        results = []
        for vuln in vulnerabilities:
            cve_id = vuln.get("cve_id", "")
            cvss = float(vuln.get("cvss_score", 0))
            asset_crit = float(vuln.get("asset_criticality", 3))
            exposure = float(vuln.get("network_exposure", 3))

            in_kev = cve_id in self.kev_catalog
            kev_data = self.kev_catalog.get(cve_id, {})
            epss = epss_scores.get(cve_id, {"epss": 0, "percentile": 0})

            risk_score = (
                (1.0 if in_kev else 0.0) * 10 * 0.30 +
                epss["epss"] * 10 * 0.25 +
                cvss * 0.20 +
                (asset_crit / 5.0) * 10 * 0.15 +
                (exposure / 5.0) * 10 * 0.10
            )

            if in_kev or (epss["epss"] > 0.5 and cvss >= 9.0):
                priority, sla = "P1-Emergency", 2
            elif epss["epss"] > 0.5 or cvss >= 9.0:
                priority, sla = "P2-Critical", 7
            elif cvss >= 7.0:
                priority, sla = "P3-High", 14
            elif cvss >= 4.0:
                priority, sla = "P4-Medium", 30
            else:
                priority, sla = "P5-Low", 90

            results.append({
                **vuln,
                "in_cisa_kev": in_kev,
                "ransomware_use": kev_data.get("ransomware_use", "N/A"),
                "kev_due_date": kev_data.get("due_date", "N/A"),
                "epss_score": round(epss["epss"], 4),
                "epss_percentile": round(epss["percentile"], 4),
                "risk_score": round(risk_score, 2),
                "priority": priority,
                "sla_days": sla,
            })

        df = pd.DataFrame(results)
        return df.sort_values("risk_score", ascending=False)

    def check_cve(self, cve_id):
        """Check a single CVE against KEV and EPSS."""
        in_kev = cve_id in self.kev_catalog
        kev_data = self.kev_catalog.get(cve_id, {})
        epss = self.get_epss_batch([cve_id]).get(cve_id, {"epss": 0, "percentile": 0})

        print(f"\n{'=' * 60}")
        print(f"CVE:              {cve_id}")
        print(f"In CISA KEV:      {'YES' if in_kev else 'No'}")
        if in_kev:
            print(f"  Vendor:         {kev_data.get('vendor', 'N/A')}")
            print(f"  Product:        {kev_data.get('product', 'N/A')}")
            print(f"  Date Added:     {kev_data.get('date_added', 'N/A')}")
            print(f"  Due Date:       {kev_data.get('due_date', 'N/A')}")
            print(f"  Ransomware Use: {kev_data.get('ransomware_use', 'N/A')}")
            print(f"  Action:         {kev_data.get('action', 'N/A')}")
        print(f"EPSS Score:       {epss['epss']:.4f} ({epss['percentile'] * 100:.1f}th pct)")

    def catalog_stats(self):
        """Print KEV catalog statistics."""
        if not self.kev_catalog:
            print("[!] KEV catalog not loaded.")
            return

        df = pd.DataFrame(self.kev_catalog.values())

        print(f"\n{'=' * 60}")
        print(f"CISA KEV CATALOG STATISTICS")
        print(f"{'=' * 60}")
        print(f"Total CVEs: {len(self.kev_catalog)}")

        ransomware = df[df["ransomware_use"] == "Known"]
        print(f"Ransomware-associated: {len(ransomware)}")

        print(f"\nTop 10 Vendors:")
        print(df["vendor"].value_counts().head(10).to_string())

        df["date_added"] = pd.to_datetime(df["date_added"], errors="coerce")
        df["year_added"] = df["date_added"].dt.year
        print(f"\nAdditions by Year:")
        print(df["year_added"].value_counts().sort_index().to_string())


def main():
    parser = argparse.ArgumentParser(description="CISA KEV CVE Prioritization Engine")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("fetch", help="Download/update KEV catalog")
    subparsers.add_parser("stats", help="Show KEV catalog statistics")

    check_p = subparsers.add_parser("check", help="Check a single CVE")
    check_p.add_argument("--cve", required=True, help="CVE ID to check")

    pri_p = subparsers.add_parser("prioritize", help="Prioritize vulns from CSV")
    pri_p.add_argument("--csv", required=True, help="Input CSV (needs cve_id column)")
    pri_p.add_argument("--output", default="kev_prioritized.csv", help="Output CSV")

    args = parser.parse_args()
    engine = KEVPrioritizer()

    if args.command == "fetch":
        engine.fetch_kev()
    elif args.command == "stats":
        engine.load_cached_kev()
        engine.catalog_stats()
    elif args.command == "check":
        engine.load_cached_kev()
        engine.check_cve(args.cve)
    elif args.command == "prioritize":
        engine.load_cached_kev()
        df = pd.read_csv(args.csv)
        vulns = df.to_dict("records")
        result = engine.prioritize(vulns)
        result.to_csv(args.output, index=False)
        print(f"\n[+] Prioritized {len(result)} vulnerabilities to {args.output}")
        print(f"\nPriority Distribution:")
        print(result["priority"].value_counts().to_string())
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
