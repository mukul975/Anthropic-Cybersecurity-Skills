#!/usr/bin/env python3
"""
Endpoint Vulnerability Remediation Prioritizer

Parses vulnerability scan exports (Nessus CSV), enriches with EPSS scores,
cross-references CISA KEV catalog, and generates prioritized remediation plans.
"""

import json
import csv
import sys
import os
from datetime import datetime, timedelta
from collections import defaultdict
from urllib.request import urlopen
from urllib.error import URLError


CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"


def load_nessus_csv(csv_path: str) -> list:
    """Parse Nessus scan export CSV into vulnerability records."""
    vulns = []

    with open(csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cvss = 0.0
            try:
                cvss = float(row.get("CVSS v3.0 Base Score", "0") or
                             row.get("CVSS v2.0 Base Score", "0") or "0")
            except ValueError:
                pass

            cve_list = [c.strip() for c in row.get("CVE", "").split(",") if c.strip()]

            vuln = {
                "plugin_id": row.get("Plugin ID", ""),
                "plugin_name": row.get("Name", ""),
                "severity": row.get("Risk", "None"),
                "host": row.get("Host", ""),
                "protocol": row.get("Protocol", ""),
                "port": row.get("Port", ""),
                "cvss_score": cvss,
                "cves": cve_list,
                "solution": row.get("Solution", ""),
                "synopsis": row.get("Synopsis", ""),
                "description": row.get("Description", "")[:200],
            }
            vulns.append(vuln)

    return vulns


def fetch_cisa_kev() -> set:
    """Fetch CISA Known Exploited Vulnerabilities catalog."""
    try:
        with urlopen(CISA_KEV_URL, timeout=15) as resp:
            data = json.loads(resp.read())
            return {v["cveID"] for v in data.get("vulnerabilities", [])}
    except (URLError, json.JSONDecodeError, KeyError) as e:
        print(f"Warning: Could not fetch CISA KEV catalog: {e}")
        return set()


def fetch_epss_scores(cves: list) -> dict:
    """Fetch EPSS scores for a list of CVEs."""
    epss_scores = {}
    batch_size = 100

    for i in range(0, len(cves), batch_size):
        batch = cves[i:i + batch_size]
        cve_param = ",".join(batch)
        url = f"{EPSS_API_URL}?cve={cve_param}"
        try:
            with urlopen(url, timeout=15) as resp:
                data = json.loads(resp.read())
                for item in data.get("data", []):
                    epss_scores[item["cve"]] = float(item.get("epss", 0))
        except (URLError, json.JSONDecodeError) as e:
            print(f"Warning: EPSS lookup failed for batch: {e}")

    return epss_scores


def prioritize_vulnerabilities(vulns: list, kev_cves: set, epss_scores: dict) -> list:
    """Assign remediation priority based on risk scoring."""
    for vuln in vulns:
        cvss = vuln["cvss_score"]
        cves = vuln["cves"]

        in_kev = any(cve in kev_cves for cve in cves)
        max_epss = max((epss_scores.get(cve, 0) for cve in cves), default=0)

        vuln["in_cisa_kev"] = in_kev
        vuln["epss_score"] = round(max_epss, 4)

        if cvss >= 9.0 or in_kev or (cvss >= 7.0 and max_epss > 0.7):
            vuln["priority"] = "P1"
            vuln["sla_days"] = 14
        elif cvss >= 7.0 and max_epss > 0.5:
            vuln["priority"] = "P2"
            vuln["sla_days"] = 30
        elif cvss >= 4.0:
            vuln["priority"] = "P3"
            vuln["sla_days"] = 60
        else:
            vuln["priority"] = "P4"
            vuln["sla_days"] = 90

        vuln["sla_deadline"] = (
            datetime.utcnow() + timedelta(days=vuln["sla_days"])
        ).strftime("%Y-%m-%d")

    vulns.sort(key=lambda v: (
        {"P1": 0, "P2": 1, "P3": 2, "P4": 3}.get(v["priority"], 4),
        -v["cvss_score"],
        -v["epss_score"],
    ))

    return vulns


def generate_remediation_plan(vulns: list, output_path: str) -> None:
    """Generate prioritized remediation plan in JSON."""
    summary = defaultdict(int)
    hosts_affected = defaultdict(set)

    for vuln in vulns:
        summary[vuln["priority"]] += 1
        hosts_affected[vuln["priority"]].add(vuln["host"])

    plan = {
        "report_generated": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total_vulnerabilities": len(vulns),
            "by_priority": dict(summary),
            "unique_hosts": {p: len(h) for p, h in hosts_affected.items()},
        },
        "kev_vulnerabilities": [v for v in vulns if v.get("in_cisa_kev")],
        "remediation_queue": [
            {
                "priority": v["priority"],
                "sla_deadline": v["sla_deadline"],
                "host": v["host"],
                "plugin_name": v["plugin_name"],
                "cvss": v["cvss_score"],
                "epss": v["epss_score"],
                "cisa_kev": v["in_cisa_kev"],
                "cves": v["cves"],
                "solution": v["solution"],
            }
            for v in vulns
        ],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(plan, f, indent=2)


def export_remediation_csv(vulns: list, output_path: str) -> None:
    """Export remediation plan to CSV for team assignment."""
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Priority", "SLA Deadline", "Host", "Vulnerability",
            "CVSS", "EPSS", "CISA KEV", "CVEs", "Solution",
            "Status", "Assigned To", "Notes",
        ])
        for v in vulns:
            writer.writerow([
                v["priority"], v["sla_deadline"], v["host"],
                v["plugin_name"], v["cvss_score"], v["epss_score"],
                v["in_cisa_kev"], "; ".join(v["cves"]),
                v["solution"][:200], "Open", "", "",
            ])


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python process.py <nessus_export.csv>")
        print()
        print("Parses Nessus CSV export, enriches with EPSS/CISA KEV data,")
        print("and generates a prioritized remediation plan.")
        sys.exit(1)

    csv_path = sys.argv[1]
    if not os.path.exists(csv_path):
        print(f"Error: File not found: {csv_path}")
        sys.exit(1)

    print("Parsing vulnerability scan results...")
    vulns = load_nessus_csv(csv_path)
    print(f"Loaded {len(vulns)} vulnerability findings")

    all_cves = list({cve for v in vulns for cve in v["cves"]})
    print(f"Unique CVEs: {len(all_cves)}")

    print("Fetching CISA KEV catalog...")
    kev_cves = fetch_cisa_kev()
    print(f"KEV catalog contains {len(kev_cves)} CVEs")

    print("Fetching EPSS scores...")
    epss_scores = fetch_epss_scores(all_cves) if all_cves else {}
    print(f"Retrieved EPSS scores for {len(epss_scores)} CVEs")

    print("Prioritizing vulnerabilities...")
    vulns = prioritize_vulnerabilities(vulns, kev_cves, epss_scores)

    base = os.path.splitext(os.path.basename(csv_path))[0]
    out_dir = os.path.dirname(csv_path) or "."

    plan_path = os.path.join(out_dir, f"{base}_remediation_plan.json")
    generate_remediation_plan(vulns, plan_path)
    print(f"Remediation plan: {plan_path}")

    csv_out = os.path.join(out_dir, f"{base}_remediation.csv")
    export_remediation_csv(vulns, csv_out)
    print(f"Remediation CSV: {csv_out}")

    print(f"\n--- Remediation Summary ---")
    for p in ["P1", "P2", "P3", "P4"]:
        count = sum(1 for v in vulns if v["priority"] == p)
        if count:
            print(f"  {p}: {count} vulnerabilities")

    kev_count = sum(1 for v in vulns if v.get("in_cisa_kev"))
    if kev_count:
        print(f"\n  CISA KEV matches: {kev_count} (mandatory remediation)")
