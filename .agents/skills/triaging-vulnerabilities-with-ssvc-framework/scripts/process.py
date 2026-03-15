#!/usr/bin/env python3
"""SSVC Vulnerability Triage Processor.

Evaluates vulnerabilities against CISA's Stakeholder-Specific Vulnerability
Categorization (SSVC) decision tree and produces prioritized triage reports.
"""

import argparse
import csv
import json
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SSVC_SLA = {
    "Act": 2,
    "Attend": 14,
    "Track*": 60,
    "Track": 90,
}


def fetch_kev_catalog():
    """Download the CISA Known Exploited Vulnerabilities catalog."""
    resp = requests.get(KEV_URL, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return {v["cveID"] for v in data.get("vulnerabilities", [])}


def fetch_epss_scores(cve_ids):
    """Fetch EPSS scores for a list of CVE IDs from FIRST API."""
    scores = {}
    batch_size = 100
    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i : i + batch_size]
        params = {"cve": ",".join(batch)}
        resp = requests.get(EPSS_API, params=params, timeout=30)
        if resp.status_code == 200:
            for entry in resp.json().get("data", []):
                scores[entry["cve"]] = {
                    "epss": float(entry.get("epss", 0)),
                    "percentile": float(entry.get("percentile", 0)),
                }
        time.sleep(1)
    return scores


def fetch_nvd_cve(cve_id, api_key=None):
    """Fetch CVE details from NVD API v2."""
    params = {"cveId": cve_id}
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    resp = requests.get(NVD_API, params=params, headers=headers, timeout=30)
    if resp.status_code == 200:
        vulns = resp.json().get("vulnerabilities", [])
        if vulns:
            return vulns[0].get("cve", {})
    return None


def evaluate_exploitation(cve_id, kev_set, epss_scores):
    """Determine exploitation status: active, poc, or none."""
    if cve_id in kev_set:
        return "active"
    epss_data = epss_scores.get(cve_id, {})
    if epss_data.get("epss", 0) > 0.5:
        return "poc"
    if epss_data.get("epss", 0) > 0.1:
        return "poc"
    return "none"


def evaluate_technical_impact(cvss_vector):
    """Assess technical impact from CVSS vector string."""
    if not cvss_vector:
        return "partial"
    vector_upper = cvss_vector.upper()
    if "S:C" in vector_upper:
        return "total"
    if "C:H" in vector_upper and "I:H" in vector_upper and "A:H" in vector_upper:
        return "total"
    if "C:H" in vector_upper and "I:H" in vector_upper:
        return "total"
    return "partial"


def evaluate_automatability(cvss_vector):
    """Determine if exploitation can be automated."""
    if not cvss_vector:
        return "no"
    vector_upper = cvss_vector.upper()
    network = "AV:N" in vector_upper
    low_complexity = "AC:L" in vector_upper
    no_user_interaction = "UI:N" in vector_upper
    if network and low_complexity and no_user_interaction:
        return "yes"
    return "no"


def ssvc_decision(exploitation, tech_impact, automatability, mission_prevalence, public_wellbeing):
    """Apply CISA SSVC decision tree to produce triage outcome.

    Returns one of: Act, Attend, Track*, Track
    """
    if exploitation == "active":
        if automatability == "yes":
            return "Act"
        if tech_impact == "total":
            if mission_prevalence in ("essential", "support"):
                return "Act"
            return "Attend"
        if mission_prevalence == "essential":
            return "Attend"
        if public_wellbeing in ("irreversible", "material"):
            return "Attend"
        return "Attend"

    if exploitation == "poc":
        if automatability == "yes" and tech_impact == "total":
            if mission_prevalence in ("essential", "support"):
                return "Attend"
            return "Track*"
        if tech_impact == "total" and mission_prevalence == "essential":
            return "Attend"
        if public_wellbeing == "irreversible":
            return "Attend"
        return "Track*"

    # exploitation == "none"
    if tech_impact == "total" and mission_prevalence == "essential":
        return "Track*"
    if automatability == "yes" and mission_prevalence == "essential":
        return "Track*"
    return "Track"


def parse_nessus_csv(filepath):
    """Parse Nessus CSV export into vulnerability records."""
    vulns = []
    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve = row.get("CVE", "").strip()
            if not cve or not cve.startswith("CVE-"):
                continue
            vulns.append(
                {
                    "cve_id": cve,
                    "host": row.get("Host", "unknown"),
                    "port": row.get("Port", ""),
                    "plugin_name": row.get("Name", ""),
                    "severity": row.get("Severity", ""),
                    "cvss_vector": row.get("CVSS V3 Vector", ""),
                    "description": row.get("Synopsis", ""),
                }
            )
    return vulns


def parse_openvas_xml(filepath):
    """Parse OpenVAS XML report into vulnerability records."""
    vulns = []
    tree = ET.parse(filepath)
    root = tree.getroot()
    for result in root.iter("result"):
        nvt = result.find("nvt")
        if nvt is None:
            continue
        cve_elem = nvt.find("cve")
        if cve_elem is None or not cve_elem.text or cve_elem.text == "NOCVE":
            continue
        host_elem = result.find("host")
        port_elem = result.find("port")
        vulns.append(
            {
                "cve_id": cve_elem.text.strip(),
                "host": host_elem.text.strip() if host_elem is not None else "unknown",
                "port": port_elem.text.strip() if port_elem is not None else "",
                "plugin_name": nvt.findtext("name", ""),
                "severity": result.findtext("severity", ""),
                "cvss_vector": nvt.findtext("tags", ""),
                "description": result.findtext("description", ""),
            }
        )
    return vulns


def parse_generic_csv(filepath):
    """Parse generic CSV with cve_id, host, cvss_vector columns."""
    vulns = []
    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve = row.get("cve_id", "").strip()
            if not cve:
                continue
            vulns.append(
                {
                    "cve_id": cve,
                    "host": row.get("host", "unknown"),
                    "port": row.get("port", ""),
                    "plugin_name": row.get("plugin_name", ""),
                    "severity": row.get("severity", ""),
                    "cvss_vector": row.get("cvss_vector", ""),
                    "description": row.get("description", ""),
                    "mission_prevalence": row.get("mission_prevalence", "support"),
                    "public_wellbeing": row.get("public_wellbeing", "minimal"),
                }
            )
    return vulns


def run_triage(vulns, kev_set, epss_scores, default_mission="support", default_wellbeing="minimal"):
    """Run SSVC triage on a list of vulnerability records."""
    results = []
    for vuln in vulns:
        cve_id = vuln["cve_id"]
        exploitation = evaluate_exploitation(cve_id, kev_set, epss_scores)
        tech_impact = evaluate_technical_impact(vuln.get("cvss_vector", ""))
        automatability = evaluate_automatability(vuln.get("cvss_vector", ""))
        mission = vuln.get("mission_prevalence", default_mission)
        wellbeing = vuln.get("public_wellbeing", default_wellbeing)

        outcome = ssvc_decision(exploitation, tech_impact, automatability, mission, wellbeing)
        epss_data = epss_scores.get(cve_id, {})

        results.append(
            {
                "cve_id": cve_id,
                "host": vuln.get("host", "unknown"),
                "port": vuln.get("port", ""),
                "plugin_name": vuln.get("plugin_name", ""),
                "ssvc_outcome": outcome,
                "sla_days": SSVC_SLA[outcome],
                "exploitation_status": exploitation,
                "technical_impact": tech_impact,
                "automatability": automatability,
                "mission_prevalence": mission,
                "public_wellbeing": wellbeing,
                "epss_score": epss_data.get("epss", 0),
                "epss_percentile": epss_data.get("percentile", 0),
                "in_kev": cve_id in kev_set,
            }
        )

    outcome_order = {"Act": 0, "Attend": 1, "Track*": 2, "Track": 3}
    results.sort(key=lambda r: (outcome_order.get(r["ssvc_outcome"], 4), -r["epss_score"]))
    return results


def generate_report(results, output_path, report_format="json"):
    """Generate triage report in JSON or CSV format."""
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_vulnerabilities": len(results),
        "outcome_counts": {},
        "results": results,
    }
    for r in results:
        outcome = r["ssvc_outcome"]
        summary["outcome_counts"][outcome] = summary["outcome_counts"].get(outcome, 0) + 1

    if report_format == "csv":
        if results:
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=results[0].keys())
                writer.writeheader()
                writer.writerows(results)
    else:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

    return summary


def main():
    parser = argparse.ArgumentParser(description="SSVC Vulnerability Triage Processor")
    parser.add_argument("--input", required=True, help="Path to vulnerability scan results")
    parser.add_argument("--output", default="ssvc_triage_report.json", help="Output report path")
    parser.add_argument(
        "--format",
        choices=["nessus", "openvas", "generic"],
        default="generic",
        help="Input format",
    )
    parser.add_argument(
        "--output-format", choices=["json", "csv"], default="json", help="Output format"
    )
    parser.add_argument("--nvd-api-key", help="NVD API key for higher rate limits")
    parser.add_argument(
        "--mission-prevalence",
        choices=["minimal", "support", "essential"],
        default="support",
        help="Default mission prevalence",
    )
    parser.add_argument(
        "--public-wellbeing",
        choices=["minimal", "material", "irreversible"],
        default="minimal",
        help="Default public well-being impact",
    )
    args = parser.parse_args()

    print("[*] Fetching CISA KEV catalog...")
    kev_set = fetch_kev_catalog()
    print(f"    Loaded {len(kev_set)} known exploited vulnerabilities")

    print(f"[*] Parsing input file: {args.input}")
    if args.format == "nessus":
        vulns = parse_nessus_csv(args.input)
    elif args.format == "openvas":
        vulns = parse_openvas_xml(args.input)
    else:
        vulns = parse_generic_csv(args.input)
    print(f"    Found {len(vulns)} vulnerability records")

    cve_ids = list({v["cve_id"] for v in vulns})
    print(f"[*] Fetching EPSS scores for {len(cve_ids)} unique CVEs...")
    epss_scores = fetch_epss_scores(cve_ids)

    print("[*] Running SSVC triage...")
    results = run_triage(
        vulns, kev_set, epss_scores, args.mission_prevalence, args.public_wellbeing
    )

    print(f"[*] Generating report: {args.output}")
    summary = generate_report(results, args.output, args.output_format)

    print("\n[+] SSVC Triage Summary:")
    for outcome, count in sorted(summary["outcome_counts"].items()):
        print(f"    {outcome}: {count}")
    print(f"    Total: {summary['total_vulnerabilities']}")


if __name__ == "__main__":
    main()
