#!/usr/bin/env python3
"""Patch Tuesday Response Agent - Tracks Microsoft patches, assesses risk, and prioritizes deployment."""

import json
import logging
import argparse
from datetime import datetime

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MSRC_API_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0"


def fetch_patch_tuesday_updates(api_key, year_month):
    """Fetch Microsoft Security Update Guide data via MSRC API."""
    headers = {"api-key": api_key, "Accept": "application/json"}
    resp = requests.get(f"{MSRC_API_BASE}/Updates('{year_month}')", headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    logger.info("Fetched MSRC update for %s", year_month)
    return data


def parse_vulnerabilities(cvrf_data):
    """Parse CVRF data to extract vulnerability details."""
    vulns = []
    for vuln in cvrf_data.get("Vulnerability", []):
        cve_id = vuln.get("CVE", "")
        title = vuln.get("Title", {}).get("Value", "")
        severity = "unknown"
        cvss_score = 0.0
        exploited = False
        for threat in vuln.get("Threats", []):
            desc = threat.get("Description", {}).get("Value", "")
            if "Exploited:Yes" in desc:
                exploited = True
            if threat.get("Type") == 3:
                severity = desc
        for score_set in vuln.get("CVSSScoreSets", []):
            base = score_set.get("BaseScore", 0.0)
            if base > cvss_score:
                cvss_score = base
        affected_products = []
        for product_status in vuln.get("ProductStatuses", []):
            for pid in product_status.get("ProductID", []):
                affected_products.append(pid)
        vulns.append({
            "cve": cve_id, "title": title, "severity": severity,
            "cvss_score": cvss_score, "exploited_in_wild": exploited,
            "affected_product_ids": affected_products[:10],
        })
    logger.info("Parsed %d vulnerabilities", len(vulns))
    return vulns


def check_cisa_kev(cve_list):
    """Check CVEs against CISA Known Exploited Vulnerabilities catalog."""
    try:
        resp = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=15)
        resp.raise_for_status()
        kev_data = resp.json()
        kev_cves = {v["cveID"] for v in kev_data.get("vulnerabilities", [])}
        in_kev = [cve for cve in cve_list if cve in kev_cves]
        logger.info("Found %d CVEs in CISA KEV", len(in_kev))
        return in_kev
    except requests.RequestException as e:
        logger.warning("Failed to check CISA KEV: %s", e)
        return []


def prioritize_patches(vulns, kev_cves):
    """Prioritize patches based on CVSS, exploitation status, and CISA KEV."""
    for vuln in vulns:
        priority_score = 0
        if vuln["exploited_in_wild"]:
            priority_score += 40
        if vuln["cve"] in kev_cves:
            priority_score += 30
        if vuln["cvss_score"] >= 9.0:
            priority_score += 20
        elif vuln["cvss_score"] >= 7.0:
            priority_score += 10
        if vuln["severity"].lower() == "critical":
            priority_score += 10
        vuln["priority_score"] = priority_score
        if priority_score >= 60:
            vuln["deployment_urgency"] = "emergency"
            vuln["sla_hours"] = 24
        elif priority_score >= 40:
            vuln["deployment_urgency"] = "critical"
            vuln["sla_hours"] = 72
        elif priority_score >= 20:
            vuln["deployment_urgency"] = "standard"
            vuln["sla_hours"] = 168
        else:
            vuln["deployment_urgency"] = "routine"
            vuln["sla_hours"] = 720
    return sorted(vulns, key=lambda v: v["priority_score"], reverse=True)


def generate_deployment_plan(prioritized_vulns):
    """Generate phased deployment plan."""
    phases = {"emergency_24h": [], "critical_72h": [], "standard_7d": [], "routine_30d": []}
    for vuln in prioritized_vulns:
        urgency = vuln.get("deployment_urgency", "routine")
        entry = {"cve": vuln["cve"], "title": vuln["title"], "cvss": vuln["cvss_score"],
                 "exploited": vuln["exploited_in_wild"]}
        if urgency == "emergency":
            phases["emergency_24h"].append(entry)
        elif urgency == "critical":
            phases["critical_72h"].append(entry)
        elif urgency == "standard":
            phases["standard_7d"].append(entry)
        else:
            phases["routine_30d"].append(entry)
    return phases


def generate_report(vulns, kev_cves, deployment_plan, year_month):
    """Generate Patch Tuesday response report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "patch_tuesday": year_month,
        "total_vulnerabilities": len(vulns),
        "actively_exploited": sum(1 for v in vulns if v.get("exploited_in_wild")),
        "in_cisa_kev": len(kev_cves),
        "critical_cvss": sum(1 for v in vulns if v.get("cvss_score", 0) >= 9.0),
        "deployment_plan": deployment_plan,
        "top_10_priority": [{"cve": v["cve"], "title": v["title"], "cvss": v["cvss_score"],
                             "exploited": v["exploited_in_wild"], "priority": v["priority_score"]}
                            for v in vulns[:10]],
    }
    print(f"PATCH TUESDAY REPORT ({year_month}): {len(vulns)} vulns, "
          f"{report['actively_exploited']} exploited, {len(kev_cves)} in KEV")
    return report


def main():
    parser = argparse.ArgumentParser(description="Patch Tuesday Response Process Agent")
    parser.add_argument("--api-key", required=True, help="MSRC API key")
    parser.add_argument("--month", required=True, help="Year-Month (e.g., 2024-Jan)")
    parser.add_argument("--output", default="patch_tuesday_report.json")
    args = parser.parse_args()

    cvrf_data = fetch_patch_tuesday_updates(args.api_key, args.month)
    vulns = parse_vulnerabilities(cvrf_data)
    cve_list = [v["cve"] for v in vulns]
    kev_cves = check_cisa_kev(cve_list)
    prioritized = prioritize_patches(vulns, set(kev_cves))
    deployment_plan = generate_deployment_plan(prioritized)
    report = generate_report(prioritized, kev_cves, deployment_plan, args.month)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
