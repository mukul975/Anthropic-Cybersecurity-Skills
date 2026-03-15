#!/usr/bin/env python3
"""Agent for prioritizing vulnerabilities with CVSS scoring.

Calculates CVSS v3.1 base scores from metric vectors, enriches
with EPSS exploit probability and KEV catalog data, and generates
a risk-prioritized remediation report.
"""

import json
import sys
import requests
from datetime import datetime
from collections import defaultdict

CVSS_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": {"U": 0.85, "C": 0.85}, "L": {"U": 0.62, "C": 0.68},
            "H": {"U": 0.27, "C": 0.50}},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": "unchanged", "C": "changed"},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


class CVSSPrioritizationAgent:
    """Calculates CVSS scores and prioritizes vulnerabilities."""

    def __init__(self):
        self.vulnerabilities = []

    def parse_vector(self, vector_string):
        """Parse CVSS v3.1 vector string into metric dict."""
        metrics = {}
        parts = vector_string.replace("CVSS:3.1/", "").split("/")
        for part in parts:
            key, val = part.split(":")
            metrics[key] = val
        return metrics

    def calculate_base_score(self, vector_string):
        """Calculate CVSS v3.1 base score from vector string."""
        m = self.parse_vector(vector_string)
        scope_changed = m.get("S") == "C"

        isc_base = 1 - (
            (1 - CVSS_WEIGHTS["C"][m["C"]]) *
            (1 - CVSS_WEIGHTS["I"][m["I"]]) *
            (1 - CVSS_WEIGHTS["A"][m["A"]])
        )

        if scope_changed:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
        else:
            impact = 6.42 * isc_base

        if impact <= 0:
            return 0.0

        scope_key = "C" if scope_changed else "U"
        pr_val = CVSS_WEIGHTS["PR"][m["PR"]][scope_key]
        exploitability = (8.22 * CVSS_WEIGHTS["AV"][m["AV"]] *
                          CVSS_WEIGHTS["AC"][m["AC"]] * pr_val *
                          CVSS_WEIGHTS["UI"][m["UI"]])

        if scope_changed:
            score = min(1.08 * (impact + exploitability), 10.0)
        else:
            score = min(impact + exploitability, 10.0)

        import math
        return math.ceil(score * 10) / 10

    def severity_rating(self, score):
        if score == 0.0:
            return "None"
        elif score <= 3.9:
            return "Low"
        elif score <= 6.9:
            return "Medium"
        elif score <= 8.9:
            return "High"
        return "Critical"

    def fetch_epss(self, cve_ids):
        """Fetch EPSS exploit probability scores from FIRST.org API."""
        scores = {}
        try:
            cves = ",".join(cve_ids[:100])
            resp = requests.get(
                f"https://api.first.org/data/v1/epss?cve={cves}", timeout=15)
            if resp.status_code == 200:
                for entry in resp.json().get("data", []):
                    scores[entry["cve"]] = {
                        "epss": float(entry.get("epss", 0)),
                        "percentile": float(entry.get("percentile", 0)),
                    }
        except requests.RequestException:
            pass
        return scores

    def fetch_kev(self):
        """Fetch CISA Known Exploited Vulnerabilities catalog."""
        try:
            resp = requests.get(
                "https://www.cisa.gov/sites/default/files/feeds/"
                "known_exploited_vulnerabilities.json", timeout=15)
            if resp.status_code == 200:
                return {v["cveID"] for v in
                        resp.json().get("vulnerabilities", [])}
        except requests.RequestException:
            pass
        return set()

    def add_vulnerability(self, cve_id, vector, description=""):
        score = self.calculate_base_score(vector)
        self.vulnerabilities.append({
            "cve_id": cve_id, "vector": vector, "cvss_score": score,
            "severity": self.severity_rating(score),
            "description": description,
        })

    def prioritize(self):
        """Enrich and prioritize all vulnerabilities."""
        cve_ids = [v["cve_id"] for v in self.vulnerabilities]
        epss_data = self.fetch_epss(cve_ids)
        kev_set = self.fetch_kev()

        for vuln in self.vulnerabilities:
            cve = vuln["cve_id"]
            epss = epss_data.get(cve, {})
            vuln["epss_score"] = epss.get("epss", 0)
            vuln["epss_percentile"] = epss.get("percentile", 0)
            vuln["in_kev"] = cve in kev_set

            priority = vuln["cvss_score"] * 10
            if vuln["in_kev"]:
                priority += 30
            if vuln["epss_score"] > 0.5:
                priority += 20
            elif vuln["epss_score"] > 0.1:
                priority += 10
            vuln["priority_score"] = round(priority, 1)

        self.vulnerabilities.sort(key=lambda v: v["priority_score"], reverse=True)
        return self.vulnerabilities

    def generate_report(self):
        self.prioritize()
        sev_dist = defaultdict(int)
        for v in self.vulnerabilities:
            sev_dist[v["severity"]] += 1

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "total_vulns": len(self.vulnerabilities),
            "severity_distribution": dict(sev_dist),
            "kev_count": sum(1 for v in self.vulnerabilities if v["in_kev"]),
            "prioritized_vulns": self.vulnerabilities,
        }
        print(json.dumps(report, indent=2))
        return report


def main():
    agent = CVSSPrioritizationAgent()
    agent.add_vulnerability("CVE-2024-3400", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    agent.add_vulnerability("CVE-2024-21887", "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H")
    agent.add_vulnerability("CVE-2023-44487", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
    agent.generate_report()


if __name__ == "__main__":
    main()
