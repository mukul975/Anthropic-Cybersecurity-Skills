#!/usr/bin/env python3
"""Agent for web application vulnerability triage.

Ingests scan results from multiple scanners (Nikto, ZAP, Burp),
deduplicates findings, prioritizes by CVSS and exploitability,
assigns SLA deadlines, and generates a triage report.
"""

import json
import sys
from datetime import datetime, timedelta
from collections import defaultdict


SLA_DAYS = {"Critical": 7, "High": 30, "Medium": 90, "Low": 180, "Info": 365}

CVSS_SEVERITY = {
    (9.0, 10.0): "Critical", (7.0, 8.9): "High",
    (4.0, 6.9): "Medium", (0.1, 3.9): "Low", (0.0, 0.0): "Info",
}


class VulnTriageAgent:
    """Triages web application vulnerability scan results."""

    def __init__(self):
        self.findings = []
        self.triaged = []

    def ingest_json_report(self, filepath, scanner_name="unknown"):
        """Load findings from a JSON scan report."""
        with open(filepath) as f:
            data = json.load(f)
        items = data if isinstance(data, list) else data.get("findings", data.get("alerts", []))
        for item in items:
            self.findings.append({
                "title": item.get("title", item.get("name", item.get("description", "")[:80])),
                "severity": item.get("severity", item.get("risk", "Medium")),
                "cvss": item.get("cvss", item.get("cvss_score", 0)),
                "url": item.get("url", item.get("uri", "")),
                "parameter": item.get("parameter", item.get("param", "")),
                "description": item.get("description", "")[:500],
                "cwe": item.get("cwe", item.get("cweid", "")),
                "scanner": scanner_name,
            })
        return len(items)

    def deduplicate(self):
        """Remove duplicate findings based on title + URL + parameter."""
        seen = set()
        unique = []
        for f in self.findings:
            key = (f["title"].lower(), f["url"], f["parameter"])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self.findings = unique
        return len(unique)

    def classify_severity(self, cvss_score):
        for (low, high), severity in CVSS_SEVERITY.items():
            if low <= cvss_score <= high:
                return severity
        return "Medium"

    def prioritize(self):
        """Score and prioritize findings for remediation."""
        now = datetime.utcnow()
        for f in self.findings:
            severity = f.get("severity", "Medium")
            if severity not in SLA_DAYS:
                severity = self.classify_severity(float(f.get("cvss", 0)))
                f["severity"] = severity

            sla_days = SLA_DAYS.get(severity, 90)
            f["sla_deadline"] = (now + timedelta(days=sla_days)).isoformat()
            f["sla_days"] = sla_days

            priority_score = float(f.get("cvss", 0)) * 10
            if f.get("parameter"):
                priority_score += 5
            if "injection" in f.get("title", "").lower():
                priority_score += 10
            if "authentication" in f.get("title", "").lower():
                priority_score += 8
            f["priority_score"] = round(priority_score, 1)

        self.triaged = sorted(self.findings, key=lambda x: x["priority_score"], reverse=True)
        return self.triaged

    def generate_report(self):
        self.deduplicate()
        self.prioritize()
        severity_dist = defaultdict(int)
        for f in self.triaged:
            severity_dist[f["severity"]] += 1

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "total_findings": len(self.triaged),
            "severity_distribution": dict(severity_dist),
            "top_priority": self.triaged[:20],
        }
        print(json.dumps(report, indent=2, default=str))
        return report


def main():
    agent = VulnTriageAgent()
    for filepath in sys.argv[1:]:
        agent.ingest_json_report(filepath, scanner_name=filepath)
    agent.generate_report()


if __name__ == "__main__":
    main()
