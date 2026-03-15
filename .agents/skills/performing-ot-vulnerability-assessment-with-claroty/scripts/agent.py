#!/usr/bin/env python3
"""Agent for performing OT vulnerability assessment with Claroty xDome platform."""

import json
import argparse
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None


class ClarotyVulnClient:
    """Client for Claroty xDome Vulnerability Assessment API."""

    def __init__(self, base_url, token):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {token}", "Content-Type": "application/json"})

    def get_vulnerabilities(self, severity=None, asset_type=None, limit=100):
        params = {"limit": limit}
        if severity:
            params["severity"] = severity
        if asset_type:
            params["asset_type"] = asset_type
        resp = self.session.get(f"{self.base_url}/api/v1/vulnerabilities", params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def get_vulnerability_detail(self, vuln_id):
        resp = self.session.get(f"{self.base_url}/api/v1/vulnerabilities/{vuln_id}", timeout=30)
        resp.raise_for_status()
        return resp.json()

    def get_affected_assets(self, cve_id):
        resp = self.session.get(f"{self.base_url}/api/v1/vulnerabilities/cve/{cve_id}/assets", timeout=30)
        resp.raise_for_status()
        return resp.json()

    def get_risk_score(self):
        resp = self.session.get(f"{self.base_url}/api/v1/risk/score", timeout=30)
        resp.raise_for_status()
        return resp.json()


def assess_vulnerabilities(base_url, token, severity=None, limit=100):
    """Retrieve and analyze OT vulnerabilities."""
    client = ClarotyVulnClient(base_url, token)
    data = client.get_vulnerabilities(severity, limit=limit)
    vulns = data.get("vulnerabilities", data.get("results", []))
    by_severity = {}
    by_asset_type = {}
    for v in vulns:
        s = v.get("severity", "unknown")
        by_severity[s] = by_severity.get(s, 0) + 1
        at = v.get("asset_type", "unknown")
        by_asset_type[at] = by_asset_type.get(at, 0) + 1
    critical = [v for v in vulns if v.get("severity", "").lower() == "critical"]
    return {
        "total_vulnerabilities": len(vulns),
        "by_severity": by_severity,
        "by_asset_type": by_asset_type,
        "critical_vulns": [{"cve": v.get("cve_id"), "asset": v.get("asset_name"),
                            "cvss": v.get("cvss_score"), "description": v.get("description", "")[:150]}
                           for v in critical[:20]],
        "timestamp": datetime.utcnow().isoformat(),
    }


def prioritize_remediation(base_url, token, limit=50):
    """Prioritize OT vulnerabilities for remediation based on risk."""
    client = ClarotyVulnClient(base_url, token)
    data = client.get_vulnerabilities(limit=limit)
    vulns = data.get("vulnerabilities", data.get("results", []))
    scored = []
    for v in vulns:
        cvss = float(v.get("cvss_score", 0))
        criticality_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        asset_crit = criticality_map.get(v.get("asset_criticality", "").lower(), 1)
        exploitable = 1.5 if v.get("exploitable", False) else 1.0
        risk = round(cvss * asset_crit * exploitable / 10, 1)
        scored.append({**v, "risk_score": risk,
                       "priority": "CRITICAL" if risk >= 4 else "HIGH" if risk >= 2.5 else "MEDIUM" if risk >= 1.5 else "LOW"})
    scored.sort(key=lambda x: x["risk_score"], reverse=True)
    return {
        "total_assessed": len(scored),
        "remediation_queue": [{"cve": v.get("cve_id"), "asset": v.get("asset_name"),
                                "risk_score": v["risk_score"], "priority": v["priority"],
                                "cvss": v.get("cvss_score")} for v in scored[:30]],
    }


def get_risk_overview(base_url, token):
    """Get overall OT risk posture."""
    client = ClarotyVulnClient(base_url, token)
    risk = client.get_risk_score()
    vulns = assess_vulnerabilities(base_url, token)
    return {
        "risk_score": risk,
        "vulnerability_summary": vulns["by_severity"],
        "total_vulnerabilities": vulns["total_vulnerabilities"],
        "timestamp": datetime.utcnow().isoformat(),
    }


def main():
    if not requests:
        print(json.dumps({"error": "requests not installed"}))
        return
    parser = argparse.ArgumentParser(description="OT Vulnerability Assessment with Claroty Agent")
    parser.add_argument("--url", required=True, help="Claroty xDome base URL")
    parser.add_argument("--token", required=True, help="API token")
    sub = parser.add_subparsers(dest="command")
    v = sub.add_parser("vulns", help="List vulnerabilities")
    v.add_argument("--severity", help="Filter: critical, high, medium, low")
    v.add_argument("--limit", type=int, default=100)
    sub.add_parser("prioritize", help="Prioritize remediation")
    sub.add_parser("risk", help="Risk overview")
    args = parser.parse_args()
    if args.command == "vulns":
        result = assess_vulnerabilities(args.url, args.token, args.severity, args.limit)
    elif args.command == "prioritize":
        result = prioritize_remediation(args.url, args.token)
    elif args.command == "risk":
        result = get_risk_overview(args.url, args.token)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
