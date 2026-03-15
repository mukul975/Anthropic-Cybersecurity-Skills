#!/usr/bin/env python3
"""Azure AD Conditional Access policy audit agent using Microsoft Graph API."""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List

try:
    import requests
except ImportError:
    sys.exit("requests required: pip install requests")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


class ConditionalAccessClient:
    """Client for Microsoft Graph Conditional Access API."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.token = self._auth(tenant_id, client_id, client_secret)
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def _auth(self, tenant_id, client_id, client_secret) -> str:
        resp = requests.post(
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
            data={"grant_type": "client_credentials", "client_id": client_id,
                  "client_secret": client_secret,
                  "scope": "https://graph.microsoft.com/.default"}, timeout=15)
        resp.raise_for_status()
        return resp.json()["access_token"]

    def list_policies(self) -> List[dict]:
        """List all conditional access policies."""
        resp = requests.get(f"{GRAPH_BASE}/identity/conditionalAccess/policies",
                            headers=self.headers, timeout=30)
        resp.raise_for_status()
        return resp.json().get("value", [])

    def list_named_locations(self) -> List[dict]:
        """List named locations used in policies."""
        resp = requests.get(f"{GRAPH_BASE}/identity/conditionalAccess/namedLocations",
                            headers=self.headers, timeout=30)
        resp.raise_for_status()
        return resp.json().get("value", [])


def audit_policy(policy: dict) -> dict:
    """Audit a single conditional access policy for security gaps."""
    findings = []
    conditions = policy.get("conditions", {})
    grant = policy.get("grantControls", {})
    users = conditions.get("users", {})
    if "All" in users.get("includeUsers", []) and not users.get("excludeUsers"):
        pass
    if not grant.get("builtInControls"):
        findings.append("No grant controls configured")
    if "mfa" not in (grant.get("builtInControls") or []):
        findings.append("MFA not required")
    if policy.get("state") != "enabled":
        findings.append("Policy is not enabled")
    apps = conditions.get("applications", {})
    if "All" not in apps.get("includeApplications", []):
        findings.append("Policy does not cover all applications")
    return {
        "name": policy.get("displayName", ""),
        "state": policy.get("state", ""),
        "grant_controls": grant.get("builtInControls", []),
        "findings": findings,
        "risk_level": "HIGH" if len(findings) >= 2 else "MEDIUM" if findings else "LOW",
    }


def check_baseline_policies(policies: List[dict]) -> List[dict]:
    """Check for essential baseline conditional access policies."""
    baselines = [
        {"name": "Require MFA for admins", "check": lambda p: "mfa" in str(p.get("grantControls", {})).lower() and "admin" in str(p.get("conditions", {}).get("users", {})).lower()},
        {"name": "Block legacy authentication", "check": lambda p: "block" in str(p.get("grantControls", {})).lower()},
        {"name": "Require compliant devices", "check": lambda p: "compliantDevice" in str(p.get("grantControls", {}))},
    ]
    results = []
    for baseline in baselines:
        found = any(baseline["check"](p) for p in policies)
        results.append({"baseline": baseline["name"], "implemented": found,
                        "priority": "CRITICAL" if not found else "OK"})
    return results


def generate_report(client: ConditionalAccessClient) -> dict:
    """Generate conditional access audit report."""
    policies = client.list_policies()
    locations = client.list_named_locations()
    audited = [audit_policy(p) for p in policies]
    baselines = check_baseline_policies(policies)
    enabled = sum(1 for p in policies if p.get("state") == "enabled")
    report = {
        "analysis_date": datetime.utcnow().isoformat(),
        "total_policies": len(policies),
        "enabled_policies": enabled,
        "named_locations": len(locations),
        "policy_audits": audited,
        "baseline_checks": baselines,
        "summary": {
            "high_risk": sum(1 for a in audited if a["risk_level"] == "HIGH"),
            "missing_baselines": sum(1 for b in baselines if not b["implemented"]),
        },
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="Azure AD Conditional Access Audit Agent")
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--client-secret", required=True)
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--output", default="conditional_access_report.json")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    client = ConditionalAccessClient(args.tenant_id, args.client_id, args.client_secret)
    report = generate_report(client)
    out_path = os.path.join(args.output_dir, args.output)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Report saved to %s", out_path)
    print(json.dumps(report["summary"], indent=2))


if __name__ == "__main__":
    main()
