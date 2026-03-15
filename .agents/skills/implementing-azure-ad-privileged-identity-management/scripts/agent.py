#!/usr/bin/env python3
"""Azure AD Privileged Identity Management agent using Microsoft Graph API via requests."""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional

try:
    import requests
except ImportError:
    sys.exit("requests required: pip install requests")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


class PIMClient:
    """Client for Microsoft Entra PIM via Graph API."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.token = self._acquire_token(client_id, client_secret)
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {self.token}"})

    def _acquire_token(self, client_id: str, client_secret: str) -> str:
        resp = requests.post(
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://graph.microsoft.com/.default",
            }, timeout=15)
        resp.raise_for_status()
        return resp.json()["access_token"]

    def list_role_definitions(self) -> List[dict]:
        """List available directory role definitions."""
        resp = self.session.get(f"{GRAPH_BASE}/roleManagement/directory/roleDefinitions", timeout=30)
        resp.raise_for_status()
        return resp.json().get("value", [])

    def list_eligible_assignments(self) -> List[dict]:
        """List PIM eligible role assignments."""
        resp = self.session.get(
            f"{GRAPH_BASE}/roleManagement/directory/roleEligibilityScheduleInstances", timeout=30)
        resp.raise_for_status()
        return resp.json().get("value", [])

    def list_active_assignments(self) -> List[dict]:
        """List currently active (activated) role assignments."""
        resp = self.session.get(
            f"{GRAPH_BASE}/roleManagement/directory/roleAssignmentScheduleInstances", timeout=30)
        resp.raise_for_status()
        return resp.json().get("value", [])

    def list_role_settings(self) -> List[dict]:
        """List PIM role management policy assignments."""
        resp = self.session.get(
            f"{GRAPH_BASE}/policies/roleManagementPolicyAssignments?"
            "$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'", timeout=30)
        resp.raise_for_status()
        return resp.json().get("value", [])

    def get_activation_requests(self, top: int = 50) -> List[dict]:
        """List recent role activation requests."""
        resp = self.session.get(
            f"{GRAPH_BASE}/roleManagement/directory/roleEligibilityScheduleRequests?"
            f"$top={top}&$orderby=createdDateTime desc", timeout=30)
        resp.raise_for_status()
        return resp.json().get("value", [])


def audit_permanent_assignments(active: List[dict], eligible: List[dict]) -> List[dict]:
    """Identify permanent (non-PIM) role assignments that should be converted to eligible."""
    eligible_ids = {a.get("principalId") for a in eligible}
    permanent = []
    for a in active:
        if a.get("assignmentType") == "Assigned" and a.get("principalId") not in eligible_ids:
            permanent.append({
                "principal_id": a.get("principalId", ""),
                "role": a.get("roleDefinition", {}).get("displayName", ""),
                "start": a.get("startDateTime", ""),
                "recommendation": "Convert to eligible assignment with JIT activation",
            })
    return permanent


def compute_pim_coverage(active: List[dict], eligible: List[dict]) -> dict:
    """Calculate PIM coverage metrics."""
    total = len(active)
    eligible_count = len(eligible)
    pim_pct = (eligible_count / (total + eligible_count) * 100) if (total + eligible_count) else 0
    return {
        "active_assignments": total,
        "eligible_assignments": eligible_count,
        "pim_coverage_pct": round(pim_pct, 1),
    }


def generate_report(client: PIMClient) -> dict:
    """Generate PIM compliance report."""
    roles = client.list_role_definitions()
    eligible = client.list_eligible_assignments()
    active = client.list_active_assignments()
    permanent = audit_permanent_assignments(active, eligible)
    coverage = compute_pim_coverage(active, eligible)

    report = {
        "analysis_date": datetime.utcnow().isoformat(),
        "role_definitions": len(roles),
        "coverage": coverage,
        "permanent_assignments": permanent,
        "permanent_count": len(permanent),
        "recommendations": [],
    }
    if permanent:
        report["recommendations"].append(
            f"Convert {len(permanent)} permanent assignments to PIM-eligible")
    if coverage["pim_coverage_pct"] < 80:
        report["recommendations"].append("Increase PIM coverage above 80%")
    return report


def main():
    parser = argparse.ArgumentParser(description="Azure AD PIM Audit Agent")
    parser.add_argument("--tenant-id", required=True, help="Azure AD tenant ID")
    parser.add_argument("--client-id", required=True, help="App registration client ID")
    parser.add_argument("--client-secret", required=True, help="App registration secret")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--output", default="pim_report.json")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    client = PIMClient(args.tenant_id, args.client_id, args.client_secret)
    report = generate_report(client)
    out_path = os.path.join(args.output_dir, args.output)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Report saved to %s", out_path)
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
