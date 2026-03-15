#!/usr/bin/env python3
"""BeyondCorp zero trust access assessment agent using Google Cloud IAP API via requests."""

import argparse
import json
import logging
import os
import subprocess
import sys
from datetime import datetime
from typing import Dict, List, Optional

try:
    import requests
except ImportError:
    sys.exit("requests required: pip install requests")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def get_gcloud_token() -> str:
    """Get access token from gcloud CLI."""
    try:
        result = subprocess.run(
            ["gcloud", "auth", "print-access-token"], capture_output=True, text=True, timeout=10)
        return result.stdout.strip()
    except FileNotFoundError:
        return ""


def list_iap_resources(project_id: str, token: str) -> List[dict]:
    """List IAP-protected resources in a GCP project."""
    url = f"https://iap.googleapis.com/v1/projects/{project_id}/iap_tunnel/locations/-/destGroups"
    resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=30)
    if resp.status_code == 200:
        return resp.json().get("destGroups", [])
    return []


def get_iap_settings(project_id: str, resource: str, token: str) -> dict:
    """Get IAP settings for a specific resource."""
    url = f"https://iap.googleapis.com/v1/projects/{project_id}/iap_web/compute/services/{resource}:iapSettings"
    resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=30)
    if resp.status_code == 200:
        return resp.json()
    return {"error": resp.status_code}


def list_access_levels(org_id: str, policy_name: str, token: str) -> List[dict]:
    """List Access Context Manager access levels."""
    url = f"https://accesscontextmanager.googleapis.com/v1/accessPolicies/{policy_name}/accessLevels"
    resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=30)
    if resp.status_code == 200:
        return resp.json().get("accessLevels", [])
    return []


def audit_iap_bindings(project_id: str, token: str) -> List[dict]:
    """Audit IAM policy bindings for IAP-secured resources."""
    url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}:getIamPolicy"
    resp = requests.post(url, headers={"Authorization": f"Bearer {token}"},
                         json={}, timeout=30)
    if resp.status_code != 200:
        return []
    bindings = resp.json().get("bindings", [])
    iap_bindings = [b for b in bindings if "iap" in b.get("role", "").lower()]
    return iap_bindings


def assess_zero_trust_posture(project_id: str, token: str) -> dict:
    """Assess BeyondCorp zero trust posture for a project."""
    iap_resources = list_iap_resources(project_id, token)
    iap_bindings = audit_iap_bindings(project_id, token)
    findings = []
    if not iap_resources:
        findings.append({"severity": "HIGH", "finding": "No IAP-protected resources found"})
    if not iap_bindings:
        findings.append({"severity": "HIGH", "finding": "No IAP IAM bindings configured"})
    allUsers = any("allUsers" in str(b.get("members", [])) for b in iap_bindings)
    if allUsers:
        findings.append({"severity": "CRITICAL", "finding": "IAP binding includes allUsers"})
    return {
        "iap_resources": len(iap_resources),
        "iap_bindings": len(iap_bindings),
        "findings": findings,
    }


def generate_report(project_id: str, token: str) -> dict:
    """Generate BeyondCorp zero trust assessment report."""
    report = {
        "analysis_date": datetime.utcnow().isoformat(),
        "project": project_id,
        "posture": assess_zero_trust_posture(project_id, token),
    }
    score = 100
    for f in report["posture"]["findings"]:
        if f["severity"] == "CRITICAL":
            score -= 30
        elif f["severity"] == "HIGH":
            score -= 15
    report["zero_trust_score"] = max(0, score)
    return report


def main():
    parser = argparse.ArgumentParser(description="BeyondCorp Zero Trust Assessment Agent")
    parser.add_argument("--project", required=True, help="GCP project ID")
    parser.add_argument("--token", default="", help="Access token (or uses gcloud)")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--output", default="beyondcorp_report.json")
    args = parser.parse_args()

    token = args.token or get_gcloud_token()
    if not token:
        logger.error("No access token. Run: gcloud auth print-access-token")
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)
    report = generate_report(args.project, token)
    out_path = os.path.join(args.output_dir, args.output)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", out_path)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
