#!/usr/bin/env python3
"""BeyondCorp Zero Trust Agent - audits IAP configuration, access levels, and policy bindings."""

import json
import argparse
import logging
import subprocess
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def gcloud_json(args_list):
    """Execute gcloud command and return JSON output."""
    cmd = ["gcloud"] + args_list + ["--format=json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return json.loads(result.stdout) if result.returncode == 0 and result.stdout else []


def list_iap_protected_resources(project):
    """List resources protected by Identity-Aware Proxy."""
    backends = gcloud_json(["compute", "backend-services", "list", "--project", project])
    protected = []
    for backend in backends:
        iap = backend.get("iap", {})
        protected.append({
            "name": backend.get("name", ""),
            "iap_enabled": iap.get("enabled", False),
            "oauth2_client_id": bool(iap.get("oauth2ClientId", "")),
        })
    return protected


def get_access_levels(policy_name):
    """Retrieve Access Context Manager access levels."""
    levels = gcloud_json(["access-context-manager", "levels", "list", "--policy", policy_name])
    parsed = []
    for level in levels:
        basic = level.get("basic", {})
        conditions = basic.get("conditions", [])
        parsed.append({
            "name": level.get("name", "").split("/")[-1],
            "title": level.get("title", ""),
            "combining_function": basic.get("combiningFunction", "AND"),
            "condition_count": len(conditions),
            "has_ip_restriction": any(c.get("ipSubnetworks") for c in conditions),
            "has_device_policy": any(c.get("devicePolicy") for c in conditions),
            "has_region_restriction": any(c.get("regions") for c in conditions),
        })
    return parsed


def audit_iap_iam_bindings(project):
    """Audit IAM bindings on IAP-protected resources."""
    findings = []
    cmd = ["gcloud", "iap", "web", "get-iam-policy", "--project", project, "--format=json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        return [{"issue": "Cannot retrieve IAP IAM policy", "severity": "high"}]
    policy = json.loads(result.stdout) if result.stdout else {}
    for binding in policy.get("bindings", []):
        role = binding.get("role", "")
        members = binding.get("members", [])
        condition = binding.get("condition")
        if role == "roles/iap.httpsResourceAccessor":
            if "allUsers" in members or "allAuthenticatedUsers" in members:
                findings.append({
                    "role": role, "issue": "Public access via allUsers/allAuthenticatedUsers",
                    "severity": "critical",
                    "recommendation": "Restrict to specific user/group identities",
                })
            if not condition:
                findings.append({
                    "role": role, "members": members[:5],
                    "issue": "IAP binding without access level condition",
                    "severity": "high",
                    "recommendation": "Add access level condition for context-aware enforcement",
                })
    return findings


def audit_access_level_strength(access_levels):
    """Audit access levels for security strength."""
    findings = []
    for level in access_levels:
        if not level["has_device_policy"]:
            findings.append({
                "access_level": level["name"],
                "issue": "No device policy requirement",
                "severity": "medium",
                "recommendation": "Add device trust requirements (encryption, screen lock, OS version)",
            })
        if not level["has_ip_restriction"] and not level["has_region_restriction"]:
            findings.append({
                "access_level": level["name"],
                "issue": "No network or geographic restriction",
                "severity": "medium",
                "recommendation": "Consider adding corporate IP range or geo restrictions",
            })
        if level["condition_count"] == 0:
            findings.append({
                "access_level": level["name"],
                "issue": "Empty access level with no conditions",
                "severity": "high",
            })
    return findings


def check_endpoint_verification(project):
    """Check Endpoint Verification deployment status."""
    devices = gcloud_json(["endpoint-verification", "list", "--project", project])
    total = len(devices)
    compliant = sum(1 for d in devices if d.get("complianceState") == "COMPLIANT")
    return {
        "total_devices": total,
        "compliant": compliant,
        "non_compliant": total - compliant,
        "compliance_rate": round(compliant / max(total, 1) * 100, 1),
    }


def generate_report(protected, access_levels, iam_findings, level_findings, endpoint_status):
    iap_enabled = sum(1 for r in protected if r["iap_enabled"])
    all_findings = iam_findings + level_findings
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "framework": "BeyondCorp Enterprise / Zero Trust",
        "iap_protected_resources": len(protected),
        "iap_enabled_count": iap_enabled,
        "iap_coverage": round(iap_enabled / max(len(protected), 1) * 100, 1),
        "access_levels_defined": len(access_levels),
        "access_level_details": access_levels,
        "endpoint_verification": endpoint_status,
        "iam_findings": iam_findings,
        "access_level_findings": level_findings,
        "total_findings": len(all_findings),
        "critical_findings": sum(1 for f in all_findings if f.get("severity") == "critical"),
    }


def main():
    parser = argparse.ArgumentParser(description="BeyondCorp Zero Trust Audit Agent")
    parser.add_argument("--project", required=True, help="GCP project ID")
    parser.add_argument("--access-policy", required=True, help="Access Context Manager policy ID")
    parser.add_argument("--output", default="beyondcorp_audit_report.json")
    args = parser.parse_args()

    protected = list_iap_protected_resources(args.project)
    access_levels = get_access_levels(args.access_policy)
    iam_findings = audit_iap_iam_bindings(args.project)
    level_findings = audit_access_level_strength(access_levels)
    endpoint_status = check_endpoint_verification(args.project)
    report = generate_report(protected, access_levels, iam_findings, level_findings, endpoint_status)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("BeyondCorp: %.1f%% IAP coverage, %d access levels, %d findings",
                report["iap_coverage"], report["access_levels_defined"], report["total_findings"])
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
