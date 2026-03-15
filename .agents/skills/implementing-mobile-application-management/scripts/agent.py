#!/usr/bin/env python3
"""Mobile Application Management Agent - audits MDM policies, app inventory, and compliance posture."""

import json
import argparse
import logging
import subprocess
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def mdm_api_request(base_url, token, endpoint, method="GET"):
    """Execute MDM API request via curl."""
    cmd = ["curl", "-s", "-X", method,
           "-H", f"Authorization: Bearer {token}",
           "-H", "Accept: application/json",
           f"{base_url}{endpoint}"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout) if result.stdout else {}


def get_managed_devices(base_url, token):
    """Get all managed devices."""
    return mdm_api_request(base_url, token, "/api/v1/devices")


def get_managed_apps(base_url, token):
    """Get managed application inventory."""
    return mdm_api_request(base_url, token, "/api/v1/apps")


def get_compliance_policies(base_url, token):
    """Get device compliance policies."""
    return mdm_api_request(base_url, token, "/api/v1/compliance/policies")


def get_app_protection_policies(base_url, token):
    """Get MAM app protection policies."""
    return mdm_api_request(base_url, token, "/api/v1/app-protection-policies")


def audit_device_compliance(devices):
    """Audit device compliance status."""
    compliant = 0
    non_compliant = 0
    issues = defaultdict(int)
    for device in devices:
        if device.get("compliance_state") == "compliant":
            compliant += 1
        else:
            non_compliant += 1
            for issue in device.get("compliance_issues", []):
                issues[issue] += 1
    return {
        "total_devices": len(devices),
        "compliant": compliant,
        "non_compliant": non_compliant,
        "compliance_rate": round(compliant / max(len(devices), 1) * 100, 1),
        "top_issues": dict(sorted(issues.items(), key=lambda x: x[1], reverse=True)[:10]),
    }


def audit_app_security(apps):
    """Audit managed app security configuration."""
    findings = []
    for app in apps:
        app_name = app.get("name", "unknown")
        if not app.get("managed"):
            findings.append({"app": app_name, "issue": "unmanaged_app", "severity": "medium"})
        if app.get("data_sharing_allowed"):
            findings.append({"app": app_name, "issue": "data_sharing_enabled", "severity": "high"})
        if not app.get("encryption_required"):
            findings.append({"app": app_name, "issue": "encryption_not_required", "severity": "high"})
        if not app.get("pin_required"):
            findings.append({"app": app_name, "issue": "no_app_pin", "severity": "medium"})
        if app.get("allow_backup_to_cloud"):
            findings.append({"app": app_name, "issue": "cloud_backup_allowed", "severity": "medium"})
    return findings


def audit_protection_policies(policies):
    """Audit MAM protection policy configuration."""
    results = []
    for policy in policies:
        checks = {
            "data_transfer_restricted": policy.get("restrict_cut_copy_paste", False),
            "save_as_blocked": policy.get("block_save_as", False),
            "screen_capture_blocked": policy.get("block_screen_capture", False),
            "managed_browser_required": policy.get("require_managed_browser", False),
            "min_os_version_set": bool(policy.get("minimum_os_version")),
            "jailbreak_detection": policy.get("block_jailbroken", False),
            "offline_grace_period_set": bool(policy.get("offline_interval")),
        }
        passed = sum(1 for v in checks.values() if v)
        results.append({
            "policy_name": policy.get("name", "unknown"),
            "platform": policy.get("platform", "unknown"),
            "checks": checks,
            "score": round(passed / max(len(checks), 1) * 100, 1),
        })
    return results


def generate_report(devices, apps, policies, protection_policies):
    device_audit = audit_device_compliance(devices)
    app_findings = audit_app_security(apps)
    policy_audit = audit_protection_policies(protection_policies)
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "device_compliance": device_audit,
        "app_security_findings": len(app_findings),
        "high_severity_findings": len([f for f in app_findings if f["severity"] == "high"]),
        "app_findings_detail": app_findings[:20],
        "protection_policy_audit": policy_audit,
        "overall_mam_score": round(
            sum(p["score"] for p in policy_audit) / max(len(policy_audit), 1), 1),
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="Mobile Application Management Audit Agent")
    parser.add_argument("--mdm-url", required=True, help="MDM/UEM API base URL")
    parser.add_argument("--token", required=True, help="API bearer token")
    parser.add_argument("--output", default="mam_audit_report.json")
    args = parser.parse_args()

    devices = get_managed_devices(args.mdm_url, args.token)
    apps = get_managed_apps(args.mdm_url, args.token)
    policies = get_compliance_policies(args.mdm_url, args.token)
    protection = get_app_protection_policies(args.mdm_url, args.token)
    report = generate_report(devices, apps, policies, protection)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("MAM audit: %d devices (%.1f%% compliant), %d app findings, MAM score %.1f%%",
                report["device_compliance"]["total_devices"],
                report["device_compliance"]["compliance_rate"],
                report["app_security_findings"], report["overall_mam_score"])
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
