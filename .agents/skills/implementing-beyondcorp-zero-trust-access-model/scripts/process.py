#!/usr/bin/env python3
"""
BeyondCorp Zero Trust Access Model - Assessment and Audit Tool

Audits GCP IAP configuration, Access Context Manager access levels,
and Endpoint Verification device compliance to validate BeyondCorp
deployment readiness and ongoing compliance.

Requirements:
    pip install google-cloud-iap google-cloud-access-context-manager
    pip install google-cloud-logging google-auth pandas
"""

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from typing import Any


def run_gcloud(args: list[str]) -> dict | list | str:
    """Execute a gcloud command and return parsed JSON output."""
    cmd = ["gcloud"] + args + ["--format=json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        print(f"[ERROR] gcloud {' '.join(args[:3])}...: {result.stderr.strip()}")
        return {}
    try:
        return json.loads(result.stdout) if result.stdout.strip() else {}
    except json.JSONDecodeError:
        return result.stdout.strip()


def audit_iap_enabled_services(project_id: str) -> list[dict[str, Any]]:
    """List all backend services with IAP enabled and their policy bindings."""
    print("\n[1/6] Auditing IAP-enabled backend services...")

    backends = run_gcloud([
        "compute", "backend-services", "list",
        "--project", project_id
    ])
    if not isinstance(backends, list):
        print("  No backend services found or unable to list.")
        return []

    iap_services = []
    for backend in backends:
        name = backend.get("name", "unknown")
        iap_config = backend.get("iap", {})
        iap_enabled = iap_config.get("enabled", False)

        if iap_enabled:
            # Get IAM policy for this backend service
            policy = run_gcloud([
                "iap", "web", "get-iam-policy",
                "--resource-type=backend-services",
                "--service", name,
                "--project", project_id
            ])
            bindings = policy.get("bindings", []) if isinstance(policy, dict) else []

            iap_services.append({
                "service_name": name,
                "iap_enabled": True,
                "oauth2_client_id": iap_config.get("oauth2ClientId", "N/A"),
                "bindings_count": len(bindings),
                "bindings": bindings,
                "has_access_level_conditions": any(
                    b.get("condition") for b in bindings
                )
            })
            status = "WITH" if iap_services[-1]["has_access_level_conditions"] else "WITHOUT"
            print(f"  [IAP ON]  {name} - {len(bindings)} bindings {status} access level conditions")
        else:
            print(f"  [IAP OFF] {name}")

    return iap_services


def audit_access_levels(policy_id: str) -> list[dict[str, Any]]:
    """Enumerate and validate Access Context Manager access levels."""
    print("\n[2/6] Auditing Access Context Manager access levels...")

    levels = run_gcloud([
        "access-context-manager", "levels", "list",
        "--policy", policy_id
    ])
    if not isinstance(levels, list):
        print("  No access levels found or unable to list.")
        return []

    access_levels = []
    for level in levels:
        name = level.get("name", "").split("/")[-1]
        title = level.get("title", "Untitled")
        basic = level.get("basic", {})
        custom = level.get("custom", {})

        level_info = {
            "name": name,
            "title": title,
            "type": "basic" if basic else "custom",
            "combining_function": basic.get("combiningFunction", "AND"),
            "conditions_count": len(basic.get("conditions", [])),
            "has_device_policy": False,
            "has_ip_restriction": False,
            "has_region_restriction": False,
            "requires_encryption": False,
            "requires_screenlock": False,
        }

        for condition in basic.get("conditions", []):
            device_policy = condition.get("devicePolicy", {})
            if device_policy:
                level_info["has_device_policy"] = True
                enc_statuses = device_policy.get("allowedEncryptionStatuses", [])
                if "ENCRYPTED" in enc_statuses:
                    level_info["requires_encryption"] = True
                if device_policy.get("requireScreenlock"):
                    level_info["requires_screenlock"] = True
            if condition.get("ipSubnetworks"):
                level_info["has_ip_restriction"] = True
            if condition.get("regions"):
                level_info["has_region_restriction"] = True
                level_info["allowed_regions"] = condition["regions"]

        access_levels.append(level_info)
        print(f"  [{level_info['type'].upper()}] {title} ({name})")
        print(f"    Device policy: {level_info['has_device_policy']}, "
              f"Encryption: {level_info['requires_encryption']}, "
              f"Screen lock: {level_info['requires_screenlock']}")

    return access_levels


def audit_endpoint_verification(project_id: str) -> dict[str, Any]:
    """Check Endpoint Verification device enrollment and compliance."""
    print("\n[3/6] Auditing Endpoint Verification device compliance...")

    devices = run_gcloud([
        "alpha", "devices", "list",
        "--format=json"
    ])
    if not isinstance(devices, list):
        print("  Unable to retrieve device inventory. Ensure Endpoint Verification is deployed.")
        return {"total": 0, "compliant": 0, "non_compliant": 0}

    stats = {
        "total": len(devices),
        "compliant": 0,
        "non_compliant": 0,
        "os_distribution": {},
        "encryption_status": {"encrypted": 0, "unencrypted": 0, "unknown": 0},
        "non_compliant_devices": []
    }

    for device in devices:
        os_type = device.get("osType", "UNKNOWN")
        stats["os_distribution"][os_type] = stats["os_distribution"].get(os_type, 0) + 1

        compliance = device.get("complianceState", "UNKNOWN")
        if compliance == "COMPLIANT":
            stats["compliant"] += 1
        else:
            stats["non_compliant"] += 1
            stats["non_compliant_devices"].append({
                "device_id": device.get("name", "unknown"),
                "os": os_type,
                "compliance_state": compliance
            })

    compliance_rate = (stats["compliant"] / stats["total"] * 100) if stats["total"] > 0 else 0
    print(f"  Total devices: {stats['total']}")
    print(f"  Compliant: {stats['compliant']} ({compliance_rate:.1f}%)")
    print(f"  Non-compliant: {stats['non_compliant']}")
    print(f"  OS distribution: {stats['os_distribution']}")

    return stats


def audit_iap_access_logs(project_id: str, hours: int = 24) -> dict[str, Any]:
    """Analyze IAP access logs for denials and anomalies."""
    print(f"\n[4/6] Analyzing IAP access logs (last {hours} hours)...")

    start_time = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    log_filter = (
        f'resource.type="iap_tunnel" OR resource.type="gce_backend_service" '
        f'AND timestamp >= "{start_time}"'
    )

    logs = run_gcloud([
        "logging", "read", log_filter,
        "--project", project_id,
        "--limit=1000"
    ])
    if not isinstance(logs, list):
        print("  No IAP access logs found or unable to query.")
        return {"total": 0, "allowed": 0, "denied": 0}

    stats = {
        "total": len(logs),
        "allowed": 0,
        "denied": 0,
        "denied_users": {},
        "denied_applications": {},
        "top_accessed_apps": {}
    }

    for entry in logs:
        payload = entry.get("jsonPayload", {})
        decision = payload.get("decision", "ALLOW")
        user = payload.get("authenticationInfo", {}).get("principalEmail", "unknown")
        resource = entry.get("resource", {}).get("labels", {}).get("backend_service_name", "unknown")

        stats["top_accessed_apps"][resource] = stats["top_accessed_apps"].get(resource, 0) + 1

        if decision == "DENY":
            stats["denied"] += 1
            stats["denied_users"][user] = stats["denied_users"].get(user, 0) + 1
            stats["denied_applications"][resource] = stats["denied_applications"].get(resource, 0) + 1
        else:
            stats["allowed"] += 1

    denial_rate = (stats["denied"] / stats["total"] * 100) if stats["total"] > 0 else 0
    print(f"  Total requests: {stats['total']}")
    print(f"  Allowed: {stats['allowed']}")
    print(f"  Denied: {stats['denied']} ({denial_rate:.1f}%)")
    if stats["denied_users"]:
        top_denied = sorted(stats["denied_users"].items(), key=lambda x: x[1], reverse=True)[:5]
        print(f"  Top denied users: {top_denied}")

    return stats


def audit_session_policies(project_id: str) -> list[dict[str, Any]]:
    """Check IAP session duration and re-authentication settings."""
    print("\n[5/6] Auditing IAP session and re-authentication policies...")

    backends = run_gcloud([
        "compute", "backend-services", "list",
        "--project", project_id
    ])
    if not isinstance(backends, list):
        return []

    session_policies = []
    for backend in backends:
        iap = backend.get("iap", {})
        if not iap.get("enabled"):
            continue

        name = backend.get("name", "unknown")
        settings = run_gcloud([
            "iap", "settings", "get",
            "--project", project_id,
            "--resource-type=compute",
            "--service", name
        ])

        if isinstance(settings, dict):
            access_settings = settings.get("accessSettings", {})
            reauth = access_settings.get("reauthSettings", {})
            session_policies.append({
                "service": name,
                "max_session_duration": reauth.get("maxAge", "Not configured"),
                "reauth_method": reauth.get("method", "Not configured"),
                "policy_type": reauth.get("policyType", "DEFAULT")
            })
            print(f"  {name}: session={reauth.get('maxAge', 'default')}, "
                  f"method={reauth.get('method', 'default')}")

    return session_policies


def generate_compliance_report(
    project_id: str,
    iap_services: list,
    access_levels: list,
    device_stats: dict,
    log_stats: dict,
    session_policies: list
) -> str:
    """Generate a comprehensive BeyondCorp compliance report."""
    print("\n[6/6] Generating BeyondCorp compliance report...")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_services = len(iap_services)
    with_conditions = sum(1 for s in iap_services if s["has_access_level_conditions"])
    device_compliance = (
        (device_stats["compliant"] / device_stats["total"] * 100)
        if device_stats["total"] > 0 else 0
    )

    report = f"""
BeyondCorp Zero Trust Compliance Audit Report
{'=' * 55}
Project: {project_id}
Generated: {now}
Audit Period: Last 24 hours

1. IAP COVERAGE
   IAP-enabled services:            {total_services}
   Services with access levels:     {with_conditions} / {total_services}
   Coverage rate:                   {(with_conditions / total_services * 100) if total_services else 0:.1f}%

2. ACCESS LEVELS
   Total access levels defined:     {len(access_levels)}
   With device policy:              {sum(1 for a in access_levels if a['has_device_policy'])}
   Requiring encryption:            {sum(1 for a in access_levels if a['requires_encryption'])}
   Requiring screen lock:           {sum(1 for a in access_levels if a['requires_screenlock'])}
   With IP restrictions:            {sum(1 for a in access_levels if a['has_ip_restriction'])}
   With region restrictions:        {sum(1 for a in access_levels if a['has_region_restriction'])}

3. DEVICE COMPLIANCE
   Total enrolled devices:          {device_stats['total']}
   Compliant devices:               {device_stats['compliant']} ({device_compliance:.1f}%)
   Non-compliant devices:           {device_stats['non_compliant']}

4. ACCESS LOG ANALYSIS (24h)
   Total access requests:           {log_stats['total']}
   Allowed:                         {log_stats['allowed']}
   Denied:                          {log_stats['denied']}
   Denial rate:                     {(log_stats['denied'] / log_stats['total'] * 100) if log_stats['total'] else 0:.1f}%

5. SESSION POLICIES
   Services with re-auth policy:    {len(session_policies)}

6. RECOMMENDATIONS
"""
    recommendations = []
    if with_conditions < total_services:
        recommendations.append(
            f"   - {total_services - with_conditions} IAP services lack access level conditions. "
            "Add device posture requirements."
        )
    if device_compliance < 95:
        recommendations.append(
            f"   - Device compliance is {device_compliance:.1f}% (target: 95%). "
            "Remediate non-compliant devices."
        )
    if not any(a["requires_encryption"] for a in access_levels):
        recommendations.append(
            "   - No access levels require disk encryption. Add encryption requirement to sensitive app tiers."
        )
    if len(session_policies) < total_services:
        recommendations.append(
            f"   - {total_services - len(session_policies)} services lack explicit session policies. "
            "Configure re-authentication."
        )
    if not recommendations:
        recommendations.append("   - No critical issues found. Continue monitoring.")

    report += "\n".join(recommendations)

    return report


def main():
    if len(sys.argv) < 2:
        print("Usage: python process.py <project-id> [access-policy-id]")
        print("\nExample:")
        print("  python process.py my-gcp-project 123456789")
        sys.exit(1)

    project_id = sys.argv[1]
    policy_id = sys.argv[2] if len(sys.argv) > 2 else None

    print(f"BeyondCorp Zero Trust Audit - Project: {project_id}")
    print("=" * 55)

    iap_services = audit_iap_enabled_services(project_id)
    access_levels = audit_access_levels(policy_id) if policy_id else []
    device_stats = audit_endpoint_verification(project_id)
    log_stats = audit_iap_access_logs(project_id)
    session_policies = audit_session_policies(project_id)

    report = generate_compliance_report(
        project_id, iap_services, access_levels,
        device_stats, log_stats, session_policies
    )
    print(report)

    report_path = f"beyondcorp_audit_{project_id}_{datetime.now().strftime('%Y%m%d')}.txt"
    with open(report_path, "w") as f:
        f.write(report)
    print(f"\nReport saved to: {report_path}")


if __name__ == "__main__":
    main()
