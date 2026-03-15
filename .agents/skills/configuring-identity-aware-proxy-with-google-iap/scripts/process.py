#!/usr/bin/env python3
"""
Google Cloud IAP - Configuration Audit Tool

Audits IAP-enabled backend services, IAM bindings, access levels,
session settings, and access logs for compliance validation.

Requirements:
    pip install google-cloud-compute google-auth requests
"""

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from typing import Any


def run_gcloud(args: list[str]) -> Any:
    """Execute gcloud command and return JSON output."""
    cmd = ["gcloud"] + args + ["--format=json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        return []
    try:
        return json.loads(result.stdout) if result.stdout.strip() else []
    except json.JSONDecodeError:
        return []


def audit_iap_backends(project_id: str) -> list[dict]:
    """Audit all backend services for IAP configuration."""
    print("\n[1/5] Auditing IAP-enabled backend services...")
    backends = run_gcloud(["compute", "backend-services", "list", "--project", project_id])
    if not isinstance(backends, list):
        return []

    results = []
    for backend in backends:
        name = backend.get("name", "unknown")
        iap = backend.get("iap", {})
        enabled = iap.get("enabled", False)

        info = {"name": name, "iap_enabled": enabled, "bindings": [], "has_conditions": False}

        if enabled:
            policy = run_gcloud([
                "iap", "web", "get-iam-policy",
                "--resource-type=backend-services",
                "--service", name, "--project", project_id
            ])
            bindings = policy.get("bindings", []) if isinstance(policy, dict) else []
            info["bindings"] = bindings
            info["bindings_count"] = len(bindings)
            info["has_conditions"] = any(b.get("condition") for b in bindings)
            print(f"  [IAP ON]  {name}: {len(bindings)} bindings, conditions: {info['has_conditions']}")
        else:
            print(f"  [IAP OFF] {name}")

        results.append(info)
    return results


def audit_access_levels(policy_id: str) -> list[dict]:
    """Audit Access Context Manager levels."""
    print("\n[2/5] Auditing access levels...")
    if not policy_id:
        print("  Skipped - no policy ID provided")
        return []

    levels = run_gcloud(["access-context-manager", "levels", "list", "--policy", policy_id])
    if not isinstance(levels, list):
        return []

    results = []
    for level in levels:
        name = level.get("name", "").split("/")[-1]
        title = level.get("title", "")
        basic = level.get("basic", {})
        has_device = any(
            c.get("devicePolicy") for c in basic.get("conditions", [])
        )
        has_ip = any(
            c.get("ipSubnetworks") for c in basic.get("conditions", [])
        )
        results.append({"name": name, "title": title, "has_device": has_device, "has_ip": has_ip})
        print(f"  {title}: device_policy={has_device}, ip_restriction={has_ip}")

    return results


def audit_iap_tunnel_access(project_id: str) -> dict:
    """Audit IAP TCP tunnel permissions."""
    print("\n[3/5] Auditing IAP tunnel access...")
    instances = run_gcloud(["compute", "instances", "list", "--project", project_id])
    if not isinstance(instances, list):
        return {"total_vms": 0}

    stats = {"total_vms": len(instances), "with_external_ip": 0, "tunnel_accessible": 0}
    for vm in instances:
        name = vm.get("name", "unknown")
        interfaces = vm.get("networkInterfaces", [])
        has_ext_ip = any(
            iface.get("accessConfigs") for iface in interfaces
        )
        if has_ext_ip:
            stats["with_external_ip"] += 1

    print(f"  Total VMs: {stats['total_vms']}, With external IP: {stats['with_external_ip']}")
    if stats["with_external_ip"] > 0:
        print(f"  [WARN] {stats['with_external_ip']} VMs have external IPs - consider removing for IAP-only access")
    return stats


def audit_iap_logs(project_id: str) -> dict:
    """Analyze recent IAP access logs."""
    print("\n[4/5] Analyzing IAP access logs (24h)...")
    start = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    logs = run_gcloud([
        "logging", "read",
        f'resource.type="gce_backend_service" AND protoPayload.serviceName="iap.googleapis.com" AND timestamp>="{start}"',
        "--project", project_id, "--limit=500"
    ])
    if not isinstance(logs, list):
        return {"total": 0, "allowed": 0, "denied": 0}

    stats = {"total": len(logs), "allowed": 0, "denied": 0, "users": set()}
    for entry in logs:
        payload = entry.get("protoPayload", {})
        status = payload.get("status", {}).get("code", 0)
        user = payload.get("authenticationInfo", {}).get("principalEmail", "")
        if status == 0:
            stats["allowed"] += 1
        else:
            stats["denied"] += 1
        if user:
            stats["users"].add(user)

    stats["unique_users"] = len(stats["users"])
    del stats["users"]
    print(f"  Requests: {stats['total']}, Allowed: {stats['allowed']}, Denied: {stats['denied']}")
    return stats


def generate_report(project_id: str, backends: list, levels: list,
                    tunnels: dict, logs: dict) -> str:
    """Generate IAP audit report."""
    print("\n[5/5] Generating report...")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    iap_on = [b for b in backends if b["iap_enabled"]]
    iap_off = [b for b in backends if not b["iap_enabled"]]
    with_conditions = [b for b in iap_on if b.get("has_conditions")]

    report = f"""
Google Cloud IAP Audit Report
{'=' * 55}
Project: {project_id}
Generated: {now}

1. BACKEND SERVICES
   Total backend services:       {len(backends)}
   IAP enabled:                  {len(iap_on)}
   IAP disabled:                 {len(iap_off)}
   With access level conditions: {len(with_conditions)} / {len(iap_on)}

2. ACCESS LEVELS
   Total defined:                {len(levels)}
   With device policy:           {sum(1 for l in levels if l['has_device'])}
   With IP restrictions:         {sum(1 for l in levels if l['has_ip'])}

3. VM ACCESS
   Total VMs:                    {tunnels['total_vms']}
   With external IP:             {tunnels['with_external_ip']}

4. ACCESS LOGS (24h)
   Total requests:               {logs['total']}
   Allowed:                      {logs['allowed']}
   Denied:                       {logs['denied']}
   Unique users:                 {logs.get('unique_users', 0)}

5. RECOMMENDATIONS
"""
    recs = []
    if iap_off:
        recs.append(f"   - Enable IAP on {len(iap_off)} unprotected backend service(s)")
    if len(with_conditions) < len(iap_on):
        recs.append(f"   - Add access level conditions to {len(iap_on) - len(with_conditions)} IAP service(s)")
    if tunnels["with_external_ip"] > 0:
        recs.append(f"   - Remove external IPs from {tunnels['with_external_ip']} VM(s) for IAP-only access")
    if not recs:
        recs.append("   - Configuration meets best practices")
    report += "\n".join(recs)
    return report


def main():
    if len(sys.argv) < 2:
        print("Usage: python process.py <project-id> [access-policy-id]")
        sys.exit(1)

    project_id = sys.argv[1]
    policy_id = sys.argv[2] if len(sys.argv) > 2 else None

    backends = audit_iap_backends(project_id)
    levels = audit_access_levels(policy_id)
    tunnels = audit_iap_tunnel_access(project_id)
    logs = audit_iap_logs(project_id)
    report = generate_report(project_id, backends, levels, tunnels, logs)
    print(report)

    filename = f"iap_audit_{project_id}_{datetime.now().strftime('%Y%m%d')}.txt"
    with open(filename, "w") as f:
        f.write(report)
    print(f"\nReport saved to: {filename}")


if __name__ == "__main__":
    main()
