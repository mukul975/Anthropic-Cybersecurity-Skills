#!/usr/bin/env python3
"""
Cloudflare Access Zero Trust - Deployment Audit Tool

Queries Cloudflare API to audit Access applications, policies, tunnel
health, and device enrollment for zero trust compliance validation.

Requirements:
    pip install requests
"""

import json
import sys
from datetime import datetime, timezone
from typing import Any

import requests

CF_API_BASE = "https://api.cloudflare.com/client/v4"


class CloudflareAccessAuditor:
    """Audit Cloudflare Zero Trust Access deployment."""

    def __init__(self, api_token: str, account_id: str):
        self.api_token = api_token
        self.account_id = account_id
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }

    def _get(self, endpoint: str, params: dict = None) -> dict:
        """Make authenticated GET request."""
        url = f"{CF_API_BASE}/accounts/{self.account_id}/{endpoint}"
        resp = requests.get(url, headers=self.headers, params=params or {}, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def audit_access_applications(self) -> dict[str, Any]:
        """Audit all Access applications and their configurations."""
        print("\n[1/5] Auditing Access Applications...")
        data = self._get("access/apps")
        apps = data.get("result", [])

        stats = {
            "total": len(apps),
            "self_hosted": 0,
            "saas": 0,
            "ssh": 0,
            "vnc": 0,
            "without_policies": 0,
            "session_durations": {},
            "apps": []
        }

        for app in apps:
            app_type = app.get("type", "unknown")
            name = app.get("name", "unknown")
            domain = app.get("domain", "N/A")
            session = app.get("session_duration", "24h")
            policies_count = len(app.get("policies", []))

            if app_type == "self_hosted":
                stats["self_hosted"] += 1
            elif app_type == "saas":
                stats["saas"] += 1
            elif app_type == "ssh":
                stats["ssh"] += 1
            elif app_type == "vnc":
                stats["vnc"] += 1

            if policies_count == 0:
                stats["without_policies"] += 1
                print(f"  [WARN] App '{name}' has no access policies!")

            stats["session_durations"][session] = stats["session_durations"].get(session, 0) + 1
            stats["apps"].append({
                "name": name, "type": app_type, "domain": domain,
                "session": session, "policies": policies_count
            })
            print(f"  [{app_type.upper()}] {name} ({domain}) - {policies_count} policies, session: {session}")

        return stats

    def audit_tunnels(self) -> dict[str, Any]:
        """Audit Cloudflare Tunnel health and configuration."""
        print("\n[2/5] Auditing Cloudflare Tunnels...")
        data = self._get("cfd_tunnel", params={"is_deleted": "false"})
        tunnels = data.get("result", [])

        stats = {
            "total": len(tunnels),
            "healthy": 0,
            "degraded": 0,
            "inactive": 0,
            "tunnels": []
        }

        for tunnel in tunnels:
            name = tunnel.get("name", "unknown")
            status = tunnel.get("status", "unknown")
            connections = tunnel.get("connections", [])
            created = tunnel.get("created_at", "")

            if status == "healthy":
                stats["healthy"] += 1
            elif status == "degraded":
                stats["degraded"] += 1
                print(f"  [WARN] Tunnel '{name}' is degraded")
            else:
                stats["inactive"] += 1
                print(f"  [WARN] Tunnel '{name}' is inactive")

            stats["tunnels"].append({
                "name": name, "status": status,
                "connections": len(connections), "created": created
            })

        print(f"  Total: {stats['total']}, Healthy: {stats['healthy']}, "
              f"Degraded: {stats['degraded']}, Inactive: {stats['inactive']}")
        return stats

    def audit_device_posture(self) -> dict[str, Any]:
        """Audit device posture rules configuration."""
        print("\n[3/5] Auditing Device Posture Rules...")
        data = self._get("devices/posture")
        rules = data.get("result", [])

        stats = {
            "total": len(rules),
            "types": {},
            "rules": []
        }

        for rule in rules:
            name = rule.get("name", "unknown")
            rule_type = rule.get("type", "unknown")
            stats["types"][rule_type] = stats["types"].get(rule_type, 0) + 1
            stats["rules"].append({"name": name, "type": rule_type})
            print(f"  [{rule_type}] {name}")

        required_types = {"disk_encryption", "os_version", "firewall"}
        missing = required_types - set(stats["types"].keys())
        if missing:
            print(f"  [WARN] Missing recommended posture types: {missing}")

        return stats

    def audit_device_enrollment(self) -> dict[str, Any]:
        """Audit enrolled devices."""
        print("\n[4/5] Auditing Device Enrollment...")
        data = self._get("devices")
        devices = data.get("result", [])

        stats = {
            "total": len(devices),
            "os_distribution": {},
            "active": 0,
            "revoked": 0
        }

        for device in devices:
            os_type = device.get("os_version", "unknown").split(" ")[0] if device.get("os_version") else "unknown"
            stats["os_distribution"][os_type] = stats["os_distribution"].get(os_type, 0) + 1
            if device.get("revoked_at"):
                stats["revoked"] += 1
            else:
                stats["active"] += 1

        print(f"  Total: {stats['total']}, Active: {stats['active']}, Revoked: {stats['revoked']}")
        print(f"  OS Distribution: {stats['os_distribution']}")
        return stats

    def generate_report(self, apps, tunnels, posture, devices) -> str:
        """Generate comprehensive audit report."""
        print("\n[5/5] Generating report...")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        report = f"""
Cloudflare Zero Trust Access Audit Report
{'=' * 55}
Account: {self.account_id}
Generated: {now}

1. ACCESS APPLICATIONS
   Total applications:         {apps['total']}
   Self-hosted:                {apps['self_hosted']}
   SaaS:                       {apps['saas']}
   SSH/Infrastructure:         {apps['ssh']}
   Without policies:           {apps['without_policies']}
   Session durations:          {apps['session_durations']}

2. TUNNEL INFRASTRUCTURE
   Total tunnels:              {tunnels['total']}
   Healthy:                    {tunnels['healthy']}
   Degraded:                   {tunnels['degraded']}
   Inactive:                   {tunnels['inactive']}

3. DEVICE POSTURE
   Posture rules defined:      {posture['total']}
   Rule types:                 {posture['types']}

4. DEVICE ENROLLMENT
   Total devices:              {devices['total']}
   Active:                     {devices['active']}
   Revoked:                    {devices['revoked']}

5. RECOMMENDATIONS
"""
        recs = []
        if apps['without_policies'] > 0:
            recs.append(f"   - {apps['without_policies']} app(s) without policies - add access rules immediately")
        if tunnels['degraded'] > 0 or tunnels['inactive'] > 0:
            recs.append(f"   - {tunnels['degraded'] + tunnels['inactive']} tunnel(s) need attention")
        if "disk_encryption" not in posture.get("types", {}):
            recs.append("   - Add disk encryption posture rule")
        if "os_version" not in posture.get("types", {}):
            recs.append("   - Add OS version posture rule")
        if not recs:
            recs.append("   - No critical issues found")
        report += "\n".join(recs)
        return report


def main():
    if len(sys.argv) < 3:
        print("Usage: python process.py <cf_api_token> <account_id>")
        sys.exit(1)

    auditor = CloudflareAccessAuditor(sys.argv[1], sys.argv[2])
    apps = auditor.audit_access_applications()
    tunnels = auditor.audit_tunnels()
    posture = auditor.audit_device_posture()
    devices = auditor.audit_device_enrollment()
    report = auditor.generate_report(apps, tunnels, posture, devices)
    print(report)

    filename = f"cloudflare_zt_audit_{datetime.now().strftime('%Y%m%d')}.txt"
    with open(filename, "w") as f:
        f.write(report)
    print(f"\nReport saved to: {filename}")


if __name__ == "__main__":
    main()
