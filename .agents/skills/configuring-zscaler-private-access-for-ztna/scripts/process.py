#!/usr/bin/env python3
"""
Zscaler Private Access (ZPA) - Deployment Audit and Compliance Checker

Queries ZPA Admin API to audit App Connector health, application segment
coverage, access policy configuration, and user activity for ZTNA compliance.

Requirements:
    pip install requests
"""

import json
import sys
import time
from datetime import datetime, timezone
from typing import Any

import requests

ZPA_BASE_URL = "https://config.private.zscaler.com"


class ZPAAuditor:
    """Audit Zscaler Private Access deployment configuration."""

    def __init__(self, client_id: str, client_secret: str, customer_id: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.customer_id = customer_id
        self.token = None
        self._authenticate()

    def _authenticate(self):
        """Authenticate with ZPA API."""
        resp = requests.post(
            f"{ZPA_BASE_URL}/signin",
            json={
                "apiKey": self.client_id,
                "username": self.client_secret,
                "password": self.customer_id
            },
            timeout=30
        )
        resp.raise_for_status()
        self.token = resp.json().get("token")
        print("[AUTH] Successfully authenticated with ZPA API")

    def _get(self, endpoint: str, params: dict = None) -> dict:
        """Make authenticated GET request to ZPA API."""
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        resp = requests.get(
            f"{ZPA_BASE_URL}/mgmtconfig/v1/admin/customers/{self.customer_id}/{endpoint}",
            headers=headers,
            params=params or {},
            timeout=30
        )
        resp.raise_for_status()
        return resp.json()

    def audit_app_connectors(self) -> dict[str, Any]:
        """Audit App Connector deployment and health."""
        print("\n[1/5] Auditing App Connectors...")
        data = self._get("connector")
        connectors = data.get("list", [])

        stats = {
            "total": len(connectors),
            "healthy": 0,
            "unhealthy": 0,
            "groups": {},
            "version_distribution": {},
            "unhealthy_list": []
        }

        for conn in connectors:
            name = conn.get("name", "unknown")
            enabled = conn.get("enabled", False)
            runtime_status = conn.get("runtimeStatus", "UNKNOWN")
            version = conn.get("currentVersion", "unknown")
            group = conn.get("appConnectorGroupName", "ungrouped")

            stats["groups"][group] = stats["groups"].get(group, 0) + 1
            stats["version_distribution"][version] = stats["version_distribution"].get(version, 0) + 1

            if enabled and runtime_status == "ACTIVE":
                stats["healthy"] += 1
            else:
                stats["unhealthy"] += 1
                stats["unhealthy_list"].append({
                    "name": name, "status": runtime_status, "group": group
                })
                print(f"  [WARN] Unhealthy connector: {name} (status: {runtime_status})")

        print(f"  Total: {stats['total']}, Healthy: {stats['healthy']}, Unhealthy: {stats['unhealthy']}")
        print(f"  Groups: {stats['groups']}")

        # Check HA: each group should have >= 2 connectors
        for group, count in stats["groups"].items():
            if count < 2:
                print(f"  [CRITICAL] Group '{group}' has only {count} connector(s) - no HA!")

        return stats

    def audit_application_segments(self) -> dict[str, Any]:
        """Audit application segment configuration."""
        print("\n[2/5] Auditing Application Segments...")
        data = self._get("application")
        segments = data.get("list", [])

        stats = {
            "total": len(segments),
            "enabled": 0,
            "disabled": 0,
            "bypass_enabled": 0,
            "health_reporting": {"continuous": 0, "on_access": 0, "none": 0},
            "segments": []
        }

        for seg in segments:
            name = seg.get("name", "unknown")
            enabled = seg.get("enabled", False)
            bypass_type = seg.get("bypassType", "NEVER")
            health = seg.get("healthReporting", "NONE")
            domains = seg.get("domainNames", [])
            tcp_ports = seg.get("tcpPortRanges", [])

            if enabled:
                stats["enabled"] += 1
            else:
                stats["disabled"] += 1
                print(f"  [WARN] Disabled segment: {name}")

            if bypass_type != "NEVER":
                stats["bypass_enabled"] += 1
                print(f"  [WARN] Bypass enabled on segment: {name} (type: {bypass_type})")

            health_key = health.lower() if health.lower() in stats["health_reporting"] else "none"
            stats["health_reporting"][health_key] += 1

            stats["segments"].append({
                "name": name,
                "enabled": enabled,
                "domains": domains[:5],
                "ports": tcp_ports[:5],
                "bypass": bypass_type
            })

        print(f"  Total: {stats['total']}, Enabled: {stats['enabled']}, Disabled: {stats['disabled']}")
        print(f"  Bypass enabled: {stats['bypass_enabled']}")
        print(f"  Health reporting: {stats['health_reporting']}")
        return stats

    def audit_access_policies(self) -> dict[str, Any]:
        """Audit access policy configuration."""
        print("\n[3/5] Auditing Access Policies...")
        data = self._get("policySet/rules?policyType=ACCESS_POLICY")
        rules = data.get("list", [])

        stats = {
            "total": len(rules),
            "allow_rules": 0,
            "deny_rules": 0,
            "has_default_deny": False,
            "rules_without_conditions": 0,
            "rules_with_posture": 0,
            "rules": []
        }

        for rule in rules:
            name = rule.get("name", "unknown")
            action = rule.get("action", "UNKNOWN")
            conditions = rule.get("conditions", [])
            order = rule.get("order", 0)

            if action == "ALLOW":
                stats["allow_rules"] += 1
            elif action == "DENY":
                stats["deny_rules"] += 1

            if not conditions:
                stats["rules_without_conditions"] += 1
                print(f"  [WARN] Rule '{name}' has no conditions - overly permissive")

            # Check for device posture conditions
            has_posture = any(
                c.get("operands", [{}])[0].get("objectType") == "POSTURE_PROFILE"
                for c in conditions if c.get("operands")
            )
            if has_posture:
                stats["rules_with_posture"] += 1

            stats["rules"].append({
                "name": name, "action": action, "order": order,
                "conditions_count": len(conditions), "has_posture": has_posture
            })

        # Check for default deny rule (should be last rule with DENY action)
        if rules and rules[-1].get("action") == "DENY":
            stats["has_default_deny"] = True
        else:
            print("  [CRITICAL] No default deny rule found! All unlisted access may be permitted.")

        print(f"  Total rules: {stats['total']}")
        print(f"  Allow: {stats['allow_rules']}, Deny: {stats['deny_rules']}")
        print(f"  Rules with device posture: {stats['rules_with_posture']}")
        print(f"  Default deny: {'Yes' if stats['has_default_deny'] else 'NO - MISSING!'}")
        return stats

    def audit_server_groups(self) -> dict[str, Any]:
        """Audit server group configuration."""
        print("\n[4/5] Auditing Server Groups...")
        data = self._get("serverGroup")
        groups = data.get("list", [])

        stats = {
            "total": len(groups),
            "enabled": 0,
            "servers_total": 0,
            "groups": []
        }

        for group in groups:
            name = group.get("name", "unknown")
            enabled = group.get("enabled", False)
            servers = group.get("servers", [])

            if enabled:
                stats["enabled"] += 1
            stats["servers_total"] += len(servers)
            stats["groups"].append({
                "name": name, "enabled": enabled, "server_count": len(servers)
            })

        print(f"  Total groups: {stats['total']}, Enabled: {stats['enabled']}")
        print(f"  Total servers: {stats['servers_total']}")
        return stats

    def generate_report(self, connectors, segments, policies, server_groups) -> str:
        """Generate comprehensive ZPA audit report."""
        print("\n[5/5] Generating audit report...")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        report = f"""
ZPA ZTNA Deployment Audit Report
{'=' * 55}
Customer ID: {self.customer_id}
Generated: {now}

1. APP CONNECTORS
   Total deployed:              {connectors['total']}
   Healthy:                     {connectors['healthy']}
   Unhealthy:                   {connectors['unhealthy']}
   Connector groups:            {len(connectors['groups'])}
   HA compliance (2+ per group): {'PASS' if all(v >= 2 for v in connectors['groups'].values()) else 'FAIL'}

2. APPLICATION SEGMENTS
   Total segments:              {segments['total']}
   Enabled:                     {segments['enabled']}
   Disabled:                    {segments['disabled']}
   With bypass enabled:         {segments['bypass_enabled']}
   Health reporting:            {segments['health_reporting']}

3. ACCESS POLICIES
   Total rules:                 {policies['total']}
   Allow rules:                 {policies['allow_rules']}
   Deny rules:                  {policies['deny_rules']}
   Default deny rule:           {'YES' if policies['has_default_deny'] else 'MISSING - CRITICAL'}
   Rules with device posture:   {policies['rules_with_posture']} / {policies['total']}

4. SERVER GROUPS
   Total groups:                {server_groups['total']}
   Total servers:               {server_groups['servers_total']}

5. RECOMMENDATIONS
"""
        recommendations = []
        if connectors['unhealthy'] > 0:
            recommendations.append(f"   - Fix {connectors['unhealthy']} unhealthy App Connector(s)")
        if not policies['has_default_deny']:
            recommendations.append("   - ADD DEFAULT DENY RULE immediately")
        if policies['rules_with_posture'] < policies['allow_rules']:
            gap = policies['allow_rules'] - policies['rules_with_posture']
            recommendations.append(f"   - Add device posture to {gap} allow rule(s)")
        if segments['bypass_enabled'] > 0:
            recommendations.append(f"   - Review {segments['bypass_enabled']} segment(s) with bypass enabled")
        if not recommendations:
            recommendations.append("   - No critical issues found")

        report += "\n".join(recommendations)
        return report


def main():
    if len(sys.argv) < 4:
        print("Usage: python process.py <client_id> <client_secret> <customer_id>")
        print("\nAudits ZPA deployment for connector health, segment coverage, and policy compliance.")
        sys.exit(1)

    auditor = ZPAAuditor(sys.argv[1], sys.argv[2], sys.argv[3])

    connectors = auditor.audit_app_connectors()
    segments = auditor.audit_application_segments()
    policies = auditor.audit_access_policies()
    server_groups = auditor.audit_server_groups()

    report = auditor.generate_report(connectors, segments, policies, server_groups)
    print(report)

    filename = f"zpa_audit_{datetime.now().strftime('%Y%m%d')}.txt"
    with open(filename, "w") as f:
        f.write(report)
    print(f"\nReport saved to: {filename}")


if __name__ == "__main__":
    main()
