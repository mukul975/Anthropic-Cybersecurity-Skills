#!/usr/bin/env python3
"""
Azure AD PIM Audit and Configuration Tool

Audits Entra ID role assignments, identifies permanent privileged assignments
that should be converted to PIM eligible, and monitors PIM activation events.

Requirements:
    pip install msal requests pandas
"""

import json
import sys
from datetime import datetime, timezone

try:
    import requests
    import msal
except ImportError:
    print("[ERROR] Required: pip install msal requests")
    sys.exit(1)


class EntraPIMAuditor:
    """Audit and manage Microsoft Entra PIM configuration."""

    def __init__(self, tenant_id, client_id, client_secret):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = None
        self._authenticate()

    def _authenticate(self):
        """Acquire Microsoft Graph access token using client credentials."""
        app = msal.ConfidentialClientApplication(
            self.client_id,
            authority=f"https://login.microsoftonline.com/{self.tenant_id}",
            client_credential=self.client_secret,
        )
        result = app.acquire_token_for_client(
            scopes=["https://graph.microsoft.com/.default"]
        )
        if "access_token" in result:
            self.token = result["access_token"]
            print("[OK] Authenticated to Microsoft Graph")
        else:
            raise Exception(f"Auth failed: {result.get('error_description')}")

    def _graph_get(self, endpoint):
        """Make authenticated GET request to Microsoft Graph."""
        headers = {"Authorization": f"Bearer {self.token}"}
        url = f"https://graph.microsoft.com/v1.0{endpoint}"
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()

    def get_directory_roles(self):
        """List all Entra directory role definitions."""
        result = self._graph_get("/roleManagement/directory/roleDefinitions")
        roles = {}
        for role in result.get("value", []):
            roles[role["id"]] = {
                "displayName": role["displayName"],
                "description": role.get("description", ""),
                "isBuiltIn": role.get("isBuiltIn", False),
            }
        return roles

    def get_active_assignments(self):
        """List all permanently active role assignments (non-PIM)."""
        result = self._graph_get(
            "/roleManagement/directory/roleAssignments?$expand=principal"
        )
        assignments = []
        for item in result.get("value", []):
            assignments.append({
                "roleDefinitionId": item["roleDefinitionId"],
                "principalId": item["principalId"],
                "directoryScopeId": item.get("directoryScopeId", "/"),
                "principalDisplayName": item.get("principal", {}).get("displayName", ""),
                "principalType": item.get("principal", {}).get("@odata.type", ""),
            })
        return assignments

    def get_eligible_assignments(self):
        """List all PIM eligible role assignments."""
        result = self._graph_get(
            "/roleManagement/directory/roleEligibilityScheduleInstances"
        )
        eligible = []
        for item in result.get("value", []):
            eligible.append({
                "roleDefinitionId": item["roleDefinitionId"],
                "principalId": item["principalId"],
                "directoryScopeId": item.get("directoryScopeId", "/"),
                "startDateTime": item.get("startDateTime"),
                "endDateTime": item.get("endDateTime"),
            })
        return eligible

    def get_pim_activation_history(self, days=30):
        """Retrieve PIM role activation audit events."""
        result = self._graph_get(
            f"/auditLogs/directoryAudits?"
            f"$filter=category eq 'RoleManagement' and "
            f"activityDisplayName eq 'Add member to role completed (PIM activation)'"
            f"&$top=100"
        )
        activations = []
        for event in result.get("value", []):
            activations.append({
                "activityDateTime": event.get("activityDateTime"),
                "activityDisplayName": event.get("activityDisplayName"),
                "initiatedBy": event.get("initiatedBy", {}).get("user", {}).get("displayName", ""),
                "targetResources": [
                    t.get("displayName", "") for t in event.get("targetResources", [])
                ],
                "result": event.get("result"),
            })
        return activations

    def identify_permanent_admins(self):
        """Find permanently active admin assignments that should be PIM eligible."""
        roles = self.get_directory_roles()
        active = self.get_active_assignments()
        eligible = self.get_eligible_assignments()

        critical_roles = {
            rid: info for rid, info in roles.items()
            if info["displayName"] in [
                "Global Administrator",
                "Privileged Role Administrator",
                "Security Administrator",
                "Exchange Administrator",
                "SharePoint Administrator",
                "User Administrator",
                "Application Administrator",
                "Cloud Application Administrator",
                "Intune Administrator",
                "Compliance Administrator",
            ]
        }

        findings = []
        eligible_principals = {
            (e["roleDefinitionId"], e["principalId"]) for e in eligible
        }

        for assignment in active:
            role_id = assignment["roleDefinitionId"]
            if role_id in critical_roles:
                is_also_eligible = (role_id, assignment["principalId"]) in eligible_principals
                findings.append({
                    "role": critical_roles[role_id]["displayName"],
                    "principal": assignment["principalDisplayName"],
                    "principalType": assignment["principalType"],
                    "hasEligibleAssignment": is_also_eligible,
                    "recommendation": "Convert to PIM eligible" if not is_also_eligible else "Review - has both active and eligible",
                })

        return findings

    def generate_audit_report(self):
        """Generate comprehensive PIM audit report."""
        roles = self.get_directory_roles()
        active = self.get_active_assignments()
        eligible = self.get_eligible_assignments()
        permanent_findings = self.identify_permanent_admins()

        report = {
            "report_title": "Microsoft Entra PIM Audit Report",
            "tenant_id": self.tenant_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_directory_roles": len(roles),
                "total_active_assignments": len(active),
                "total_eligible_assignments": len(eligible),
                "permanent_admin_findings": len(permanent_findings),
            },
            "findings": permanent_findings,
            "recommendations": [],
        }

        if len(permanent_findings) > 0:
            report["recommendations"].append({
                "priority": "Critical",
                "finding": f"{len(permanent_findings)} permanent privileged role assignments found",
                "action": "Convert to PIM eligible assignments with MFA and approval requirements"
            })

        active_global_admins = sum(
            1 for f in permanent_findings
            if f["role"] == "Global Administrator"
        )
        if active_global_admins > 2:
            report["recommendations"].append({
                "priority": "High",
                "finding": f"{active_global_admins} permanent Global Administrators (should be max 2 break-glass)",
                "action": "Reduce to 2 break-glass accounts, convert rest to PIM eligible"
            })

        return report


if __name__ == "__main__":
    print("=" * 60)
    print("Microsoft Entra PIM Audit Tool")
    print("=" * 60)
    print()
    print("Usage:")
    print("  auditor = EntraPIMAuditor(tenant_id, client_id, client_secret)")
    print("  report = auditor.generate_audit_report()")
    print("  print(json.dumps(report, indent=2))")
    print()
    print("Required Microsoft Graph permissions:")
    print("  - RoleManagement.Read.All")
    print("  - AuditLog.Read.All")
    print("  - Directory.Read.All")
