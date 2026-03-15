#!/usr/bin/env python3
"""Agent for performing OAuth scope minimization review.

Audits OAuth 2.0 permission grants in Microsoft Entra ID (Azure AD)
to identify over-permissioned apps, stale grants, and excessive scopes.
"""

import requests
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta


SCOPE_RISK = {
    "critical": [
        "Directory.ReadWrite.All", "Application.ReadWrite.All",
        "Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All",
        "Sites.FullControl.All", "User.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
    ],
    "high": [
        "Mail.Read", "Files.Read.All", "User.Read.All",
        "Group.Read.All", "Directory.Read.All", "AuditLog.Read.All",
        "Calendars.ReadWrite", "Contacts.ReadWrite",
    ],
    "medium": [
        "Calendars.Read", "Files.ReadWrite", "Tasks.ReadWrite",
        "Chat.ReadWrite", "ChannelMessage.Send",
    ],
    "low": [
        "User.Read", "openid", "profile", "email", "offline_access",
        "People.Read", "User.ReadBasic.All",
    ],
}


class OAuthScopeAuditor:
    """Audits OAuth permission grants via Microsoft Graph API."""

    def __init__(self, tenant_id, client_id, client_secret):
        self.tenant_id = tenant_id
        self.base_url = "https://graph.microsoft.com/v1.0"
        self.token = self._get_token(client_id, client_secret)
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def _get_token(self, client_id, client_secret):
        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        resp = requests.post(url, data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://graph.microsoft.com/.default",
        })
        resp.raise_for_status()
        return resp.json()["access_token"]

    def _paginated_get(self, url):
        results = []
        while url:
            resp = requests.get(url, headers=self.headers)
            resp.raise_for_status()
            data = resp.json()
            results.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
        return results

    def get_service_principals(self):
        """Get all enterprise applications (service principals)."""
        return self._paginated_get(
            f"{self.base_url}/servicePrincipals?$top=999"
            "&$select=id,appId,displayName,appOwnerOrganizationId,accountEnabled,createdDateTime"
        )

    def get_oauth_grants(self):
        """Get all delegated permission grants."""
        return self._paginated_get(
            f"{self.base_url}/oauth2PermissionGrants?$top=999"
        )

    def classify_scope(self, scope):
        """Classify a scope by risk level."""
        for level, scopes in SCOPE_RISK.items():
            if scope in scopes:
                return level
        return "high"

    def build_permission_inventory(self):
        """Build complete OAuth permission inventory."""
        sps = self.get_service_principals()
        grants = self.get_oauth_grants()
        sp_map = {sp["id"]: sp for sp in sps}

        inventory = []
        for grant in grants:
            sp = sp_map.get(grant.get("clientId"), {})
            scopes = grant.get("scope", "").split()
            for scope in scopes:
                if not scope:
                    continue
                inventory.append({
                    "app_name": sp.get("displayName", "Unknown"),
                    "app_id": grant.get("clientId"),
                    "scope": scope,
                    "risk_level": self.classify_scope(scope),
                    "consent_type": grant.get("consentType"),
                    "is_third_party": sp.get("appOwnerOrganizationId") != self.tenant_id,
                    "is_enabled": sp.get("accountEnabled", True),
                })
        return inventory

    def find_over_permissioned(self, inventory, approved_scopes=None):
        """Find apps with excessive or unapproved scopes."""
        findings = []
        app_perms = defaultdict(list)
        for perm in inventory:
            app_perms[perm["app_name"]].append(perm)

        for app_name, perms in app_perms.items():
            critical = [p for p in perms if p["risk_level"] == "critical"]
            high = [p for p in perms if p["risk_level"] == "high"]

            if critical:
                findings.append({
                    "app_name": app_name,
                    "severity": "CRITICAL",
                    "finding": f"{len(critical)} critical scopes granted",
                    "critical_scopes": [p["scope"] for p in critical],
                    "is_third_party": perms[0].get("is_third_party", False),
                })
            elif len(high) > 3:
                findings.append({
                    "app_name": app_name,
                    "severity": "HIGH",
                    "finding": f"{len(high)} high-risk scopes granted",
                    "high_scopes": [p["scope"] for p in high],
                })
        return findings

    def find_broad_permissions(self, inventory):
        """Detect overly broad permissions that could be narrowed."""
        downgrades = [
            ("Mail.ReadWrite", "Mail.Read"),
            ("Files.ReadWrite.All", "Files.Read.All"),
            ("Directory.ReadWrite.All", "Directory.Read.All"),
            ("User.ReadWrite.All", "User.Read.All"),
        ]
        findings = []
        app_scopes = defaultdict(set)
        for perm in inventory:
            app_scopes[perm["app_name"]].add(perm["scope"])

        for app_name, scopes in app_scopes.items():
            for broad, narrow in downgrades:
                if broad in scopes:
                    findings.append({
                        "app_name": app_name,
                        "current_scope": broad,
                        "recommended_scope": narrow,
                        "recommendation": f"Downgrade from {broad} to {narrow}",
                    })
        return findings

    def generate_report(self):
        """Generate comprehensive OAuth scope review report."""
        inventory = self.build_permission_inventory()

        risk_counts = defaultdict(int)
        for perm in inventory:
            risk_counts[perm["risk_level"]] += 1

        third_party = [p for p in inventory if p.get("is_third_party")]

        report = {
            "tenant_id": self.tenant_id,
            "report_date": datetime.utcnow().isoformat(),
            "total_permissions": len(inventory),
            "risk_breakdown": dict(risk_counts),
            "third_party_permissions": len(third_party),
            "over_permissioned": self.find_over_permissioned(inventory),
            "broad_permissions": self.find_broad_permissions(inventory),
            "unique_apps": len(set(p["app_name"] for p in inventory)),
        }

        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 4:
        print("Usage: agent.py <tenant_id> <client_id> <client_secret>")
        sys.exit(1)

    tenant_id = sys.argv[1]
    client_id = sys.argv[2]
    client_secret = sys.argv[3]

    auditor = OAuthScopeAuditor(tenant_id, client_id, client_secret)
    auditor.generate_report()


if __name__ == "__main__":
    main()
