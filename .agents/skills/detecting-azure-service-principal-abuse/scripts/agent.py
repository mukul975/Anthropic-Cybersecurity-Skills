#!/usr/bin/env python3
"""Azure Service Principal abuse detection agent."""

import json
import sys
import argparse
from datetime import datetime, timedelta

try:
    from azure.identity import ClientSecretCredential
    from azure.mgmt.authorization import AuthorizationManagementClient
    from azure.graphrbac import GraphRbacManagementClient
except ImportError:
    ClientSecretCredential = None

try:
    import requests
except ImportError:
    print("Install: pip install requests")
    sys.exit(1)


class AzureGraphClient:
    """Client for Microsoft Graph API to audit service principals."""

    def __init__(self, tenant_id, client_id, client_secret):
        self.tenant_id = tenant_id
        self.token = self._get_token(tenant_id, client_id, client_secret)
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def _get_token(self, tenant_id, client_id, client_secret):
        resp = requests.post(
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://graph.microsoft.com/.default",
            },
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def _get(self, endpoint, params=None):
        resp = requests.get(f"https://graph.microsoft.com/v1.0{endpoint}",
                            headers=self.headers, params=params, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def list_service_principals(self):
        return self._get("/servicePrincipals", params={"$top": 200}).get("value", [])

    def get_sp_credentials(self, sp_id):
        return self._get(f"/servicePrincipals/{sp_id}").get("passwordCredentials", [])

    def get_sp_app_roles(self, sp_id):
        return self._get(f"/servicePrincipals/{sp_id}/appRoleAssignments").get("value", [])

    def get_sign_in_logs(self, sp_id, days=7):
        since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        return self._get("/auditLogs/signIns", params={
            "$filter": f"appId eq '{sp_id}' and createdDateTime ge {since}",
            "$top": 100,
        }).get("value", [])

    def get_directory_roles(self):
        return self._get("/directoryRoles").get("value", [])

    def get_role_members(self, role_id):
        return self._get(f"/directoryRoles/{role_id}/members").get("value", [])


def audit_credential_expiry(client, principals):
    """Check for expired or soon-to-expire service principal credentials."""
    findings = []
    now = datetime.utcnow()
    for sp in principals:
        sp_id = sp.get("id", "")
        display = sp.get("displayName", "")
        creds = sp.get("passwordCredentials", [])
        key_creds = sp.get("keyCredentials", [])

        for cred in creds + key_creds:
            end_str = cred.get("endDateTime", "")
            if not end_str:
                continue
            try:
                end = datetime.fromisoformat(end_str.rstrip("Z"))
            except ValueError:
                continue

            if end < now:
                findings.append({
                    "sp_name": display, "sp_id": sp_id,
                    "credential_id": cred.get("keyId", ""),
                    "issue": "Credential expired but not removed",
                    "severity": "MEDIUM", "expired": end_str,
                })
            elif end < now + timedelta(days=30):
                findings.append({
                    "sp_name": display, "sp_id": sp_id,
                    "issue": f"Credential expires within 30 days ({end_str})",
                    "severity": "LOW",
                })

        if len(creds) > 2:
            findings.append({
                "sp_name": display, "sp_id": sp_id,
                "issue": f"Multiple password credentials ({len(creds)}) — possible backdoor",
                "severity": "HIGH",
            })

    return findings


def audit_privileged_sp_roles(client):
    """Find service principals with high-privilege directory roles."""
    findings = []
    high_priv_roles = {
        "Global Administrator", "Application Administrator",
        "Cloud Application Administrator", "Privileged Role Administrator",
    }
    roles = client.get_directory_roles()
    for role in roles:
        role_name = role.get("displayName", "")
        if role_name not in high_priv_roles:
            continue
        members = client.get_role_members(role["id"])
        for m in members:
            if m.get("@odata.type") == "#microsoft.graph.servicePrincipal":
                findings.append({
                    "sp_name": m.get("displayName", ""),
                    "sp_id": m.get("id", ""),
                    "role": role_name,
                    "issue": f"Service principal has {role_name} role",
                    "severity": "CRITICAL",
                })
    return findings


def run_audit(args):
    """Execute Azure service principal abuse detection audit."""
    print(f"\n{'='*60}")
    print(f"  AZURE SERVICE PRINCIPAL ABUSE DETECTION")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    client = AzureGraphClient(args.tenant_id, args.client_id, args.client_secret)
    report = {}

    principals = client.list_service_principals()
    report["total_service_principals"] = len(principals)
    print(f"--- SERVICE PRINCIPALS ({len(principals)}) ---")
    for sp in principals[:10]:
        print(f"  {sp.get('displayName','')}: {sp.get('appId','')[:20]}...")

    cred_findings = audit_credential_expiry(client, principals)
    report["credential_findings"] = cred_findings
    print(f"\n--- CREDENTIAL AUDIT ({len(cred_findings)} findings) ---")
    for f in cred_findings[:15]:
        print(f"  [{f['severity']}] {f['sp_name']}: {f['issue']}")

    role_findings = audit_privileged_sp_roles(client)
    report["privileged_role_findings"] = role_findings
    print(f"\n--- PRIVILEGED ROLE ASSIGNMENTS ({len(role_findings)}) ---")
    for f in role_findings:
        print(f"  [{f['severity']}] {f['sp_name']}: {f['role']}")

    return report


def main():
    parser = argparse.ArgumentParser(description="Azure SP Abuse Detection Agent")
    parser.add_argument("--tenant-id", required=True, help="Azure AD tenant ID")
    parser.add_argument("--client-id", required=True, help="App registration client ID")
    parser.add_argument("--client-secret", required=True, help="App registration secret")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
