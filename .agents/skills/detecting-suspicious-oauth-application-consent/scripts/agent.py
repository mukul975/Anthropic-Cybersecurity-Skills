#!/usr/bin/env python3
"""Agent for detecting suspicious OAuth application consent grants in Azure AD / Entra ID."""

import json
import argparse
from datetime import datetime, timedelta

try:
    import msal
except ImportError:
    msal = None

try:
    import requests
except ImportError:
    requests = None

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
HIGH_RISK_SCOPES = [
    "Mail.Read", "Mail.ReadWrite", "Mail.Send",
    "Files.ReadWrite.All", "Files.Read.All",
    "User.ReadWrite.All", "Directory.ReadWrite.All",
    "Sites.ReadWrite.All", "Contacts.ReadWrite",
    "MailboxSettings.ReadWrite", "People.Read.All",
    "Calendars.ReadWrite", "Notes.ReadWrite.All",
]


def get_access_token(tenant_id, client_id, client_secret):
    """Authenticate via MSAL client credentials flow and return access token."""
    if not msal:
        return None
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    app = msal.ConfidentialClientApplication(
        client_id, authority=authority, client_credential=client_secret
    )
    result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    if "access_token" in result:
        return result["access_token"]
    raise RuntimeError(f"Auth failed: {result.get('error_description', result.get('error'))}")


def graph_get(token, endpoint, params=None):
    """Make authenticated GET request to Microsoft Graph API."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    url = f"{GRAPH_BASE}{endpoint}"
    all_items = []
    while url:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        all_items.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
        params = None
    return all_items


def enumerate_oauth_grants(token):
    """List all delegated OAuth2 permission grants in the tenant."""
    grants = graph_get(token, "/oauth2PermissionGrants")
    results = []
    for g in grants:
        scope_list = g.get("scope", "").split()
        risky = [s for s in scope_list if s in HIGH_RISK_SCOPES]
        results.append({
            "id": g.get("id"),
            "clientId": g.get("clientId"),
            "consentType": g.get("consentType"),
            "principalId": g.get("principalId"),
            "resourceId": g.get("resourceId"),
            "scopes": scope_list,
            "high_risk_scopes": risky,
            "risk_score": len(risky) * 15,
        })
    return results


def list_service_principals(token):
    """List service principals with their app roles and permissions."""
    sps = graph_get(token, "/servicePrincipals", params={"$top": "999"})
    results = []
    for sp in sps:
        app_roles = sp.get("appRoles", [])
        verified = sp.get("verifiedPublisher", {})
        results.append({
            "id": sp.get("id"),
            "appId": sp.get("appId"),
            "displayName": sp.get("displayName"),
            "publisherName": sp.get("publisherName"),
            "verifiedPublisher": verified.get("displayName") if verified else None,
            "isVerified": bool(verified.get("verifiedPublisherId")),
            "appRoleCount": len(app_roles),
            "accountEnabled": sp.get("accountEnabled"),
            "signInAudience": sp.get("signInAudience"),
        })
    return results


def query_consent_audit_logs(token, days=30):
    """Query directory audit logs for consent grant events."""
    since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    filter_str = (
        f"activityDisplayName eq 'Consent to application' "
        f"and activityDateTime ge {since}"
    )
    logs = graph_get(token, "/auditLogs/directoryAudits", params={"$filter": filter_str})
    events = []
    for log in logs:
        initiated = log.get("initiatedBy", {}).get("user", {})
        targets = log.get("targetResources", [])
        events.append({
            "activityDateTime": log.get("activityDateTime"),
            "activityDisplayName": log.get("activityDisplayName"),
            "result": log.get("result"),
            "initiatedByUser": initiated.get("userPrincipalName"),
            "initiatedByIp": initiated.get("ipAddress"),
            "targetApp": targets[0].get("displayName") if targets else None,
            "targetAppId": targets[0].get("id") if targets else None,
            "additionalDetails": log.get("additionalDetails"),
        })
    return events


def analyze_risk(grants, service_principals):
    """Correlate grants with service principals to produce risk assessment."""
    sp_map = {sp["id"]: sp for sp in service_principals}
    findings = []
    for grant in grants:
        sp = sp_map.get(grant["clientId"], {})
        risk = grant["risk_score"]
        if not sp.get("isVerified"):
            risk += 25
        if grant.get("consentType") == "AllPrincipals":
            risk += 20
        risk = min(risk, 100)
        level = "CRITICAL" if risk >= 70 else "HIGH" if risk >= 50 else "MEDIUM" if risk >= 25 else "LOW"
        findings.append({
            "appDisplayName": sp.get("displayName", "Unknown"),
            "appId": sp.get("appId"),
            "publisherVerified": sp.get("isVerified", False),
            "consentType": grant.get("consentType"),
            "highRiskScopes": grant.get("high_risk_scopes"),
            "riskScore": risk,
            "riskLevel": level,
            "recommendation": "Revoke consent and investigate" if risk >= 50
                else "Review scopes and publisher" if risk >= 25
                else "Monitor",
        })
    findings.sort(key=lambda x: x["riskScore"], reverse=True)
    return findings


def full_audit(token, days=30):
    """Run comprehensive OAuth consent audit."""
    grants = enumerate_oauth_grants(token)
    sps = list_service_principals(token)
    audit_events = query_consent_audit_logs(token, days)
    risk_findings = analyze_risk(grants, sps)
    critical = sum(1 for f in risk_findings if f["riskLevel"] == "CRITICAL")
    high = sum(1 for f in risk_findings if f["riskLevel"] == "HIGH")
    unverified = sum(1 for sp in sps if not sp.get("isVerified"))
    return {
        "audit_type": "OAuth Application Consent Audit",
        "timestamp": datetime.utcnow().isoformat(),
        "summary": {
            "total_grants": len(grants),
            "total_service_principals": len(sps),
            "consent_events_last_n_days": len(audit_events),
            "critical_findings": critical,
            "high_findings": high,
            "unverified_publishers": unverified,
        },
        "risk_findings": risk_findings[:25],
        "recent_consent_events": audit_events[:20],
    }


def main():
    parser = argparse.ArgumentParser(description="OAuth Application Consent Audit Agent")
    parser.add_argument("--tenant-id", required=True, help="Azure AD tenant ID")
    parser.add_argument("--client-id", required=True, help="App registration client ID")
    parser.add_argument("--client-secret", required=True, help="App client secret")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("grants", help="Enumerate OAuth2 permission grants")
    sub.add_parser("apps", help="List service principals")
    sub.add_parser("audit-logs", help="Query consent audit logs")
    p_full = sub.add_parser("full", help="Full OAuth consent audit")
    p_full.add_argument("--days", type=int, default=30, help="Audit log lookback days")
    args = parser.parse_args()

    token = get_access_token(args.tenant_id, args.client_id, args.client_secret)

    if args.command == "grants":
        result = enumerate_oauth_grants(token)
    elif args.command == "apps":
        result = list_service_principals(token)
    elif args.command == "audit-logs":
        result = query_consent_audit_logs(token)
    elif args.command == "full":
        result = full_audit(token, args.days)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
