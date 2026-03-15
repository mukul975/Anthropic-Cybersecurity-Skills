#!/usr/bin/env python3
"""Azure Lateral Movement Detection Agent - hunts for lateral movement in Azure AD/Entra ID."""

import json
import argparse
import logging
import requests
from collections import defaultdict
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

LATERAL_MOVEMENT_INDICATORS = {
    "oauth_consent_grant": {"mitre": "T1550.001", "severity": "high"},
    "service_principal_credential_add": {"mitre": "T1098.001", "severity": "critical"},
    "cross_tenant_signin": {"mitre": "T1078.004", "severity": "high"},
    "mailbox_delegation": {"mitre": "T1098.002", "severity": "high"},
    "token_replay": {"mitre": "T1528", "severity": "critical"},
    "conditional_access_bypass": {"mitre": "T1556.007", "severity": "critical"},
}


def get_graph_token(tenant_id, client_id, client_secret):
    """Authenticate to Microsoft Graph API via OAuth2 client credentials."""
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
    }
    resp = requests.post(url, data=data, timeout=30)
    resp.raise_for_status()
    return resp.json()["access_token"]


def query_audit_logs(token, hours=24):
    """Query Azure AD audit logs for suspicious directory changes."""
    since = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    url = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"
    headers = {"Authorization": f"Bearer {token}"}
    params = {"$filter": f"activityDateTime ge {since}", "$top": 500, "$orderby": "activityDateTime desc"}
    resp = requests.get(url, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json().get("value", [])


def query_signin_logs(token, hours=24):
    """Query Azure AD sign-in logs for anomalous authentication patterns."""
    since = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    url = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
    headers = {"Authorization": f"Bearer {token}"}
    params = {"$filter": f"createdDateTime ge {since}", "$top": 500}
    resp = requests.get(url, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json().get("value", [])


def detect_oauth_consent_abuse(audit_logs):
    """Detect suspicious OAuth application consent grants."""
    findings = []
    for log in audit_logs:
        activity = log.get("activityDisplayName", "")
        if "Consent to application" in activity:
            target = log.get("targetResources", [{}])[0]
            app_name = target.get("displayName", "")
            actor = log.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", "")
            findings.append({
                "indicator": "oauth_consent_grant", "actor": actor, "application": app_name,
                "timestamp": log.get("activityDateTime", ""),
                "severity": "high", "mitre": "T1550.001",
                "detail": f"OAuth consent granted to '{app_name}' by {actor}",
            })
    return findings


def detect_service_principal_changes(audit_logs):
    """Detect credential additions to service principals."""
    findings = []
    suspicious_ops = ["Add service principal credentials", "Add service principal",
                      "Add app role assignment to service principal"]
    for log in audit_logs:
        activity = log.get("activityDisplayName", "")
        if any(op in activity for op in suspicious_ops):
            actor = log.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", "unknown")
            target = log.get("targetResources", [{}])[0].get("displayName", "")
            findings.append({
                "indicator": "service_principal_credential_add", "actor": actor,
                "target_sp": target, "timestamp": log.get("activityDateTime", ""),
                "severity": "critical", "mitre": "T1098.001",
                "detail": f"Service principal '{target}' modified by {actor}",
            })
    return findings


def detect_cross_tenant_signins(signin_logs, home_tenant_id):
    """Detect sign-ins from external/unknown tenants."""
    findings = []
    for log in signin_logs:
        resource_tenant = log.get("resourceTenantId", "")
        if resource_tenant and resource_tenant != home_tenant_id:
            findings.append({
                "indicator": "cross_tenant_signin",
                "user": log.get("userPrincipalName", ""),
                "source_ip": log.get("ipAddress", ""),
                "resource_tenant": resource_tenant,
                "timestamp": log.get("createdDateTime", ""),
                "severity": "high", "mitre": "T1078.004",
            })
    return findings


def detect_token_replay(signin_logs):
    """Detect potential token replay by finding same user from multiple IPs in short windows."""
    user_sessions = defaultdict(list)
    for log in signin_logs:
        user = log.get("userPrincipalName", "")
        ip = log.get("ipAddress", "")
        ua = log.get("clientAppUsed", "")
        if user and ip:
            user_sessions[user].append({"ip": ip, "ua": ua, "time": log.get("createdDateTime", "")})
    findings = []
    for user, sessions in user_sessions.items():
        unique_ips = set(s["ip"] for s in sessions)
        if len(unique_ips) >= 5:
            findings.append({
                "indicator": "token_replay", "user": user,
                "unique_ips": len(unique_ips), "session_count": len(sessions),
                "severity": "critical", "mitre": "T1528",
                "detail": f"User {user} signed in from {len(unique_ips)} different IPs",
            })
    return findings


def generate_report(all_findings, hours):
    by_indicator = defaultdict(int)
    for f in all_findings:
        by_indicator[f["indicator"]] += 1
    critical = sum(1 for f in all_findings if f.get("severity") == "critical")
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "lookback_hours": hours,
        "total_findings": len(all_findings),
        "critical_findings": critical,
        "by_indicator": dict(by_indicator),
        "findings": all_findings,
        "risk_level": "critical" if critical > 0 else "high" if all_findings else "low",
    }


def main():
    parser = argparse.ArgumentParser(description="Azure AD Lateral Movement Detection Agent")
    parser.add_argument("--tenant-id", required=True, help="Azure AD tenant ID")
    parser.add_argument("--client-id", required=True, help="App registration client ID")
    parser.add_argument("--client-secret", required=True, help="App registration client secret")
    parser.add_argument("--hours", type=int, default=24, help="Lookback window in hours")
    parser.add_argument("--output", default="azure_lateral_movement_report.json")
    args = parser.parse_args()

    token = get_graph_token(args.tenant_id, args.client_id, args.client_secret)
    audit_logs = query_audit_logs(token, args.hours)
    signin_logs = query_signin_logs(token, args.hours)
    findings = []
    findings.extend(detect_oauth_consent_abuse(audit_logs))
    findings.extend(detect_service_principal_changes(audit_logs))
    findings.extend(detect_cross_tenant_signins(signin_logs, args.tenant_id))
    findings.extend(detect_token_replay(signin_logs))
    report = generate_report(findings, args.hours)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Azure lateral movement: %d findings (%d critical) in %dh window",
                report["total_findings"], report["critical_findings"], args.hours)
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
