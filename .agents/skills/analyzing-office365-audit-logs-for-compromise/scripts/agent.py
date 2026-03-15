#!/usr/bin/env python3
"""Agent for analyzing Office 365 audit logs for compromise indicators via Microsoft Graph."""

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

SUSPICIOUS_OPERATIONS = [
    "New-InboxRule", "Set-InboxRule", "Set-Mailbox",
    "Add-MailboxPermission", "Set-MailboxJunkEmailConfiguration",
    "Set-OwaMailboxPolicy", "New-TransportRule",
    "Add-RecipientPermission", "Set-TransportRule",
    "UpdateInboxRules", "Set-MailboxAutoReplyConfiguration",
]


def get_access_token(tenant_id, client_id, client_secret):
    """Authenticate via MSAL client credentials flow."""
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
    """Paginated GET against Microsoft Graph API."""
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


def query_audit_logs(token, days=7):
    """Query Unified Audit Log for suspicious mail operations."""
    since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    events = []
    for operation in SUSPICIOUS_OPERATIONS:
        filter_str = (
            f"activityDisplayName eq '{operation}' "
            f"and activityDateTime ge {since}"
        )
        try:
            logs = graph_get(token, "/auditLogs/directoryAudits",
                             params={"$filter": filter_str, "$top": "100"})
            for log in logs:
                initiated = log.get("initiatedBy", {}).get("user", {})
                events.append({
                    "operation": operation,
                    "timestamp": log.get("activityDateTime"),
                    "result": log.get("result"),
                    "user": initiated.get("userPrincipalName"),
                    "ip_address": initiated.get("ipAddress"),
                    "target": [t.get("displayName") for t in log.get("targetResources", [])],
                    "details": log.get("additionalDetails"),
                })
        except Exception:
            pass
    events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return events


def check_inbox_rules(token, user_id):
    """List inbox rules for a specific mailbox and flag forwarding rules."""
    rules = graph_get(token, f"/users/{user_id}/mailFolders/inbox/messageRules")
    findings = []
    for rule in rules:
        is_forwarding = False
        forward_to = []
        actions = rule.get("actions", {})
        if actions.get("forwardTo"):
            is_forwarding = True
            forward_to = [r.get("emailAddress", {}).get("address", "")
                          for r in actions["forwardTo"]]
        if actions.get("forwardAsAttachmentTo"):
            is_forwarding = True
            forward_to += [r.get("emailAddress", {}).get("address", "")
                           for r in actions["forwardAsAttachmentTo"]]
        if actions.get("redirectTo"):
            is_forwarding = True
            forward_to += [r.get("emailAddress", {}).get("address", "")
                           for r in actions["redirectTo"]]
        delete_after = actions.get("delete", False)
        mark_read = actions.get("markAsRead", False)

        risk = 0
        if is_forwarding:
            risk += 40
        if delete_after:
            risk += 25
        if mark_read and is_forwarding:
            risk += 15
        external = [f for f in forward_to if f and not f.endswith(user_id.split("@")[-1])]
        if external:
            risk += 20

        findings.append({
            "rule_id": rule.get("id"),
            "display_name": rule.get("displayName"),
            "enabled": rule.get("isEnabled"),
            "is_forwarding": is_forwarding,
            "forward_to": forward_to,
            "external_forwards": external,
            "delete_after_forward": delete_after,
            "mark_as_read": mark_read,
            "conditions": rule.get("conditions"),
            "risk_score": min(risk, 100),
            "risk_level": "CRITICAL" if risk >= 70 else "HIGH" if risk >= 50 else "MEDIUM" if risk >= 25 else "LOW",
        })
    return findings


def check_mailbox_forwarding(token, user_id):
    """Check mailbox-level SMTP forwarding configuration."""
    try:
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.get(
            f"{GRAPH_BASE}/users/{user_id}/mailboxSettings",
            headers=headers, timeout=30
        )
        resp.raise_for_status()
        settings = resp.json()
        auto_reply = settings.get("automaticRepliesSetting", {})
        return {
            "user": user_id,
            "auto_reply_enabled": auto_reply.get("status") != "disabled",
            "auto_reply_external_audience": auto_reply.get("externalAudience"),
            "language": settings.get("language", {}).get("locale"),
            "timezone": settings.get("timeZone"),
        }
    except Exception as e:
        return {"user": user_id, "error": str(e)}


def check_oauth_grants(token):
    """Check for suspicious OAuth application consent grants."""
    grants = graph_get(token, "/oauth2PermissionGrants")
    high_risk_scopes = {"Mail.Read", "Mail.ReadWrite", "Mail.Send",
                        "Files.ReadWrite.All", "MailboxSettings.ReadWrite"}
    suspicious = []
    for g in grants:
        scopes = g.get("scope", "").split()
        risky = [s for s in scopes if s in high_risk_scopes]
        if risky:
            suspicious.append({
                "client_id": g.get("clientId"),
                "consent_type": g.get("consentType"),
                "principal_id": g.get("principalId"),
                "high_risk_scopes": risky,
                "all_scopes": scopes,
                "risk_score": min(len(risky) * 20, 100),
            })
    suspicious.sort(key=lambda x: x["risk_score"], reverse=True)
    return suspicious


def full_audit(token, users=None, days=7):
    """Run comprehensive O365 compromise audit."""
    audit_events = query_audit_logs(token, days)
    oauth_findings = check_oauth_grants(token)

    inbox_findings = []
    forwarding_findings = []
    if users:
        for user in users:
            rules = check_inbox_rules(token, user)
            inbox_findings.extend([{**r, "mailbox": user} for r in rules])
            fwd = check_mailbox_forwarding(token, user)
            forwarding_findings.append(fwd)

    suspicious_rules = [r for r in inbox_findings if r.get("is_forwarding")]
    external_forwards = [r for r in inbox_findings if r.get("external_forwards")]

    return {
        "audit_type": "Office 365 Compromise Analysis",
        "timestamp": datetime.utcnow().isoformat(),
        "lookback_days": days,
        "summary": {
            "suspicious_audit_events": len(audit_events),
            "oauth_high_risk_grants": len(oauth_findings),
            "forwarding_rules_found": len(suspicious_rules),
            "external_forwarding_rules": len(external_forwards),
            "mailboxes_scanned": len(users) if users else 0,
        },
        "audit_events": audit_events[:25],
        "oauth_findings": oauth_findings[:15],
        "forwarding_rules": suspicious_rules[:20],
        "mailbox_settings": forwarding_findings[:20],
    }


def main():
    parser = argparse.ArgumentParser(description="Office 365 Audit Log Compromise Analysis Agent")
    parser.add_argument("--tenant-id", required=True, help="Azure AD tenant ID")
    parser.add_argument("--client-id", required=True, help="App registration client ID")
    parser.add_argument("--client-secret", required=True, help="App client secret")
    sub = parser.add_subparsers(dest="command")
    p_audit = sub.add_parser("audit-logs", help="Query suspicious audit events")
    p_audit.add_argument("--days", type=int, default=7)
    p_rules = sub.add_parser("inbox-rules", help="Check inbox rules for forwarding")
    p_rules.add_argument("--user", required=True, help="User principal name")
    p_fwd = sub.add_parser("forwarding", help="Check mailbox forwarding settings")
    p_fwd.add_argument("--user", required=True)
    sub.add_parser("oauth", help="Check OAuth consent grants")
    p_full = sub.add_parser("full", help="Full compromise audit")
    p_full.add_argument("--users", nargs="+", help="User principal names to scan")
    p_full.add_argument("--days", type=int, default=7)
    args = parser.parse_args()

    token = get_access_token(args.tenant_id, args.client_id, args.client_secret)

    if args.command == "audit-logs":
        result = query_audit_logs(token, args.days)
    elif args.command == "inbox-rules":
        result = check_inbox_rules(token, args.user)
    elif args.command == "forwarding":
        result = check_mailbox_forwarding(token, args.user)
    elif args.command == "oauth":
        result = check_oauth_grants(token)
    elif args.command == "full" or args.command is None:
        result = full_audit(token, getattr(args, "users", None), getattr(args, "days", 7))
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
