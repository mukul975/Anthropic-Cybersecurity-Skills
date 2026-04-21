---
name: analyzing-office365-audit-logs-for-compromise
description: Parse Office 365 Unified Audit Logs via Microsoft Graph API to detect email forwarding rule creation, inbox delegation,
  suspicious OAuth app grants, and other indicators of account compromise.
domain: cybersecurity
subdomain: cloud-security
tags:
- Office365
- Microsoft-Graph
- audit-logs
- email-compromise
- inbox-rules
- OAuth
- BEC
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
---

# Analyzing Office 365 Audit Logs for Compromise

## Overview

Business Email Compromise (BEC) attacks often leave traces in Office 365 audit logs: suspicious inbox rule creation, email forwarding to external addresses, mailbox delegation changes, and unauthorized OAuth application consent grants. This skill uses the Microsoft Graph API to query the Unified Audit Log, enumerate inbox rules across mailboxes, detect forwarding configurations, and identify compromised account indicators.


## When to Use

- When investigating a suspected Business Email Compromise (BEC) or account takeover in an Office 365 tenant
- When a user reports unexpected email activity (missing emails, unknown forwarding rules, unauthorized sent items)
- When threat hunting for lateral movement through mailbox delegation or OAuth consent grants in a Microsoft 365 environment
- When building automated monitoring for O365 compromise indicators as part of a SIEM integration

**Do not use** for real-time alerting on sign-in events; use Microsoft Sentinel or Azure AD Identity Protection for sub-minute detection.

## Prerequisites

- Azure AD app registration with `AuditLog.Read.All`, `MailboxSettings.Read`, `Mail.Read` (application permissions)
- Python 3.9+ with `msal`, `requests` libraries (`pip install msal requests`)
- Client secret or certificate for app authentication
- Global Reader or Security Reader role assigned to the service principal

## Workflow

### Step 1: Authenticate to Microsoft Graph Using MSAL

```python
import msal
import requests

TENANT_ID = "your-tenant-id"
CLIENT_ID = "your-client-id"
CLIENT_SECRET = "your-client-secret"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"

def get_access_token() -> str:
    """Acquire a bearer token using client credentials flow."""
    authority = f"https://login.microsoftonline.com/{TENANT_ID}"
    app = msal.ConfidentialClientApplication(
        CLIENT_ID,
        authority=authority,
        client_credential=CLIENT_SECRET,
    )
    result = app.acquire_token_for_client(
        scopes=["https://graph.microsoft.com/.default"]
    )
    if "access_token" not in result:
        raise RuntimeError(f"Auth failed: {result.get('error_description')}")
    return result["access_token"]

token = get_access_token()
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
```

### Step 2: Query the Unified Audit Log for Suspicious Operations

```python
from datetime import datetime, timedelta, timezone
import json

SUSPICIOUS_OPERATIONS = [
    "Set-Mailbox",             # Forwarding rule changes
    "New-InboxRule",           # New inbox rules (hide/redirect/delete)
    "Set-InboxRule",           # Modified inbox rules
    "Add-MailboxPermission",   # Mailbox delegation granted
    "Add-RecipientPermission", # Send-as delegation
]

def query_audit_log(operations: list[str], days_back: int = 7) -> list[dict]:
    """Query the Unified Audit Log for specified operations."""
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days_back)

    findings = []
    for operation in operations:
        url = (
            f"{GRAPH_BETA}/security/auditLog/queries"
        )
        payload = {
            "displayName": f"NLPM audit: {operation}",
            "filterStartDateTime": start_time.isoformat(),
            "filterEndDateTime": end_time.isoformat(),
            "operationFilters": [operation],
        }
        resp = requests.post(url, headers=headers, json=payload)
        resp.raise_for_status()
        query_id = resp.json()["id"]

        # Poll for results (audit queries are async)
        result_url = f"{GRAPH_BETA}/security/auditLog/queries/{query_id}/records"
        resp = requests.get(result_url, headers=headers)
        resp.raise_for_status()
        records = resp.json().get("value", [])
        findings.extend(records)
        print(f"  {operation}: {len(records)} records")

    return findings

audit_records = query_audit_log(SUSPICIOUS_OPERATIONS, days_back=7)
print(f"Total suspicious audit records: {len(audit_records)}")
```

### Step 3: Enumerate Inbox Rules Across Mailboxes

```python
def get_inbox_rules(user_upn: str) -> list[dict]:
    """Retrieve inbox rules for a specific mailbox."""
    url = f"{GRAPH_BASE}/users/{user_upn}/mailFolders/inbox/messageRules"
    resp = requests.get(url, headers=headers)
    if resp.status_code == 403:
        return []  # No permission for this mailbox
    resp.raise_for_status()
    return resp.json().get("value", [])

def flag_suspicious_rules(rules: list[dict], user_upn: str) -> list[dict]:
    """Flag inbox rules that indicate compromise or data exfiltration."""
    suspicious = []
    for rule in rules:
        conditions = rule.get("conditions", {})
        actions = rule.get("actions", {})
        flags = []

        # Forwarding to external address
        if actions.get("forwardTo") or actions.get("redirectTo"):
            recipients = actions.get("forwardTo", []) + actions.get("redirectTo", [])
            external = [r for r in recipients if not r.get("emailAddress", {}).get("address", "").endswith(TENANT_DOMAIN)]
            if external:
                flags.append(f"EXTERNAL_FORWARD to {[r['emailAddress']['address'] for r in external]}")

        # Rule that deletes or marks messages read (cover-up pattern)
        if actions.get("delete") or actions.get("permanentDelete"):
            flags.append("AUTO_DELETE")
        if actions.get("markAsRead") and (actions.get("moveToFolder") or actions.get("delete")):
            flags.append("MARK_READ_AND_HIDE")

        if flags:
            suspicious.append({"user": user_upn, "rule_name": rule.get("displayName"), "flags": flags, "rule": rule})

    return suspicious

TENANT_DOMAIN = "example.com"  # Replace with actual tenant domain

# Enumerate a list of at-risk users (e.g., from prior audit log hits)
at_risk_users = list({r.get("userPrincipalName") for r in audit_records if r.get("userPrincipalName")})
all_suspicious_rules = []
for upn in at_risk_users:
    rules = get_inbox_rules(upn)
    all_suspicious_rules.extend(flag_suspicious_rules(rules, upn))

print(f"Suspicious inbox rules found: {len(all_suspicious_rules)}")
```

### Step 4: Detect OAuth Consent Grants to Suspicious Applications

```python
def get_oauth_grants() -> list[dict]:
    """List OAuth2 permission grants in the tenant."""
    url = f"{GRAPH_BASE}/oauth2PermissionGrants?$top=999"
    grants = []
    while url:
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        grants.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
    return grants

SENSITIVE_SCOPES = {"Mail.Read", "Mail.ReadWrite", "MailboxSettings.ReadWrite", "Contacts.Read", "Files.Read.All"}

def flag_suspicious_grants(grants: list[dict]) -> list[dict]:
    suspicious = []
    for grant in grants:
        scopes = set(grant.get("scope", "").split())
        risky = scopes & SENSITIVE_SCOPES
        if risky:
            suspicious.append({
                "client_id": grant.get("clientId"),
                "principal_id": grant.get("principalId"),
                "risky_scopes": list(risky),
                "consent_type": grant.get("consentType"),
            })
    return suspicious

oauth_findings = flag_suspicious_grants(get_oauth_grants())
print(f"Suspicious OAuth grants: {len(oauth_findings)}")
```

### Step 5: Build Compromise Indicator Report with Timeline

```python
report = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "period_days": 7,
    "summary": {
        "suspicious_audit_operations": len(audit_records),
        "suspicious_inbox_rules": len(all_suspicious_rules),
        "risky_oauth_grants": len(oauth_findings),
    },
    "inbox_rule_findings": all_suspicious_rules,
    "oauth_findings": oauth_findings,
    "audit_log_records": [
        {
            "operation": r.get("operation"),
            "user": r.get("userPrincipalName"),
            "timestamp": r.get("createdDateTime"),
            "ip": r.get("auditData", {}).get("ClientIP"),
        }
        for r in audit_records
    ],
}

with open("o365_compromise_report.json", "w") as f:
    json.dump(report, f, indent=2)

print(json.dumps(report["summary"], indent=2))
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Unified Audit Log (UAL)** | Microsoft 365 audit trail covering Exchange, SharePoint, Teams, and Azure AD events; retention is 90 days (standard) or 1 year (E5) |
| **Business Email Compromise (BEC)** | Social engineering attack where adversaries compromise or impersonate executive email accounts to redirect payments or extract data |
| **Inbox rule forwarding** | Exchange transport rule created in a mailbox to silently forward or redirect all incoming mail to an external address |
| **Mailbox delegation** | `Add-MailboxPermission` grants a third party Full Access or Send-As permission to a mailbox — a persistence mechanism after compromise |
| **OAuth consent grant** | Authorization token granted by a user to a third-party application for specific Microsoft Graph scopes; attacker-registered apps use this for persistent mail access |
| **MSAL client credentials flow** | OAuth 2.0 flow for daemon/service authentication using a client ID and secret; no user interaction required; returns an app-level token |
| **Microsoft Graph beta endpoint** | `/beta` API surface for features not yet in v1.0, including the audit log query API; subject to breaking changes |

## Tools & Systems

- **msal**: Microsoft Authentication Library for Python; handles token acquisition and refresh for Graph API access
- **Microsoft Graph API**: REST API for Microsoft 365 services including mailboxes, audit logs, and identity data
- **Microsoft Sentinel**: Cloud-native SIEM that ingests Microsoft 365 audit logs for real-time correlation and alerting
- **Hawk (PowerShell)**: Open-source O365 incident response tool for bulk extraction of audit log, mailbox rules, and sign-in data

## Common Scenarios

### Scenario: Investigating a BEC Incident After Finance Alert

**Context**: Finance reports receiving an email from the CFO requesting a wire transfer, but the CFO's account shows no record of sending it. Investigate whether the CFO's mailbox was compromised.

**Approach**:
1. Query the audit log for `Set-Mailbox` and `New-InboxRule` operations on the CFO's account for the past 30 days
2. Enumerate all inbox rules on the CFO's mailbox — look for forwarding rules created around the time of the suspicious email
3. Check for `Add-MailboxPermission` events granting a third party access to the CFO mailbox
4. Retrieve sign-in logs from Azure AD (`signIns` Graph endpoint) for the account and flag logins from unusual IPs or countries
5. Check for OAuth consent grants to unfamiliar apps with `Mail.Read` or `Mail.ReadWrite` scopes
6. Preserve the audit log records and export to JSON before the 90-day retention window closes

**Pitfalls**:
- Audit log availability depends on Microsoft 365 license tier; E3 tenants may lack some UAL record types — verify with `Get-AdminAuditLogConfig` in Exchange PowerShell
- Graph API audit log queries are asynchronous; poll the query status endpoint until `status == "succeeded"` before retrieving records

### Scenario: Tenant-Wide Sweep for Persistent OAuth Backdoors

**Context**: A threat intelligence report indicates adversaries in the sector are registering malicious OAuth apps to maintain persistent mailbox access after passwords are reset.

**Approach**:
1. Enumerate all OAuth2 permission grants in the tenant
2. Flag any grant with `Mail.Read`, `Mail.ReadWrite`, or `MailboxSettings.ReadWrite` scopes
3. For each flagged grant, look up the `clientId` in Azure AD application list — flag apps with no publisher verification, no privacy URL, or recently registered
4. Cross-reference the `principalId` of each risky grant against the list of executives and finance staff
5. Revoke suspicious grants via `DELETE /oauth2PermissionGrants/{id}` and disable the app registration

**Pitfalls**:
- `consentType == "AllPrincipals"` means an admin granted tenant-wide consent; these are harder to revoke because they apply to all users simultaneously
- Legitimate SaaS integrations (CRM, archiving tools) will appear in the grant list; build an allowlist of known-good `clientId` values before flagging

## Output Format

```
O365 COMPROMISE INDICATOR REPORT
===================================
Generated:          2025-10-20T11:45:00Z
Period:             7 days
Tenant:             example.com

SUMMARY
Suspicious audit operations:   4
Suspicious inbox rules:         2
Risky OAuth grants:             1

INBOX RULE FINDINGS
User                        Rule Name           Flags
cfo@example.com             "Archive"           EXTERNAL_FORWARD to [attacker@protonmail.com]
finance@example.com         "Auto-process"      AUTO_DELETE, MARK_READ_AND_HIDE

OAUTH GRANT FINDINGS
Client ID                               Principal             Risky Scopes
a1b2c3d4-...                            cfo@example.com       Mail.Read, Mail.ReadWrite
(App: "Super Invoice Helper", unverified publisher, registered 2025-10-15)

AUDIT LOG RECORDS (suspicious operations)
Timestamp               Operation          User                    Source IP
2025-10-18T09:12:00Z    New-InboxRule      cfo@example.com         185.220.101.5
2025-10-18T09:14:00Z    Set-Mailbox        cfo@example.com         185.220.101.5
2025-10-19T14:30:00Z    Add-MailboxPerm    svc-backup@example.com  10.0.1.15
2025-10-19T14:35:00Z    Set-InboxRule      finance@example.com     203.0.113.42

Report saved to: o365_compromise_report.json
```
