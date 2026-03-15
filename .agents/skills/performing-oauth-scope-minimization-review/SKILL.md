---
name: performing-oauth-scope-minimization-review
description: >
  Performs OAuth 2.0 scope minimization review to identify over-permissioned third-party
  application integrations, excessive API scopes, unused token grants, and risky OAuth
  consent patterns across identity providers and SaaS platforms.
  Activates for requests involving OAuth scope audit, API permission review, third-party
  app risk assessment, or consent grant minimization.
domain: cybersecurity
subdomain: identity-access-management
tags: [OAuth, scope-minimization, API-security, consent-review, third-party-risk, token-audit]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing OAuth Scope Minimization Review

## When to Use

- Annual or quarterly review of third-party application OAuth permissions
- After a security incident involving compromised OAuth tokens or unauthorized data access
- Compliance audit requiring documentation of third-party data access (GDPR Article 28, SOC 2)
- Discovery of shadow IT applications accessing organizational data via OAuth grants
- Migration or consolidation of SaaS applications requiring permission cleanup
- Implementing least-privilege principle for API integrations

**Do not use** for reviewing first-party application permissions within the same trust boundary; OAuth scope minimization focuses on third-party and cross-boundary consent grants.

## Prerequisites

- Admin access to identity providers (Microsoft Entra ID, Okta, Google Workspace)
- Microsoft Graph API permissions: Application.Read.All, OAuth2PermissionGrant.ReadWrite.All
- Inventory of approved third-party integrations from procurement or IT governance
- OAuth scope risk classification framework
- Tools for token analysis (jwt.io for manual review, automated scripts for bulk analysis)

## Workflow

### Step 1: Inventory All OAuth Grants and Consent Permissions

Enumerate all OAuth application registrations and delegated permissions:

```python
"""
OAuth Grant Inventory - Microsoft Entra ID
Enumerates all application registrations, service principals,
and delegated/application permission grants.
"""
import requests
import json
from collections import defaultdict

class EntraOAuthAuditor:
    def __init__(self, tenant_id, client_id, client_secret):
        self.tenant_id = tenant_id
        self.base_url = "https://graph.microsoft.com/v1.0"
        self.token = self._get_token(client_id, client_secret)
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def _get_token(self, client_id, client_secret):
        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        response = requests.post(url, data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://graph.microsoft.com/.default"
        })
        return response.json()["access_token"]

    def get_all_service_principals(self):
        """Get all service principals (enterprise applications)."""
        apps = []
        url = f"{self.base_url}/servicePrincipals?$top=999&$select=id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,accountEnabled,createdDateTime"

        while url:
            response = requests.get(url, headers=self.headers)
            data = response.json()
            apps.extend(data.get("value", []))
            url = data.get("@odata.nextLink")

        return apps

    def get_oauth2_permission_grants(self):
        """Get all delegated permission grants (user consent)."""
        grants = []
        url = f"{self.base_url}/oauth2PermissionGrants?$top=999"

        while url:
            response = requests.get(url, headers=self.headers)
            data = response.json()
            grants.extend(data.get("value", []))
            url = data.get("@odata.nextLink")

        return grants

    def get_app_role_assignments(self, sp_id):
        """Get application permission assignments for a service principal."""
        url = f"{self.base_url}/servicePrincipals/{sp_id}/appRoleAssignments"
        response = requests.get(url, headers=self.headers)
        return response.json().get("value", [])

    def build_permission_inventory(self):
        """Build comprehensive OAuth permission inventory."""
        service_principals = self.get_all_service_principals()
        delegated_grants = self.get_oauth2_permission_grants()

        # Map service principal IDs to names
        sp_map = {sp["id"]: sp for sp in service_principals}

        inventory = []

        # Process delegated permissions
        for grant in delegated_grants:
            sp = sp_map.get(grant["clientId"], {})
            scopes = grant.get("scope", "").split()

            for scope in scopes:
                if not scope:
                    continue
                inventory.append({
                    "app_name": sp.get("displayName", "Unknown"),
                    "app_id": grant.get("clientId"),
                    "publisher_tenant": sp.get("appOwnerOrganizationId"),
                    "is_third_party": sp.get("appOwnerOrganizationId") != self.tenant_id,
                    "permission_type": "Delegated",
                    "scope": scope,
                    "consent_type": grant.get("consentType"),  # AllPrincipals or Principal
                    "principal_id": grant.get("principalId"),
                    "granted_date": sp.get("createdDateTime"),
                    "is_enabled": sp.get("accountEnabled", True)
                })

        # Process application permissions
        for sp in service_principals:
            app_roles = self.get_app_role_assignments(sp["id"])
            for role in app_roles:
                inventory.append({
                    "app_name": sp.get("displayName"),
                    "app_id": sp.get("id"),
                    "publisher_tenant": sp.get("appOwnerOrganizationId"),
                    "is_third_party": sp.get("appOwnerOrganizationId") != self.tenant_id,
                    "permission_type": "Application",
                    "scope": role.get("appRoleId"),
                    "consent_type": "AdminConsent",
                    "granted_date": role.get("createdDateTime"),
                    "is_enabled": sp.get("accountEnabled", True)
                })

        return inventory
```

### Step 2: Classify OAuth Scopes by Risk Level

Categorize permissions based on data access sensitivity:

```python
"""
OAuth Scope Risk Classification
Maps API scopes to risk levels based on data sensitivity and access breadth.
"""

MICROSOFT_GRAPH_SCOPE_RISK = {
    # CRITICAL - Full administrative or unrestricted access
    "critical": {
        "scopes": [
            "Directory.ReadWrite.All",
            "RoleManagement.ReadWrite.Directory",
            "Application.ReadWrite.All",
            "AppRoleAssignment.ReadWrite.All",
            "Mail.ReadWrite",
            "Mail.Send",
            "Files.ReadWrite.All",
            "Sites.FullControl.All",
            "User.ReadWrite.All",
            "Group.ReadWrite.All",
            "MailboxSettings.ReadWrite",
            "full_access_as_app",
        ],
        "risk_description": "Can read/write all data, modify directory, or impersonate users",
        "review_frequency": "Monthly",
        "requires_admin_consent": True
    },
    # HIGH - Broad read access or sensitive data write
    "high": {
        "scopes": [
            "Mail.Read",
            "Mail.Read.Shared",
            "Calendars.ReadWrite",
            "Contacts.ReadWrite",
            "Files.Read.All",
            "Sites.Read.All",
            "User.Read.All",
            "Group.Read.All",
            "Directory.Read.All",
            "AuditLog.Read.All",
            "SecurityEvents.ReadWrite.All",
            "TeamSettings.ReadWrite.All",
        ],
        "risk_description": "Broad read access to sensitive organizational data",
        "review_frequency": "Quarterly",
        "requires_admin_consent": True
    },
    # MEDIUM - Scoped data access
    "medium": {
        "scopes": [
            "Calendars.Read",
            "Contacts.Read",
            "Files.ReadWrite",
            "Sites.ReadWrite.All",
            "Tasks.ReadWrite",
            "Notes.ReadWrite.All",
            "Chat.ReadWrite",
            "ChannelMessage.Send",
            "Team.ReadBasic.All",
        ],
        "risk_description": "Scoped access to specific data types with write capability",
        "review_frequency": "Semi-annually"
    },
    # LOW - Minimal or user-profile only access
    "low": {
        "scopes": [
            "User.Read",
            "openid",
            "profile",
            "email",
            "offline_access",
            "Calendars.Read.Shared",
            "People.Read",
            "User.ReadBasic.All",
        ],
        "risk_description": "Basic user profile or minimal scoped access",
        "review_frequency": "Annually"
    }
}

def classify_scope_risk(scope):
    """Classify a single OAuth scope by risk level."""
    for risk_level, config in MICROSOFT_GRAPH_SCOPE_RISK.items():
        if scope in config["scopes"]:
            return {
                "scope": scope,
                "risk_level": risk_level,
                "description": config["risk_description"],
                "review_frequency": config["review_frequency"]
            }
    # Unknown scopes default to HIGH risk
    return {
        "scope": scope,
        "risk_level": "high",
        "description": "Unknown scope - requires manual classification",
        "review_frequency": "Quarterly"
    }

def analyze_app_risk(app_permissions):
    """Calculate aggregate risk score for an application's permissions."""
    risk_weights = {"critical": 40, "high": 20, "medium": 10, "low": 2}
    total_score = 0
    classified_scopes = []

    for perm in app_permissions:
        classification = classify_scope_risk(perm["scope"])
        classified_scopes.append(classification)
        total_score += risk_weights.get(classification["risk_level"], 10)

    # Bonus risk for application (vs delegated) permissions
    app_type_permissions = [p for p in app_permissions if p["permission_type"] == "Application"]
    total_score += len(app_type_permissions) * 15

    # Bonus risk for admin-consented broad access
    admin_consent = [p for p in app_permissions if p["consent_type"] == "AllPrincipals"]
    total_score += len(admin_consent) * 10

    if total_score >= 100:
        aggregate_risk = "CRITICAL"
    elif total_score >= 60:
        aggregate_risk = "HIGH"
    elif total_score >= 30:
        aggregate_risk = "MEDIUM"
    else:
        aggregate_risk = "LOW"

    return {
        "total_score": total_score,
        "aggregate_risk": aggregate_risk,
        "scope_count": len(app_permissions),
        "critical_scopes": len([s for s in classified_scopes if s["risk_level"] == "critical"]),
        "high_scopes": len([s for s in classified_scopes if s["risk_level"] == "high"]),
        "classified_scopes": classified_scopes
    }
```

### Step 3: Identify Over-Permissioned Applications

Detect apps requesting more permissions than functionally needed:

```python
"""
Over-Permission Detection
Identifies applications with excessive OAuth scopes relative to their function.
"""

def detect_over_permissions(inventory, approved_apps_catalog):
    """
    Compare actual permissions against approved scope catalog
    to find over-permissioned applications.
    """
    findings = []

    # Group permissions by application
    app_permissions = defaultdict(list)
    for perm in inventory:
        app_permissions[perm["app_name"]].append(perm)

    for app_name, permissions in app_permissions.items():
        # Check against approved catalog
        approved = approved_apps_catalog.get(app_name)

        if not approved:
            # Unknown/unapproved application
            findings.append({
                "app_name": app_name,
                "finding_type": "UNAPPROVED_APPLICATION",
                "severity": "HIGH",
                "detail": f"Application not in approved catalog with {len(permissions)} permission grants",
                "scopes": [p["scope"] for p in permissions],
                "recommendation": "Review and approve or revoke all permissions"
            })
            continue

        approved_scopes = set(approved.get("approved_scopes", []))
        actual_scopes = set(p["scope"] for p in permissions)

        # Find excessive scopes (granted but not approved)
        excessive = actual_scopes - approved_scopes
        if excessive:
            risk = analyze_app_risk([p for p in permissions if p["scope"] in excessive])
            findings.append({
                "app_name": app_name,
                "finding_type": "EXCESSIVE_SCOPES",
                "severity": risk["aggregate_risk"],
                "detail": f"{len(excessive)} scopes beyond approved list",
                "excessive_scopes": list(excessive),
                "approved_scopes": list(approved_scopes),
                "recommendation": "Remove excessive scopes or update approved catalog"
            })

        # Find unused scopes (approved but activity logs show no API calls)
        # This requires API activity log correlation
        unused = approved_scopes - actual_scopes
        if unused:
            findings.append({
                "app_name": app_name,
                "finding_type": "UNUSED_APPROVED_SCOPES",
                "severity": "LOW",
                "detail": f"{len(unused)} approved scopes not currently granted",
                "unused_scopes": list(unused)
            })

        # Check for overly broad permissions
        broad_patterns = [
            ("Mail.ReadWrite", "Mail.Read", "Write access to mail when only read needed"),
            ("Files.ReadWrite.All", "Files.Read.All", "Write access to all files when only read needed"),
            ("Directory.ReadWrite.All", "Directory.Read.All", "Write access to directory when only read needed"),
            ("User.ReadWrite.All", "User.Read.All", "Write access to users when only read needed"),
        ]

        for broad, narrow, description in broad_patterns:
            if broad in actual_scopes:
                findings.append({
                    "app_name": app_name,
                    "finding_type": "OVERLY_BROAD_SCOPE",
                    "severity": "MEDIUM",
                    "detail": description,
                    "current_scope": broad,
                    "recommended_scope": narrow,
                    "recommendation": f"Downgrade from {broad} to {narrow}"
                })

    return findings
```

### Step 4: Audit Token Usage and Detect Stale Grants

Identify OAuth tokens that are no longer actively used:

```python
"""
Token Usage Audit
Analyzes sign-in logs and API activity to identify stale OAuth grants.
"""

def audit_token_usage(auditor, days_inactive=90):
    """Identify OAuth grants with no recent API activity."""
    # Get sign-in activity for service principals
    url = f"{auditor.base_url}/auditLogs/signIns"
    params = {
        "$filter": f"createdDateTime ge {(datetime.utcnow() - timedelta(days=days_inactive)).isoformat()}Z and signInEventTypes/any(t: t eq 'servicePrincipal')",
        "$top": 999
    }

    active_apps = set()
    while url:
        response = requests.get(url, headers=auditor.headers, params=params)
        data = response.json()
        for signin in data.get("value", []):
            active_apps.add(signin.get("appId"))
        url = data.get("@odata.nextLink")
        params = {}

    # Compare against all granted apps
    all_grants = auditor.get_oauth2_permission_grants()
    sp_map = {sp["id"]: sp for sp in auditor.get_all_service_principals()}

    stale_grants = []
    for grant in all_grants:
        sp = sp_map.get(grant["clientId"], {})
        app_id = sp.get("appId")

        if app_id and app_id not in active_apps:
            stale_grants.append({
                "app_name": sp.get("displayName", "Unknown"),
                "app_id": app_id,
                "scopes": grant.get("scope", "").split(),
                "consent_type": grant.get("consentType"),
                "is_third_party": sp.get("appOwnerOrganizationId") != auditor.tenant_id,
                "days_inactive": days_inactive,
                "recommendation": "Revoke - no API activity in {days_inactive} days"
            })

    return sorted(stale_grants, key=lambda x: len(x["scopes"]), reverse=True)
```

### Step 5: Generate Remediation Plan and Execute Scope Reduction

Create and execute the scope minimization remediation plan:

```python
"""
OAuth Scope Remediation
Generates and executes scope reduction actions.
"""

def generate_remediation_plan(findings, stale_grants):
    """Create prioritized remediation plan."""
    plan = []

    # Priority 1: Revoke unapproved applications
    for f in findings:
        if f["finding_type"] == "UNAPPROVED_APPLICATION":
            plan.append({
                "priority": 1,
                "action": "REVOKE_ALL_PERMISSIONS",
                "app_name": f["app_name"],
                "reason": "Unapproved third-party application",
                "impact": f"Removes {len(f['scopes'])} permission grants",
                "risk_if_not_addressed": "CRITICAL"
            })

    # Priority 2: Remove excessive scopes from approved apps
    for f in findings:
        if f["finding_type"] == "EXCESSIVE_SCOPES":
            plan.append({
                "priority": 2,
                "action": "REMOVE_EXCESSIVE_SCOPES",
                "app_name": f["app_name"],
                "scopes_to_remove": f["excessive_scopes"],
                "reason": "Scopes beyond approved catalog",
                "risk_if_not_addressed": f["severity"]
            })

    # Priority 3: Downgrade overly broad scopes
    for f in findings:
        if f["finding_type"] == "OVERLY_BROAD_SCOPE":
            plan.append({
                "priority": 3,
                "action": "DOWNGRADE_SCOPE",
                "app_name": f["app_name"],
                "current_scope": f["current_scope"],
                "target_scope": f["recommended_scope"],
                "reason": f["detail"],
                "risk_if_not_addressed": "MEDIUM"
            })

    # Priority 4: Revoke stale grants
    for grant in stale_grants:
        plan.append({
            "priority": 4,
            "action": "REVOKE_STALE_GRANT",
            "app_name": grant["app_name"],
            "scopes_to_revoke": grant["scopes"],
            "reason": f"No API activity in {grant['days_inactive']} days",
            "risk_if_not_addressed": "MEDIUM"
        })

    return sorted(plan, key=lambda x: x["priority"])

def execute_scope_reduction(auditor, grant_id, scopes_to_remove):
    """Remove specific scopes from an OAuth permission grant."""
    # Get current grant
    url = f"{auditor.base_url}/oauth2PermissionGrants/{grant_id}"
    response = requests.get(url, headers=auditor.headers)
    current_grant = response.json()

    current_scopes = set(current_grant.get("scope", "").split())
    updated_scopes = current_scopes - set(scopes_to_remove)

    if not updated_scopes:
        # Remove entire grant
        requests.delete(url, headers=auditor.headers)
        return {"action": "grant_deleted", "grant_id": grant_id}
    else:
        # Update with reduced scopes
        update_body = {"scope": " ".join(updated_scopes)}
        requests.patch(url, headers=auditor.headers, json=update_body)
        return {
            "action": "scopes_reduced",
            "grant_id": grant_id,
            "removed": list(scopes_to_remove),
            "remaining": list(updated_scopes)
        }
```

## Key Concepts

| Term | Definition |
|------|------------|
| **OAuth Scope** | Permission string defining the specific API access level granted to a client application (e.g., Mail.Read, Files.ReadWrite.All) |
| **Delegated Permission** | OAuth scope exercised on behalf of a signed-in user, limited by both the app's permissions and the user's own access rights |
| **Application Permission** | OAuth scope granted directly to the application without user context, providing access to all users' data (high risk) |
| **Admin Consent** | Tenant-wide permission grant made by an administrator that applies to all users without individual consent |
| **Scope Minimization** | Security principle of reducing OAuth permissions to the minimum set required for application functionality |
| **Stale Grant** | OAuth permission that remains active but has no recent API usage, indicating the integration is abandoned or deprecated |

## Tools & Systems

- **Microsoft Entra Admin Center**: Portal for reviewing enterprise applications, consent permissions, and OAuth grant management
- **Nudge Security**: SaaS security platform for discovering OAuth grants, assessing third-party risk, and automating scope reviews
- **Cerby**: Non-SSO application management platform for auditing OAuth integrations and managing shared accounts
- **Microsoft Graph API**: Programmatic interface for enumerating and modifying OAuth permission grants at scale

## Common Scenarios

### Scenario: Post-Breach OAuth Scope Audit

**Context**: After a phishing attack compromised an admin account, investigation reveals the attacker registered a malicious OAuth application with Mail.ReadWrite and Files.ReadWrite.All scopes, exfiltrating 6 months of email. The organization needs a comprehensive OAuth scope review.

**Approach**:
1. Immediately revoke all OAuth grants from the compromised admin session
2. Enumerate all service principals and permission grants across the tenant
3. Flag all applications registered in the last 90 days for manual review
4. Classify all third-party application scopes using the risk framework
5. Identify applications with critical scopes (Mail.ReadWrite, Files.ReadWrite.All, Directory.ReadWrite.All)
6. Cross-reference against approved application catalog from IT procurement
7. Revoke all unapproved applications immediately
8. Downgrade over-permissioned approved applications to minimum required scopes
9. Implement admin consent workflow to prevent future uncontrolled OAuth grants
10. Enable consent policy requiring admin approval for high-risk scopes

**Pitfalls**:
- Revoking permissions for business-critical integrations without coordination causes service disruption
- Not checking for application-level permissions (vs delegated) which are higher risk and often overlooked
- Missing multi-tenant applications where the publisher tenant differs from the consuming tenant
- Not implementing ongoing monitoring to detect new unauthorized OAuth grants after remediation

## Output Format

```
OAUTH SCOPE MINIMIZATION REVIEW REPORT
=========================================
Tenant:              corp.onmicrosoft.com
Review Period:       2026-02-01 to 2026-02-24
Total Applications:  147
Third-Party Apps:    98
First-Party Apps:    49

PERMISSION INVENTORY
Total OAuth Grants:          487
  Delegated Permissions:     312
  Application Permissions:   175
  Admin-Consented:           89
  User-Consented:            223

RISK CLASSIFICATION
Critical Risk Apps:     7
  - UnknownCRMApp (Mail.ReadWrite, Files.ReadWrite.All - UNAPPROVED)
  - LegacySync (Directory.ReadWrite.All - EXCESSIVE)
  - DevToolX (Application.ReadWrite.All - OVERLY BROAD)
High Risk Apps:         18
Medium Risk Apps:       34
Low Risk Apps:          88

FINDINGS
Unapproved Applications:        12 (REVOKE IMMEDIATELY)
Excessive Scopes:               23 apps with scopes beyond approved list
Overly Broad Permissions:       15 apps that can be downgraded
Stale Grants (90+ days):        31 apps with no recent API activity

REMEDIATION PLAN
Priority 1 (Immediate):    12 unapproved app revocations
Priority 2 (This Week):    23 excessive scope removals
Priority 3 (This Month):   15 scope downgrades
Priority 4 (Next Quarter): 31 stale grant revocations

Estimated Scope Reduction:  34% of total permissions
```
