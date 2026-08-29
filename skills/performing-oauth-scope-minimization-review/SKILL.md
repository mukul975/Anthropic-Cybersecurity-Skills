---
name: performing-oauth-scope-minimization-review
description: Performs OAuth 2.0 scope minimization review to identify over-permissioned third-party application integrations, excessive API scopes, unused token grants, and risky OAuth consent patterns across identity providers and SaaS platforms. Use when performing an OAuth scope audit, API permission review, third-party app risk assessment, or consent grant minimization. Do not use for detecting suspicious or malicious OAuth application consent grants - use detecting-suspicious-oauth-application-consent.
domain: cybersecurity
subdomain: identity-access-management
tags:
- OAuth
- scope-minimization
- API-security
- consent-review
- third-party-risk
- token-audit
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.AA-01
- PR.AA-02
- PR.AA-05
- PR.AA-06
mitre_attack:
- T1078
- T1110
- T1556
- T1098
mitre_f3:
  version: '1.1'
  tactics:
  - initial-access
  - positioning
  - stealth
  techniques:
  - id: T1550.001
    name: 'Use Alternate Authentication Material: Application Access Token'
    tactic: initial-access
    source: attack
  - id: F1006.001
    name: 'Account Takeover: Exposed API Key'
    tactic: initial-access
    source: f3
  - id: F1004
    name: Access with Stolen Session Cookie
    tactic: initial-access
    source: f3
  - id: F1005.001
    name: 'Account Manipulation: Account Linking'
    tactic: positioning
    source: f3
  - id: T1539
    name: Steal Web Session Cookie
    tactic: positioning
    source: attack
  - id: F1023
    name: Device Fingerprint Spoofing
    tactic: stealth
    source: f3
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

Enumerate all OAuth application registrations and delegated permissions. Using Microsoft Graph, pull every service principal (enterprise application), every delegated `oauth2PermissionGrants` (user/admin consent), and per-app `appRoleAssignments` (application permissions). Combine into a single inventory that flags third-party publishers, permission type (Delegated vs Application), consent type, and enablement.

See `references/audit-code.md` (Step 1) for the `EntraOAuthAuditor` class and `build_permission_inventory()`.

### Step 2: Classify OAuth Scopes by Risk Level

Categorize permissions based on data access sensitivity. Map each Microsoft Graph scope to a risk tier — CRITICAL (full admin / impersonation, e.g. `Directory.ReadWrite.All`, `Mail.Send`, `full_access_as_app`), HIGH (broad read, e.g. `Mail.Read`, `Directory.Read.All`), MEDIUM (scoped write), LOW (profile-only). Unknown scopes default to HIGH. Aggregate per-app risk with weighted scoring, adding bonuses for Application-type and admin-consented (`AllPrincipals`) grants.

See `references/audit-code.md` (Step 2) for the `MICROSOFT_GRAPH_SCOPE_RISK` table, `classify_scope_risk()`, and `analyze_app_risk()`.

### Step 3: Identify Over-Permissioned Applications

Detect apps requesting more permissions than functionally needed. Group the inventory by application and compare against an approved-scope catalog to surface four finding types: UNAPPROVED_APPLICATION (not in catalog), EXCESSIVE_SCOPES (granted beyond approved), UNUSED_APPROVED_SCOPES (approved but not granted), and OVERLY_BROAD_SCOPE (write scope where read suffices, e.g. `Mail.ReadWrite` → `Mail.Read`).

See `references/audit-code.md` (Step 3) for the `detect_over_permissions()` implementation.

### Step 4: Audit Token Usage and Detect Stale Grants

Identify OAuth tokens that are no longer actively used. Pull service-principal sign-in activity from `auditLogs/signIns` over the inactivity window, build the set of recently active app IDs, then flag any granted app absent from that set as a stale grant (sorted by scope count) recommended for revocation.

See `references/audit-code.md` (Step 4) for the `audit_token_usage()` implementation.

### Step 5: Generate Remediation Plan and Execute Scope Reduction

Create and execute the scope minimization remediation plan. `generate_remediation_plan()` orders actions by priority — P1 revoke unapproved apps, P2 remove excessive scopes, P3 downgrade overly broad scopes, P4 revoke stale grants. `execute_scope_reduction()` patches or deletes the `oauth2PermissionGrants` object to drop specific scopes (deleting the grant entirely when no scopes remain).

See `references/audit-code.md` (Step 5) for the `generate_remediation_plan()` and `execute_scope_reduction()` implementations.

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
