---
name: auditing-azure-active-directory-configuration
description: >
  Auditing Microsoft Entra ID (Azure Active Directory) configuration to identify risky
  authentication policies, overly permissive role assignments, stale accounts, conditional
  access gaps, and guest user risks using AzureAD PowerShell, Microsoft Graph API, and ScoutSuite.
domain: cybersecurity
subdomain: cloud-security
tags: [cloud-security, azure, entra-id, active-directory, iam-audit, conditional-access]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Auditing Azure Active Directory Configuration

## When to Use

- When performing a security assessment of an Azure tenant's identity configuration
- When compliance audits require review of authentication policies, MFA enforcement, and role assignments
- When onboarding a new Azure tenant after merger or acquisition
- When investigating suspicious sign-in activity or compromised accounts
- When validating conditional access policies adequately protect against identity-based attacks

**Do not use** for on-premises Active Directory auditing (use PingCastle or BloodHound AD), for Azure resource-level RBAC auditing without identity context, or for real-time threat detection (use Microsoft Defender for Identity).

## Prerequisites

- Global Reader or Security Reader role in the target Microsoft Entra ID tenant
- Microsoft Graph PowerShell SDK installed (`Install-Module Microsoft.Graph`)
- Az CLI authenticated to the target tenant (`az login --tenant TENANT_ID`)
- ScoutSuite with Azure provider configured for automated assessment
- Access to Azure AD audit logs and sign-in logs (requires Azure AD Premium P1/P2)

## Workflow

### Step 1: Enumerate Tenant Configuration and Security Defaults

Assess the tenant's baseline identity security settings including security defaults and legacy authentication status.

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Directory.Read.All","Policy.Read.All","AuditLog.Read.All"

# Get tenant details
Get-MgOrganization | Select-Object DisplayName, Id, VerifiedDomains

# Check if Security Defaults are enabled
Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy | Select-Object IsEnabled

# List authentication methods policies
Get-MgPolicyAuthenticationMethodPolicy | ConvertTo-Json -Depth 5

# Check legacy authentication status via Conditional Access
Get-MgIdentityConditionalAccessPolicy | Where-Object {
    $_.Conditions.ClientAppTypes -contains "exchangeActiveSync" -or
    $_.Conditions.ClientAppTypes -contains "other"
} | Select-Object DisplayName, State
```

### Step 2: Audit Privileged Role Assignments

Review directory role assignments to identify over-privileged users, permanent admin accounts, and risky role configurations.

```bash
# List all Global Administrator assignments
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/directoryRoles/filterByIds" \
  --body '{"ids":["62e90394-69f5-4237-9190-012177145e10"]}' | \
  az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/directoryRoles?filter=displayName eq 'Global Administrator'" \
  --query "value[0].id" -o tsv

# List all privileged role assignments using Graph API
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$expand=principal" \
  --query "value[*].{Role:roleDefinitionId, Principal:principal.displayName, PrincipalType:principal.@odata.type}" \
  -o table

# Check for users with multiple admin roles
az ad user list --query "[].{UPN:userPrincipalName, DisplayName:displayName}" -o table

# List service principals with admin role assignments
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$filter=principalOrganizationId eq 'TENANT_ID'" \
  -o json
```

### Step 3: Review Conditional Access Policies

Audit conditional access policies for coverage gaps, particularly around MFA enforcement, device compliance, and location-based restrictions.

```powershell
# List all Conditional Access policies
Get-MgIdentityConditionalAccessPolicy | Select-Object DisplayName, State, @{
    N='GrantControls'; E={$_.GrantControls.BuiltInControls -join ', '}
} | Format-Table -AutoSize

# Identify policies in report-only mode (not enforced)
Get-MgIdentityConditionalAccessPolicy | Where-Object {$_.State -eq "enabledForReportingButNotEnforced"} |
    Select-Object DisplayName

# Check MFA enforcement coverage
Get-MgIdentityConditionalAccessPolicy | Where-Object {
    $_.GrantControls.BuiltInControls -contains "mfa"
} | Select-Object DisplayName, State, @{
    N='Users'; E={$_.Conditions.Users.IncludeUsers -join ', '}
}

# Find policies that exclude groups (potential bypass)
Get-MgIdentityConditionalAccessPolicy | Where-Object {
    $_.Conditions.Users.ExcludeGroups.Count -gt 0
} | Select-Object DisplayName, @{
    N='ExcludedGroups'; E={$_.Conditions.Users.ExcludeGroups -join ', '}
}
```

### Step 4: Identify Stale Accounts and Guest Users

Find accounts that have not signed in recently, disabled accounts with active role assignments, and risky guest user configurations.

```bash
# Find users who haven't signed in for 90+ days
az ad user list --query "[?signInActivity.lastSignInDateTime < '2025-11-25T00:00:00Z'].{UPN:userPrincipalName, LastSignIn:signInActivity.lastSignInDateTime, Enabled:accountEnabled}" -o table

# List all guest users
az ad user list --filter "userType eq 'Guest'" \
  --query "[].{UPN:userPrincipalName, DisplayName:displayName, CreatedDate:createdDateTime}" \
  -o table

# Find guest users with privileged roles
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$expand=principal" \
  --query "value[?principal.userType=='Guest'].{Role:roleDefinitionId,Guest:principal.userPrincipalName}" \
  -o table

# Check for accounts with disabled MFA
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails" \
  --query "value[?!isMfaRegistered].{UPN:userPrincipalName,MfaRegistered:isMfaRegistered}" \
  -o table
```

### Step 5: Analyze Sign-In Logs for Risky Activity

Review sign-in logs to identify anomalous authentication patterns, failed MFA challenges, and risky sign-in detections.

```bash
# Get risky sign-ins from last 7 days
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$filter=riskLevelDuringSignIn ne 'none' and createdDateTime ge 2026-02-16T00:00:00Z" \
  --query "value[*].{User:userPrincipalName,Risk:riskLevelDuringSignIn,IP:ipAddress,App:appDisplayName,Status:status.errorCode}" \
  -o table

# Get sign-ins from unfamiliar locations
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$filter=riskEventTypes_v2/any(r:r eq 'unfamiliarFeatures')" \
  --query "value[*].{User:userPrincipalName,Location:location.city,IP:ipAddress}" \
  -o table

# Check for legacy authentication sign-ins
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$filter=clientAppUsed ne 'Browser' and clientAppUsed ne 'Mobile Apps and Desktop clients'" \
  --query "value[*].{User:userPrincipalName,ClientApp:clientAppUsed,Status:status.errorCode}" \
  -o table
```

### Step 6: Run ScoutSuite Automated Assessment

Execute ScoutSuite for comprehensive automated checks across the Azure tenant configuration.

```bash
# Run ScoutSuite against Azure
python3 -m ScoutSuite azure --cli \
  --report-dir ./scoutsuite-azure-report \
  --all-subscriptions

# Review the generated HTML report
open ./scoutsuite-azure-report/azure-report.html
```

## Key Concepts

| Term | Definition |
|------|------------|
| Microsoft Entra ID | Microsoft's cloud identity and access management service, formerly Azure Active Directory, providing authentication and authorization |
| Conditional Access | Policy engine that evaluates signals (user, device, location, risk) to enforce access controls like MFA, device compliance, or block access |
| Security Defaults | Microsoft's baseline identity protection settings that enforce MFA registration, block legacy auth, and protect privileged actions |
| Privileged Identity Management | Azure AD Premium P2 feature enabling just-in-time privileged access with approval workflows and time-bound role activation |
| Legacy Authentication | Older authentication protocols (POP3, IMAP, SMTP, ActiveSync) that do not support MFA and are commonly exploited for credential attacks |
| Risky Sign-In | Microsoft Entra Identity Protection detection of sign-in anomalies including impossible travel, unfamiliar locations, and malware-linked IPs |

## Tools & Systems

- **Microsoft Graph API**: Primary programmatic interface for querying Entra ID configuration, policies, roles, and audit logs
- **Microsoft Graph PowerShell SDK**: PowerShell module for Entra ID management and security auditing tasks
- **ScoutSuite**: Multi-cloud auditing tool with Azure provider support for IAM, storage, networking, and identity checks
- **AzureADRecon**: Community tool for comprehensive Azure AD reconnaissance and security assessment reporting
- **Microsoft Defender for Identity**: Cloud-based security solution for detecting identity-based threats and compromised credentials

## Common Scenarios

### Scenario: Post-Acquisition Azure Tenant Security Assessment

**Context**: After acquiring a company, the security team needs to assess the Azure tenant identity posture before integrating it with the corporate Entra ID.

**Approach**:
1. Enumerate all Global Administrators and check for personal accounts in admin roles
2. Review conditional access policies to verify MFA is enforced for all users, not just admins
3. Identify guest users with privileged access that may indicate third-party vendor over-permissioning
4. Check for stale accounts (no sign-in for 90+ days) that could be targets for credential attacks
5. Review sign-in logs for legacy authentication usage that bypasses MFA
6. Verify Security Defaults or equivalent CA policies block legacy auth protocols
7. Produce a risk report with prioritized remediation steps before tenant integration

**Pitfalls**: Azure AD Premium P2 is required for risky sign-in detections and PIM. If the acquired tenant uses a lower license tier, many identity protection features will be unavailable. Guest users from partner tenants may have implicit access through dynamic groups that are not visible in standard role assignment queries.

## Output Format

```
Azure Active Directory Security Audit Report
===============================================
Tenant: acme-acquired.onmicrosoft.com
Tenant ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
Audit Date: 2026-02-23
License: Azure AD Premium P2

IDENTITY CONFIGURATION:
  Security Defaults: Disabled (Conditional Access in use)
  Conditional Access Policies: 12 (8 enforced, 3 report-only, 1 disabled)
  Legacy Auth Blocked: Partial (blocked for admins only)

PRIVILEGED ACCESS:
  Global Administrators:              8 (recommended: <= 4)
  Permanent admin assignments:        6 (no PIM activation required)
  Service principals with admin:      3
  Guest users with privileged roles:  2

ACCOUNT HYGIENE:
  Total users:                        1,247
  Stale accounts (90+ days):          89
  Guest users:                        234
  Users without MFA registered:       156

SIGN-IN RISK:
  Risky sign-ins (last 30 days):      34
  Legacy auth sign-ins (last 7 days): 67
  Impossible travel detections:        5
  Unfamiliar location sign-ins:       12

CRITICAL FINDINGS:
  1. 8 Global Administrators with permanent assignments (use PIM)
  2. Legacy authentication not blocked for non-admin users
  3. 156 users without MFA registration
  4. 2 guest users with Privileged Role Administrator role
```
