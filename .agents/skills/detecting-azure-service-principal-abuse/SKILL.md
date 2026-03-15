---
name: detecting-azure-service-principal-abuse
description: Detect and investigate Azure service principal abuse including privilege escalation, credential compromise, admin consent bypass, and unauthorized enumeration in Microsoft Entra ID environments.
domain: cybersecurity
subdomain: cloud-security
tags: [azure, entra-id, service-principal, privilege-escalation, credential-abuse, detection, splunk, sentinel]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Detecting Azure Service Principal Abuse

## Overview

Azure service principals are identity objects used by applications, services, and automation tools to access Azure resources. Attackers exploit service principals for privilege escalation, lateral movement, and persistent access. Key abuse patterns include: adding credentials to existing principals, assigning privileged roles, bypassing admin consent, and enumerating service principals for attack paths. Application ownership grants the ability to manage credentials and configure permissions, creating hidden privilege escalation paths.

## Prerequisites

- Azure subscription with Microsoft Entra ID P2 license
- Access to Azure AD Audit Logs and Sign-in Logs
- Microsoft Sentinel or Splunk for SIEM-based detection
- Microsoft Graph API permissions for investigation
- Global Reader or Security Reader role minimum

## Key Abuse Patterns

### 1. New Credentials Added to Service Principal

Attackers add new client secrets or certificates to gain persistent access:

**Detection Query (KQL - Sentinel):**
```kql
AuditLogs
| where OperationName has "Add service principal credentials"
    or OperationName has "Update application - Certificates and secrets management"
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetSP = tostring(TargetResources[0].displayName)
| extend TargetSPId = tostring(TargetResources[0].id)
| project TimeGenerated, InitiatedBy, OperationName, TargetSP, TargetSPId
| sort by TimeGenerated desc
```

**Detection Query (SPL - Splunk):**
```spl
index=azure sourcetype="azure:aad:audit"
operationName="Add service principal credentials"
    OR operationName="Update application*Certificates and secrets*"
| stats count by initiatedBy.user.userPrincipalName, targetResources{}.displayName, _time
| sort -_time
```

### 2. Privileged Role Assignment to Service Principal

```kql
AuditLogs
| where OperationName == "Add member to role"
| extend RoleName = tostring(TargetResources[0].modifiedProperties[1].newValue)
| where RoleName has_any ("Global Administrator", "Application Administrator",
    "Privileged Role Administrator", "Cloud Application Administrator")
| extend TargetSP = tostring(TargetResources[0].displayName)
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, InitiatedBy, TargetSP, RoleName, OperationName
```

### 3. Service Principal Enumeration Detection

```kql
MicrosoftGraphActivityLogs
| where RequestMethod == "GET"
| where RequestUri has "/servicePrincipals"
| summarize RequestCount = count() by UserAgent, IPAddress, bin(TimeGenerated, 1h)
| where RequestCount > 10
| sort by RequestCount desc
```

### 4. Admin Consent Bypass

```kql
AuditLogs
| where OperationName == "Consent to application"
| extend ConsentType = tostring(TargetResources[0].modifiedProperties[4].newValue)
| where ConsentType has "AllPrincipals"
| extend AppName = tostring(TargetResources[0].displayName)
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, InitiatedBy, AppName, ConsentType
```

### 5. OAuth App Permissions Escalation

```kql
AuditLogs
| where OperationName == "Add app role assignment to service principal"
| extend AppRoleValue = tostring(TargetResources[0].modifiedProperties[1].newValue)
| where AppRoleValue has_any ("RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All",
    "Directory.ReadWrite.All", "Mail.ReadWrite")
| extend TargetApp = tostring(TargetResources[0].displayName)
| project TimeGenerated, TargetApp, AppRoleValue, CorrelationId
```

## Investigation Procedures

### Step 1: Identify compromised service principal

```powershell
# List service principals with recently added credentials
Connect-MgGraph -Scopes "Application.Read.All"

$suspiciousSPs = Get-MgServicePrincipal -All | ForEach-Object {
    $sp = $_
    $creds = Get-MgServicePrincipalPasswordCredential -ServicePrincipalId $sp.Id
    $recentCreds = $creds | Where-Object { $_.StartDateTime -gt (Get-Date).AddDays(-7) }
    if ($recentCreds) {
        [PSCustomObject]@{
            DisplayName = $sp.DisplayName
            AppId = $sp.AppId
            ObjectId = $sp.Id
            NewCredsCount = $recentCreds.Count
            LatestCredAdded = ($recentCreds | Sort-Object StartDateTime -Descending | Select-Object -First 1).StartDateTime
        }
    }
}
$suspiciousSPs | Sort-Object LatestCredAdded -Descending
```

### Step 2: Review service principal role assignments

```powershell
# Check role assignments for a specific service principal
$spId = "<service-principal-object-id>"
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spId | ForEach-Object {
    $resource = Get-MgServicePrincipal -ServicePrincipalId $_.ResourceId
    [PSCustomObject]@{
        AppRoleId = $_.AppRoleId
        ResourceDisplayName = $resource.DisplayName
        CreatedDateTime = $_.CreatedDateTime
    }
}
```

### Step 3: Check application ownership

```powershell
# List owners of all applications (ownership = credential control)
Get-MgApplication -All | ForEach-Object {
    $app = $_
    $owners = Get-MgApplicationOwner -ApplicationId $app.Id
    foreach ($owner in $owners) {
        [PSCustomObject]@{
            AppName = $app.DisplayName
            AppId = $app.AppId
            OwnerUPN = $owner.AdditionalProperties.userPrincipalName
            OwnerType = $owner.AdditionalProperties.'@odata.type'
        }
    }
} | Where-Object { $_.OwnerUPN -ne $null }
```

### Step 4: Review sign-in activity

```kql
AADServicePrincipalSignInLogs
| where ServicePrincipalId == "<target-sp-id>"
| project TimeGenerated, ServicePrincipalName, IPAddress, Location,
    ResourceDisplayName, Status.errorCode
| sort by TimeGenerated desc
```

## Preventive Controls

### Restrict application registration

```powershell
# Disable user ability to register applications
Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{
    AllowedToCreateApps = $false
}
```

### Configure app consent policies

```powershell
# Require admin approval for all app consent requests
New-MgPolicyPermissionGrantPolicy -Id "admin-only-consent" `
    -DisplayName "Admin Only Consent" `
    -Description "Only admins can consent to applications"
```

### Monitor with Microsoft Sentinel Analytics Rules

Create analytics rules for:
- New service principal credential additions
- Privileged role assignments to service principals
- Bulk service principal enumeration
- Admin consent grants to unknown applications
- Service principal sign-ins from unusual locations

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Account Manipulation: Additional Cloud Credentials | T1098.001 | Adding credentials to service principal |
| Valid Accounts: Cloud Accounts | T1078.004 | Using compromised service principal |
| Account Discovery: Cloud Account | T1087.004 | Enumerating service principals |
| Steal Application Access Token | T1528 | OAuth token theft via service principal |

## References

- Splunk Detection: Azure AD Service Principal Abuse
- Semperis: Service Principal Ownership Abuse in Entra ID
- MITRE ATT&CK Cloud Matrix
- Microsoft: Securing service principals in Entra ID
