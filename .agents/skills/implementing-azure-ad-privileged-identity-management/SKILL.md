---
name: implementing-azure-ad-privileged-identity-management
description: Configure Microsoft Entra Privileged Identity Management to enforce just-in-time role activation, approval workflows, and access reviews for Azure AD privileged roles.
domain: cybersecurity
subdomain: identity-access-management
tags: [azure-ad, pim, entra-id, just-in-time, privileged-roles, identity-governance, zero-trust]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing Azure AD Privileged Identity Management

## Overview

Microsoft Entra Privileged Identity Management (PIM) provides time-based and approval-based role activation to mitigate risks from excessive, unnecessary, or misused access to critical resources. PIM replaces permanent (standing) privilege assignments with eligible assignments that require users to explicitly activate their role before use, with configurable duration, MFA enforcement, approval workflows, and justification requirements. This is a core component of Zero Trust identity governance in Microsoft environments.

## Prerequisites

- Microsoft Entra ID P2 or Microsoft Entra ID Governance license
- Global Administrator or Privileged Role Administrator role
- Azure subscription for Azure resource role management
- MFA configured for all privileged users
- Microsoft Authenticator or FIDO2 key for admin accounts

## Core Concepts

### Assignment Types

| Type | Behavior | Use Case |
|------|----------|----------|
| Eligible | User must activate the role before use; expires after configured duration | Day-to-day admin work |
| Active | Role is always active; no activation needed | Service accounts, break-glass accounts |
| Time-Bound | Either type with explicit start/end dates | Temporary project access, contractor access |

### PIM Activation Flow

```
User with Eligible Assignment
        │
        ├── Opens PIM portal → My Roles
        │
        ├── Clicks "Activate" on the desired role
        │
        ├── Provides justification and optional ticket number
        │
        ├── Completes MFA challenge (if required)
        │
        ├── [If approval required] → Notification sent to approvers
        │       │
        │       ├── Approver reviews and approves/denies
        │       └── User notified of decision
        │
        ├── Role activated for configured duration (e.g., 8 hours)
        │
        └── Role automatically deactivated when duration expires
```

### Supported Resource Types

1. **Microsoft Entra Roles**: Global Admin, Exchange Admin, Security Admin, etc.
2. **Azure Resource Roles**: Owner, Contributor, User Access Administrator on subscriptions/resource groups
3. **PIM for Groups**: Manage membership in privileged security groups

## Implementation Steps

### Step 1: Plan Role Assignments

Audit current permanent role assignments and determine which should be converted to eligible:

| Current Role | Permanent Holders | Action |
|-------------|-------------------|--------|
| Global Administrator | 2-3 admins | Convert to eligible, keep 1 break-glass active |
| Exchange Administrator | IT team | Convert all to eligible |
| Security Administrator | SOC team | Convert to eligible |
| User Administrator | Help desk | Convert to eligible |
| Application Administrator | DevOps | Convert to eligible |

Best practice: Maintain no more than 2 permanent Global Administrators (break-glass accounts).

### Step 2: Configure Role Settings

For each Entra directory role, configure PIM settings:

**Via Microsoft Entra Admin Center:**
1. Navigate to Identity Governance > Privileged Identity Management > Microsoft Entra roles
2. Select "Settings" and choose the role to configure
3. Configure the following:

**Activation Settings:**
- Maximum activation duration: 8 hours (recommended; max 72 hours)
- Require MFA on activation: Enabled
- Require justification: Enabled
- Require ticket information: Enabled (for change management integration)
- Require approval: Enabled for Global Admin, Security Admin

**Assignment Settings:**
- Allow permanent eligible assignment: No (set expiry)
- Expire eligible assignments after: 6 months (requires re-certification)
- Allow permanent active assignment: Only for break-glass accounts
- Require MFA on active assignment: Enabled
- Require justification on active assignment: Enabled

**Notification Settings:**
- Send email when members are assigned eligible: Role assigners, admins
- Send email when members activate: Admins, security team
- Send email when eligible members activate roles: Role assignees

### Step 3: Configure via Microsoft Graph API

```python
import requests

# Acquire token for Microsoft Graph
def get_graph_token(tenant_id, client_id, client_secret):
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default"
    }
    response = requests.post(url, data=data)
    return response.json()["access_token"]

# Create eligible role assignment
def create_eligible_assignment(token, role_definition_id, principal_id,
                                directory_scope="/", duration_hours=8):
    url = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    body = {
        "action": "adminAssign",
        "justification": "PIM eligible assignment",
        "roleDefinitionId": role_definition_id,
        "directoryScopeId": directory_scope,
        "principalId": principal_id,
        "scheduleInfo": {
            "startDateTime": "2025-01-01T00:00:00Z",
            "expiration": {
                "type": "afterDuration",
                "duration": "P180D"  # 180-day eligible window
            }
        }
    }
    response = requests.post(url, headers=headers, json=body)
    return response.json()

# Activate a role (user self-service)
def activate_role(token, role_definition_id, principal_id, justification,
                   duration_hours=8):
    url = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    body = {
        "action": "selfActivate",
        "principalId": principal_id,
        "roleDefinitionId": role_definition_id,
        "directoryScopeId": "/",
        "justification": justification,
        "scheduleInfo": {
            "startDateTime": None,  # Now
            "expiration": {
                "type": "afterDuration",
                "duration": f"PT{duration_hours}H"
            }
        }
    }
    response = requests.post(url, headers=headers, json=body)
    return response.json()
```

### Step 4: Configure Access Reviews

Set up recurring access reviews to verify eligible assignments remain appropriate:

1. Navigate to Identity Governance > Access Reviews > New Access Review
2. Configure:
   - Review scope: Privileged Identity Management role assignments
   - Roles: Select all critical roles (Global Admin, Security Admin, etc.)
   - Reviewers: Managers or self-review with justification
   - Frequency: Quarterly for critical roles, semi-annually for others
   - Auto-apply results: Remove access for non-responsive reviews
   - Duration: 14 days for reviewers to respond

### Step 5: Configure Alerts

Enable PIM security alerts:

| Alert | Trigger | Action |
|-------|---------|--------|
| Too many global admins | > 5 Global Admins | Review and reduce |
| Roles being assigned outside PIM | Direct role assignment | Investigate and convert to PIM |
| Roles not requiring MFA | Activation without MFA | Enable MFA requirement |
| Stale eligible assignments | Not activated in 90 days | Review and potentially remove |
| Potential stale service accounts | Active assignments not used | Investigate and decommission |

## Validation Checklist

- [ ] All permanent privileged role assignments converted to eligible (except break-glass)
- [ ] Break-glass accounts configured as active with monitoring alerts
- [ ] MFA required for all role activations
- [ ] Approval workflow configured for Global Administrator and Security Administrator
- [ ] Maximum activation duration set to 8 hours or less for critical roles
- [ ] Eligible assignments expire after 6 months (requires re-certification)
- [ ] Justification and ticket information required for activations
- [ ] Email notifications configured for role assignments and activations
- [ ] Access reviews scheduled quarterly for all privileged roles
- [ ] PIM alerts enabled and reviewed weekly
- [ ] Audit logs forwarded to SIEM for monitoring

## References

- [Microsoft Entra PIM Documentation](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure)
- [Plan a PIM Deployment](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-deployment-plan)
- [Start Using PIM](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-getting-started)
- [Microsoft Graph PIM API](https://learn.microsoft.com/en-us/graph/api/resources/privilegedidentitymanagementv3-overview)
