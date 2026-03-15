---
name: performing-access-recertification-with-saviynt
description: Configure and execute access recertification campaigns in Saviynt Enterprise Identity Cloud to validate user entitlements, revoke excessive access, and maintain compliance with SOX, SOC2, and HIPAA.
domain: cybersecurity
subdomain: identity-access-management
tags: [saviynt, access-recertification, identity-governance, compliance, certification-campaign, iga]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Access Recertification with Saviynt

## Overview

Access recertification (also called access certification or access review) is a periodic process where designated reviewers validate that users have appropriate access to systems and data. Saviynt Enterprise Identity Cloud (EIC) automates this process through certification campaigns that present reviewers with current access assignments and collect approve/revoke/conditionally-certify decisions. Campaigns can be triggered on schedule (quarterly, semi-annually), event-driven (department transfer, role change), or on-demand. Saviynt provides intelligence features including risk scoring, usage analytics, and peer-group analysis to help reviewers make informed decisions.

## Prerequisites

- Saviynt Enterprise Identity Cloud (EIC) tenant with admin access
- Identity data synchronized from authoritative sources (HR, AD, cloud)
- Entitlement data imported from target applications
- Certifier roles assigned (managers, application owners, data owners)
- Campaign templates defined for each certification type

## Core Concepts

### Campaign Types

| Type | Scope | Trigger | Certifier |
|------|-------|---------|-----------|
| User Manager | All access for users under a manager | Scheduled (quarterly) | Direct manager |
| Entitlement Owner | All users with a specific entitlement | Scheduled (semi-annually) | Entitlement/app owner |
| Application | All access to a specific application | Scheduled | Application owner |
| Role-Based | All users assigned to a specific role | Scheduled | Role owner |
| Event-Based | Users whose attributes changed | Attribute change trigger | New manager |
| Micro-Certification | Single user, single entitlement | On-demand | Manager or owner |

### Certification Decisions

| Decision | Effect | Use Case |
|----------|--------|----------|
| Certify (Approve) | Access maintained | Access is still required |
| Revoke | Access removal ticket created | Access no longer needed |
| Conditionally Certify | Access maintained with conditions | Access needed temporarily, review again |
| Delegate | Reassign to another certifier | Certifier lacks knowledge to decide |
| Abstain | No decision recorded | Conflict of interest |

### Campaign Lifecycle

```
CONFIGURATION → PREVIEW → ACTIVE → IN PROGRESS → COMPLETED → REMEDIATION
       │            │         │          │             │            │
       │            │         │          │             │            └── Revoke tickets
       │            │         │          │             │                executed
       │            │         │          │             │
       │            │         │          │             └── All decisions
       │            │         │          │                 collected
       │            │         │          │
       │            │         │          └── Certifiers reviewing
       │            │         │              and making decisions
       │            │         │
       │            │         └── Campaign launched,
       │            │             notifications sent
       │            │
       │            └── Read-only preview for validation
       │
       └── Campaign parameters defined
```

## Implementation Steps

### Step 1: Configure Campaign Template

In Saviynt Admin Console:

1. Navigate to **Certifications > Campaign > Create New Campaign**
2. Define campaign parameters:

| Parameter | Value |
|-----------|-------|
| Campaign Name | Q1 2025 Manager Access Review |
| Campaign Type | User Manager |
| Description | Quarterly review of all user access |
| Certifier Type | Manager (dynamic - user's direct manager) |
| Secondary Certifier | Application Owner (fallback if manager unavailable) |
| Due Date | 14 days from launch |
| Reminder Schedule | Day 7, Day 10, Day 13 |
| Escalation | Auto-revoke on Day 15 if no decision |

3. Configure scope filters:
   - Include: All active users
   - Exclude: Service accounts, break-glass accounts
   - Application filter: All connected applications

4. Configure intelligence features:
   - Enable risk scoring (high-risk entitlements highlighted)
   - Enable usage data (last access date shown)
   - Enable peer analysis (compare access to peer group)
   - Enable SoD violation flagging

### Step 2: Configure Certifier Experience

Customize what certifiers see during the review:

**Columns Displayed:**
- User name and title
- Application name
- Entitlement/role name
- Risk score (1-10)
- Last access date
- Peer group comparison (% of peers with same access)
- SoD violation flag

**Decision Options:**
- Certify with justification (free text)
- Revoke with reason (dropdown: no longer needed, SoD conflict, role change)
- Conditionally certify with expiry date

**Bulk Actions:**
- Certify all low-risk items
- Revoke all items not accessed in 90+ days
- Filter by application, risk level, or SoD status

### Step 3: Launch Campaign via API

```python
import requests

SAVIYNT_URL = "https://tenant.saviyntcloud.com"
SAVIYNT_TOKEN = "your-api-token"

def create_certification_campaign(campaign_config):
    """Create and launch a Saviynt certification campaign."""
    headers = {
        "Authorization": f"Bearer {SAVIYNT_TOKEN}",
        "Content-Type": "application/json"
    }

    # Create campaign
    response = requests.post(
        f"{SAVIYNT_URL}/ECM/api/v5/createCampaign",
        headers=headers,
        json={
            "campaignname": campaign_config["name"],
            "campaigntype": campaign_config["type"],
            "description": campaign_config["description"],
            "certifier": campaign_config["certifier_type"],
            "duedate": campaign_config["due_date"],
            "reminderdays": campaign_config["reminder_days"],
            "autorevoke": campaign_config.get("auto_revoke", True),
            "autorevokedays": campaign_config.get("auto_revoke_days", 15),
            "scope": campaign_config.get("scope", {}),
        }
    )
    response.raise_for_status()
    campaign_id = response.json().get("campaignId")

    # Launch campaign
    launch_response = requests.post(
        f"{SAVIYNT_URL}/ECM/api/v5/launchCampaign",
        headers=headers,
        json={"campaignId": campaign_id}
    )
    launch_response.raise_for_status()

    return {
        "campaign_id": campaign_id,
        "status": "launched",
        "certifications_created": launch_response.json().get("certificationCount", 0)
    }

def get_campaign_status(campaign_id):
    """Get current status and progress of a campaign."""
    headers = {"Authorization": f"Bearer {SAVIYNT_TOKEN}"}
    response = requests.get(
        f"{SAVIYNT_URL}/ECM/api/v5/getCampaignDetails",
        headers=headers,
        params={"campaignId": campaign_id}
    )
    response.raise_for_status()
    data = response.json()

    return {
        "campaign_id": campaign_id,
        "status": data.get("status"),
        "total_items": data.get("totalLineItems", 0),
        "certified": data.get("certifiedCount", 0),
        "revoked": data.get("revokedCount", 0),
        "pending": data.get("pendingCount", 0),
        "completion_rate": data.get("completionPercentage", 0),
    }
```

### Step 4: Monitor Campaign Progress

Track certification progress and send escalations:

- **Dashboard**: Saviynt provides real-time campaign dashboard with completion rates
- **Reminders**: Automatic email reminders at configured intervals
- **Escalation**: If certifier does not respond by due date, escalate to manager's manager or auto-revoke
- **Delegation**: Allow certifiers to delegate specific items to application owners

### Step 5: Execute Remediation

After campaign closes:

1. **Auto-Remediation**: Saviynt automatically creates provisioning tasks to revoke denied access
2. **Ticket Integration**: Revocation tasks create tickets in ServiceNow/Jira for tracking
3. **Grace Period**: Configure a grace period (e.g., 5 business days) before access is actually removed
4. **Verification**: After revocation, verify access is removed from target systems
5. **Audit Trail**: All decisions, revocations, and remediations logged for compliance evidence

## Validation Checklist

- [ ] Campaign templates configured for each certification type
- [ ] Certifier roles assigned (managers, app owners, data owners)
- [ ] Risk scoring and usage analytics enabled
- [ ] SoD violation detection configured
- [ ] Reminder and escalation schedules defined
- [ ] Auto-revoke policy for non-responsive certifiers configured
- [ ] Campaign launched and certifiers notified
- [ ] Campaign completion rate > 95% before close
- [ ] Revocation tasks created for all denied entitlements
- [ ] Remediation completed within SLA
- [ ] Campaign report generated for compliance audit
- [ ] Evidence archived for regulatory retention period

## References

- [Saviynt Campaigns and Certifications Documentation](https://docs.saviyntcloud.com/bundle/EIC-Admin-25/page/Content/Chapter15-Campaigns-and-Certifications/Campaigns.htm)
- [Saviynt Simplifying Certifications with Intelligence](https://saviynt.com/blog/simplifying-certifications-with-intelligence)
- [Saviynt Advanced Access Reviews](https://oxfordcomputergroup.com/resources/saviynt-advanced-access-reviews/)
- [ISACA Access Recertification Best Practices](https://www.isaca.org/)
