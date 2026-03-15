---
name: implementing-privileged-identity-management-with-azure
description: Configure Azure AD Privileged Identity Management (PIM) using Microsoft Graph API to manage eligible role assignments, just-in-time activation, access reviews, and role management policies for zero-trust privileged access.
domain: cybersecurity
subdomain: identity-access-management
tags: [Azure-AD, PIM, privileged-access, just-in-time, eligible-roles, Microsoft-Graph, zero-trust, access-reviews, Entra-ID]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing Privileged Identity Management with Azure

## Overview

Azure AD Privileged Identity Management (PIM) enforces just-in-time privileged access by converting permanent role assignments to eligible assignments that require activation. This skill uses the Microsoft Graph API to enumerate active and eligible role assignments, create eligibility schedule requests, configure role management policies (MFA requirements, approval workflows, maximum activation duration), audit PIM activation logs, and identify over-privileged permanent assignments that should be converted to eligible.

## Prerequisites

- Python 3.9+ with `msal`, `requests`
- Azure AD application registration with `RoleManagement.ReadWrite.Directory`, `RoleEligibilitySchedule.ReadWrite.Directory` permissions
- Microsoft Entra ID P2 or Microsoft Entra ID Governance license

## Key Operations

1. **List eligible assignments** — GET /roleManagement/directory/roleEligibilityScheduleInstances
2. **Create eligibility requests** — POST /roleManagement/directory/roleEligibilityScheduleRequests
3. **Activate eligible role** — POST /roleManagement/directory/roleAssignmentScheduleRequests with action=selfActivate
4. **Audit role activations** — GET /auditLogs/directoryAudits filtered by PIM activities
5. **Review role policies** — GET /policies/roleManagementPolicies to check MFA/approval requirements

## Output

JSON audit report with permanent vs. eligible assignment counts, over-privileged accounts, policy compliance status, and recent activation history.
