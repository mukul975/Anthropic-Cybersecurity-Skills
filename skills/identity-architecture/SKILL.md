---
name: identity-architecture
description:
  Designs identity and access management solutions. Use when designing IAM architecture, reviewing access controls, or
  implementing identity governance. Expert in Zero Trust identity.
domain: cybersecurity
subdomain: identity-access-management
tags: [iam, zero-trust, identity-governance, access-management]
version: "1.0"
author: HRD-Security
license: Apache-2.0
---

# Identity Architecture Skill

## Overview

You are an identity architect specializing in Zero Trust identity solutions and access governance.
This skill covers end-to-end identity lifecycle management, authentication and authorization design,
privileged access management, and identity governance aligned with Zero Trust principles.

## Prerequisites

- Familiarity with identity providers (Microsoft Entra ID, Okta, SAML, OIDC)
- Understanding of access management models (RBAC, ABAC, PBAC)
- Knowledge of privileged access management concepts

## Key Concepts

### Core Expertise

- **Identity Providers**: Microsoft Entra ID, Okta, SAML, OIDC
- **Access Management**: RBAC, ABAC, PBAC
- **Privileged Access**: PAM, JIT access, break-glass
- **Identity Governance**: Access certification, lifecycle management
- **Authentication**: MFA, passwordless, phishing-resistant

### Zero Trust Identity Principles

#### 1. Verify Explicitly

- Authenticate based on all available data points
- Include identity, location, device health, service, data classification
- Use risk-based authentication

#### 2. Least Privilege Access

- Just-in-time (JIT) access
- Just-enough-access (JEA)
- Time-bound permissions
- Risk-based adaptive policies

#### 3. Assume Breach

- Segment access to minimize blast radius
- Monitor for identity threats
- Implement identity threat detection

## Practical Steps

### Identity Architecture Components

#### 1. Identity Provider (IdP)

```text
Identity Provider
├── User Identities
│   ├── Employees
│   ├── Contractors
│   └── B2B guests
├── Service Identities
│   ├── Managed identities
│   ├── Service principals
│   └── App registrations
└── Device Identities
    ├── Domain joined
    └── Registered
```

#### 2. Authentication

| Method            | Use Case          | Phishing Resistance |
| ----------------- | ----------------- | ------------------- |
| Password + MFA    | Standard          | Medium              |
| FIDO2 keys        | High security     | High                |
| Windows Hello     | Corporate devices | High                |
| Authenticator app | General           | Medium              |
| SMS OTP           | Legacy            | Low                 |

#### 3. Authorization Models

| Model    | Description     | Use Case             |
| -------- | --------------- | -------------------- |
| **RBAC** | Role-based      | Standard enterprise  |
| **ABAC** | Attribute-based | Complex requirements |
| **PBAC** | Policy-based    | Dynamic decisions    |

#### 4. Conditional Access

```text
User + Device + Location + Application + Risk
                    ↓
           Conditional Access Policy
                    ↓
    Allow / Block / Require MFA / Require Compliant Device
```

### Identity Lifecycle

#### 1. Joiner

- HR triggers provisioning
- Account created in IdP
- Group memberships assigned
- Access provisioned automatically

#### 2. Mover

- Role change detected
- Access reviewed and updated
- Old permissions removed
- New permissions granted

#### 3. Leaver

- Termination triggers deprovisioning
- Access immediately revoked
- Sessions terminated
- Devices wiped/recovered

### Access Governance

#### Access Reviews

| Review Type       | Frequency | Scope          |
| ----------------- | --------- | -------------- |
| Privileged access | Monthly   | Admin accounts |
| Sensitive apps    | Quarterly | High-risk apps |
| All access        | Annually  | All users      |

#### Segregation of Duties

- Define conflicting permissions
- Prevent assignment violations
- Alert on violations
- Document exceptions

### Architecture Patterns

#### Pattern: Application Authentication

```text
User → IdP → Application (SAML/OIDC)
         ↓
   Conditional Access
   - MFA required
   - Compliant device
   - Location check
```

#### Pattern: API Authentication

```text
Service → Managed Identity → Cloud Resource
            ↓
    Token acquisition
    - No secrets stored
    - Auto-rotation
    - Scoped permissions
```

#### Pattern: Privileged Access

```text
Admin → PIM → Elevated Role
         ↓
   JIT Activation
   - Approval required
   - Time-limited
   - Audit logged
```

### Administrative Account Model

A separate admin account model for privileged access is recommended.

#### Account Structure

| Attribute        | User Account          | Admin Account              |
| ---------------- | --------------------- | -------------------------- |
| Naming           | user@domain.com       | user-admin@domain.com      |
| License          | Yes                   | **No**                     |
| Mailbox          | Yes                   | **No**                     |
| PIM Eligible     | No                    | Yes                        |
| Day-to-day use   | Yes                   | No (JIT only)              |

#### Key Design Decisions

1. **No License**: Admin accounts do not have standard licenses
2. **No Mailbox**: Admin accounts cannot receive email (phishing resistance)
3. **JIT Only**: Admin accounts are only used for PIM activations
4. **Separate MFA**: Authenticator app registered to admin account

#### Notification Handling

Since admin accounts lack email, notifications use alternative channels:

| Notification Type       | Method                                   |
| ----------------------- | ---------------------------------------- |
| PIM Activation Approval | Authenticator push                       |
| Expiration Warnings     | Teams channel or alternate email         |
| Security Alerts         | Alternate email (user's primary account) |

#### Naming Convention

```text
Standard User:     firstname.lastname@domain.com
Admin Account:     firstname.lastname-admin@domain.com
Service Account:   svc-applicationname@domain.com
```

#### When Designing Identity Solutions

- Always assume admin accounts have no mailbox
- Use Authenticator push for admin notifications
- Configure alternate notification email to user's primary account

## Verification

### Identity Design Document Output

```markdown
# Identity Architecture Design

## 1. Overview
[Business context and requirements]

## 2. Identity Sources
[User, service, device identity sources]

## 3. Authentication Flow
[Authentication methods and flows]

## 4. Authorization Model
[RBAC/ABAC design]

## 5. Conditional Access Policies
[Policy table]

## 6. Privileged Access
[PAM design]

## 7. Governance
[Lifecycle, reviews, auditing]

## 8. Zero Trust Alignment
[Alignment to ZT principles]
```
