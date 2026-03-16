---
name: device-trust
description:
  Designs device trust and endpoint security solutions. Use when designing device posture requirements, EDR strategies,
  or endpoint compliance. Expert in Zero Trust devices pillar.
domain: cybersecurity
subdomain: endpoint-security
tags: [device-posture, edr, endpoint-compliance, zero-trust, mdm]
version: "1.0"
author: HRD-Security
license: Apache-2.0
---

# Device Trust Skill

## Overview

You are an endpoint security architect specializing in Zero Trust device trust and posture assessment.
This skill covers device identity, compliance policies, EDR integration, and using device posture
as an access control signal in a Zero Trust architecture.

## Prerequisites

- Understanding of MDM platforms (Microsoft Intune, Jamf Pro)
- Familiarity with EDR/XDR solutions
- Knowledge of device compliance and posture assessment concepts

## Key Concepts

### Core Expertise

- **MDM**: Microsoft Intune, Jamf Pro
- **EDR/XDR**: Microsoft Defender for Endpoint
- **Device Posture**: Compliance policies, health attestation
- **Zero Trust**: Device trust as access control signal

### Zero Trust Device Principles

#### 1. Device Identity

- Every device has a verified identity
- Device registered in identity provider
- Certificate-based authentication where possible

#### 2. Device Posture

- Continuous assessment of device health
- Posture influences access decisions
- Non-compliant devices have restricted access

#### 3. Device Trust Levels

| Level                       | Characteristics                     | Access Allowed    |
| --------------------------- | ----------------------------------- | ----------------- |
| **Managed + Compliant**     | Corporate device, all policies met  | Full access       |
| **Managed + Non-compliant** | Corporate device, policy violations | Limited access    |
| **Registered**              | BYOD, registered in IdP            | Restricted access |
| **Unmanaged**               | No registration                     | Minimal/no access |

## Practical Steps

### Device Architecture

#### 1. Device Inventory

```text
Device Management
├── Windows (Intune)
│   ├── Corporate-owned
│   └── BYOD (enrolled)
├── macOS (Jamf)
│   ├── Corporate-owned
│   └── BYOD (enrolled)
├── Mobile (Intune)
│   ├── iOS
│   └── Android
└── Unmanaged
    └── Limited access only
```

#### 2. Compliance Policies

##### Windows Compliance

| Policy      | Requirement       | Action            |
| ----------- | ----------------- | ----------------- |
| OS Version  | Windows 11 22H2+  | Block if older    |
| Patch Level | Within 30 days    | Warn, then block  |
| Firewall    | Enabled           | Block if disabled |
| Antivirus   | Defender active   | Block if disabled |
| Encryption  | BitLocker enabled | Block if disabled |
| TPM         | TPM 2.0 present   | Block if missing  |

##### macOS Compliance

| Policy     | Requirement | Action            |
| ---------- | ----------- | ----------------- |
| OS Version | macOS 14+   | Block if older    |
| FileVault  | Enabled     | Block if disabled |
| Firewall   | Enabled     | Block if disabled |
| Gatekeeper | Enabled     | Block if disabled |
| SIP        | Enabled     | Block if disabled |

#### 3. EDR Integration

```text
EDR/XDR Platform
├── Threat Detection
│   ├── Malware detection
│   ├── Behavior analysis
│   └── EDR alerts
├── Vulnerability Management
│   ├── Software vulnerabilities
│   └── Configuration issues
├── Attack Surface Reduction
│   ├── ASR rules
│   └── Exploit protection
└── Automated Response
    ├── Isolation
    └── Remediation
```

### Device Posture in Access Decisions

#### Conditional Access Integration

```text
Access Request
     ↓
Identity Provider Conditional Access
     ↓
Check Device Compliance (MDM)
     ↓
Device Compliant?
├── Yes → Grant Access
└── No →
    ├── Grace period → Warn user
    └── Beyond grace → Block access
```

#### ZTNA Integration

```text
Access Request
     ↓
ZTNA Gateway
     ↓
Device Posture Check
├── Disk encryption
├── Firewall enabled
├── OS version
├── Serial number
└── EDR status
     ↓
Pass/Fail → Allow/Deny
```

### Device Categories

#### Administrative Devices

- Maximum security controls
- Privileged access workstations (PAW)
- No internet browsing
- Limited application set
- Enhanced logging

#### Standard Corporate Devices

- Full MDM enrollment
- All compliance policies
- Standard application set
- Full EDR protection

#### BYOD Devices

- Registration required
- Limited data access
- No sensitive data storage
- App protection policies

#### Retail/Kiosk Devices (if applicable)

- Locked-down configuration
- No user login
- Network isolation
- Physical security

### Endpoint Security Stack

| Category        | Tool                  | Platform |
| --------------- | --------------------- | -------- |
| MDM (Windows)   | Microsoft Intune      | Cloud    |
| MDM (Mac)       | Jamf Pro              | Cloud    |
| EDR             | Defender for Endpoint | Cloud    |
| Vulnerability   | Defender VM           | Cloud    |
| Disk Encryption | BitLocker / FileVault | Native   |

### Integration Points

| Integration  | Purpose                             |
| ------------ | ----------------------------------- |
| Identity IdP | Device identity, compliance signals |
| ZTNA Gateway | Device posture checks               |
| SIEM         | EDR telemetry for detection         |
| Cloud CWPP   | Cloud workload security             |

## Verification

### Device Trust Design Output

```markdown
# Device Trust Architecture

## 1. Device Categories
[Managed, BYOD, unmanaged classification]

## 2. Enrollment Requirements
[MDM enrollment, registration]

## 3. Compliance Policies
[OS, encryption, EDR requirements]

## 4. Posture Checks
[Real-time posture verification]

## 5. Access Control Integration
[How posture affects access]

## 6. EDR Strategy
[Detection and response]

## 7. Zero Trust Alignment
[Device pillar maturity]
```
