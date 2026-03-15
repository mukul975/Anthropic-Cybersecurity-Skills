---
name: implementing-device-posture-assessment-in-zero-trust
description: >
  Implementing device posture assessment as a zero trust access control by integrating
  endpoint health signals from CrowdStrike ZTA, Microsoft Intune, and Jamf into
  conditional access policies that enforce compliance before granting resource access.
domain: cybersecurity
subdomain: zero-trust-architecture
tags: [device-posture, zero-trust, endpoint-compliance, crowdstrike-zta, intune, conditional-access, jamf]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing Device Posture Assessment in Zero Trust

## When to Use

- When enforcing device health as a prerequisite for accessing corporate applications
- When integrating CrowdStrike ZTA scores, Intune compliance, or Jamf device status into access decisions
- When implementing CISA Zero Trust Maturity Model device pillar requirements
- When building conditional access policies that adapt based on real-time endpoint security posture
- When detecting and blocking access from compromised, unmanaged, or non-compliant devices

**Do not use** for IoT or headless devices that cannot run posture agents, as a standalone security control without identity verification, or when real-time posture data is unavailable and stale compliance data would create false trust.

## Prerequisites

- Endpoint Detection and Response (EDR): CrowdStrike Falcon with ZTA module, or Microsoft Defender for Endpoint
- Mobile Device Management (MDM): Microsoft Intune, Jamf Pro, or VMware Workspace ONE
- Identity Provider: Microsoft Entra ID, Okta, or Ping Identity with conditional access capability
- ZTNA Platform: Zscaler ZPA, Cloudflare Access, Palo Alto Prisma Access, or cloud-native IAP
- API access to EDR/MDM platforms for posture signal ingestion

## Workflow

### Step 1: Define Device Compliance Baselines

Establish minimum security requirements for each device category.

```powershell
# Microsoft Intune: Create device compliance policy via Graph API
Connect-MgGraph -Scopes "DeviceManagementConfiguration.ReadWrite.All"

# Windows 10/11 Compliance Policy
$compliancePolicy = @{
    "@odata.type" = "#microsoft.graph.windows10CompliancePolicy"
    displayName = "Zero Trust - Windows Compliance"
    description = "Minimum device requirements for zero trust access"
    osMinimumVersion = "10.0.19045"
    bitLockerEnabled = $true
    secureBootEnabled = $true
    codeIntegrityEnabled = $true
    tpmRequired = $true
    antivirusRequired = $true
    antiSpywareRequired = $true
    defenderEnabled = $true
    firewallEnabled = $true
    passwordRequired = $true
    passwordMinimumLength = 12
    passwordRequiredType = "alphanumeric"
    storageRequireEncryption = $true
    scheduledActionsForRule = @(
        @{
            ruleName = "PasswordRequired"
            scheduledActionConfigurations = @(
                @{
                    actionType = "block"
                    gracePeriodHours = 24
                    notificationTemplateId = ""
                    notificationMessageCCList = @()
                }
            )
        }
    )
}

New-MgDeviceManagementDeviceCompliancePolicy -BodyParameter $compliancePolicy

# macOS Compliance Policy via Jamf Pro API
curl -X POST "https://jamf.company.com/api/v1/compliance-policies" \
  -H "Authorization: Bearer ${JAMF_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "Zero Trust - macOS Compliance",
    "rules": [
      {"type": "os_version", "operator": ">=", "value": "14.0"},
      {"type": "filevault_enabled", "value": true},
      {"type": "firewall_enabled", "value": true},
      {"type": "gatekeeper_enabled", "value": true},
      {"type": "sip_enabled", "value": true},
      {"type": "auto_update_enabled", "value": true},
      {"type": "screen_lock_timeout", "operator": "<=", "value": 300},
      {"type": "falcon_sensor_running", "value": true}
    ]
  }'
```

### Step 2: Configure CrowdStrike Zero Trust Assessment

Enable ZTA scoring and configure score thresholds for access tiers.

```bash
# CrowdStrike Falcon API: Query ZTA scores for all endpoints
curl -X GET "https://api.crowdstrike.com/zero-trust-assessment/entities/assessments/v1?ids=${DEVICE_AID}" \
  -H "Authorization: Bearer ${CS_TOKEN}" \
  -H "Content-Type: application/json"

# Response includes:
# {
#   "aid": "device-agent-id",
#   "assessment": {
#     "overall": 82,
#     "os": 90,
#     "sensor_config": 85,
#     "version": "7.14.16703"
#   },
#   "assessment_items": {
#     "os_signals": [
#       {"signal_id": "firmware_protection", "meets_criteria": "yes"},
#       {"signal_id": "disk_encryption", "meets_criteria": "yes"},
#       {"signal_id": "kernel_protection", "meets_criteria": "yes"}
#     ],
#     "sensor_signals": [
#       {"signal_id": "sensor_version", "meets_criteria": "yes"},
#       {"signal_id": "prevention_policies", "meets_criteria": "yes"}
#     ]
#   }
# }

# Define ZTA score thresholds for access tiers
# Tier 1 (Basic Access):      ZTA >= 50
# Tier 2 (Standard Access):   ZTA >= 65
# Tier 3 (Sensitive Access):  ZTA >= 80
# Tier 4 (Critical Access):   ZTA >= 90

# Query devices below minimum threshold
curl -X GET "https://api.crowdstrike.com/zero-trust-assessment/queries/assessments/v1?filter=assessment.overall:<50" \
  -H "Authorization: Bearer ${CS_TOKEN}"

# CrowdStrike ZTA signals evaluated:
# - OS patch level and version
# - Disk encryption (BitLocker/FileVault)
# - Sensor version and configuration
# - Prevention policy enforcement
# - Firmware protection (Secure Boot)
# - Kernel protection (SIP, Code Integrity)
# - Firewall status
```

### Step 3: Integrate Device Posture with Entra ID Conditional Access

Create conditional access policies that require compliant devices.

```powershell
# Create Conditional Access policy requiring compliant device
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

$caPolicy = @{
    displayName = "Zero Trust - Require Compliant Device"
    state = "enabled"
    conditions = @{
        applications = @{
            includeApplications = @("All")
        }
        users = @{
            includeUsers = @("All")
            excludeGroups = @("BreakGlass-Admins-Group-ID")
        }
        platforms = @{
            includePlatforms = @("all")
        }
        clientAppTypes = @("browser", "mobileAppsAndDesktopClients")
    }
    grantControls = @{
        operator = "AND"
        builtInControls = @("mfa", "compliantDevice")
    }
    sessionControls = @{
        signInFrequency = @{
            value = 4
            type = "hours"
            isEnabled = $true
            authenticationType = "primaryAndSecondaryAuthentication"
            frequencyInterval = "timeBased"
        }
        persistentBrowser = @{
            mode = "never"
            isEnabled = $true
        }
    }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $caPolicy

# Create risk-based policy using device compliance + sign-in risk
$riskPolicy = @{
    displayName = "Zero Trust - Block High Risk Sign-Ins on Non-Compliant Devices"
    state = "enabled"
    conditions = @{
        applications = @{ includeApplications = @("All") }
        users = @{ includeUsers = @("All") }
        signInRiskLevels = @("high", "medium")
        devices = @{
            deviceFilter = @{
                mode = "include"
                rule = "device.isCompliant -ne True"
            }
        }
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("block")
    }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $riskPolicy
```

### Step 4: Configure Okta Device Trust with CrowdStrike Integration

Set up Okta device trust policies using CrowdStrike posture signals.

```bash
# Okta: Configure CrowdStrike device trust integration
# Admin Console > Security > Device Integrations > Add Integration

# Okta API: Create device assurance policy
curl -X POST "https://company.okta.com/api/v1/device-assurances" \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "Corporate Device Assurance",
    "platform": "WINDOWS",
    "osVersion": {
      "minimum": "10.0.19045"
    },
    "diskEncryptionType": {
      "include": ["ALL_INTERNAL_VOLUMES"]
    },
    "screenLockType": {
      "include": ["BIOMETRIC", "PASSCODE"]
    },
    "secureHardwarePresent": true,
    "thirdPartySignalProviders": {
      "dtc": {
        "browserVersion": {
          "minimum": "120.0"
        },
        "builtInDnsClientEnabled": true,
        "chromeRemoteDesktopAppBlocked": true,
        "crowdStrikeCustomerId": "CS_CUSTOMER_ID",
        "crowdStrikeAgentId": "REQUIRED",
        "crowdStrikeVerifiedState": {
          "include": ["RUNNING"]
        }
      }
    }
  }'

# Create Okta authentication policy with device assurance
curl -X POST "https://company.okta.com/api/v1/policies" \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "Zero Trust Application Policy",
    "type": "ACCESS_POLICY",
    "conditions": null,
    "rules": [
      {
        "name": "Managed Device Access",
        "conditions": {
          "device": {
            "assurance": {
              "include": ["DEVICE_ASSURANCE_POLICY_ID"]
            },
            "managed": true,
            "registered": true
          },
          "people": {
            "groups": {"include": ["EMPLOYEES_GROUP_ID"]}
          }
        },
        "actions": {
          "appSignOn": {
            "access": "ALLOW",
            "verificationMethod": {
              "factorMode": "1FA",
              "type": "ASSURANCE"
            }
          }
        }
      },
      {
        "name": "Unmanaged Device - Block",
        "conditions": {
          "device": { "managed": false }
        },
        "actions": {
          "appSignOn": { "access": "DENY" }
        }
      }
    ]
  }'
```

### Step 5: Implement Continuous Posture Monitoring

Set up real-time monitoring of device compliance state changes.

```python
#!/usr/bin/env python3
"""Monitor device posture compliance drift in real-time."""

import requests
import time
import json
from datetime import datetime, timezone

CROWDSTRIKE_BASE = "https://api.crowdstrike.com"
INTUNE_BASE = "https://graph.microsoft.com/v1.0"

def get_cs_token(client_id: str, client_secret: str) -> str:
    resp = requests.post(f"{CROWDSTRIKE_BASE}/oauth2/token", data={
        "client_id": client_id,
        "client_secret": client_secret
    })
    return resp.json()["access_token"]

def get_low_zta_devices(token: str, threshold: int = 50) -> list:
    resp = requests.get(
        f"{CROWDSTRIKE_BASE}/zero-trust-assessment/queries/assessments/v1",
        headers={"Authorization": f"Bearer {token}"},
        params={"filter": f"assessment.overall:<{threshold}", "limit": 100}
    )
    return resp.json().get("resources", [])

def get_intune_noncompliant(token: str) -> list:
    resp = requests.get(
        f"{INTUNE_BASE}/deviceManagement/managedDevices",
        headers={"Authorization": f"Bearer {token}"},
        params={
            "$filter": "complianceState eq 'noncompliant'",
            "$select": "id,deviceName,userPrincipalName,complianceState,lastSyncDateTime,operatingSystem"
        }
    )
    return resp.json().get("value", [])

def check_posture_drift(cs_token: str, intune_token: str):
    print(f"\n[{datetime.now(timezone.utc).isoformat()}] Device Posture Check")
    print("=" * 60)

    low_zta = get_low_zta_devices(cs_token, threshold=50)
    print(f"CrowdStrike ZTA < 50: {len(low_zta)} devices")

    noncompliant = get_intune_noncompliant(intune_token)
    print(f"Intune Non-Compliant: {len(noncompliant)} devices")

    for device in noncompliant[:10]:
        print(f"  - {device['deviceName']} ({device['userPrincipalName']}): "
              f"{device['complianceState']} | Last sync: {device['lastSyncDateTime']}")

    return {"low_zta_count": len(low_zta), "noncompliant_count": len(noncompliant)}
```

## Key Concepts

| Term | Definition |
|------|------------|
| Device Posture | Collection of endpoint security attributes (OS version, encryption, EDR status, patch level) evaluated before granting access |
| CrowdStrike ZTA Score | Numerical score (1-100) calculated by CrowdStrike Falcon assessing endpoint security posture based on OS signals and sensor configuration |
| Device Compliance Policy | MDM-defined rules specifying minimum security requirements (encryption, PIN, OS version) that devices must meet |
| Conditional Access | Policy engine (Entra ID, Okta) that evaluates user identity, device compliance, location, and risk before allowing access |
| Device Trust | Verification that an endpoint is managed, enrolled, and meets security baselines before treating it as trusted |
| Posture Drift | Degradation of device security posture over time (expired patches, disabled encryption) that should trigger access revocation |

## Tools & Systems

- **CrowdStrike Falcon ZTA**: Real-time endpoint posture scoring based on OS and sensor security signals
- **Microsoft Intune**: MDM platform enforcing device compliance policies and reporting to Entra ID Conditional Access
- **Jamf Pro**: Apple device management with compliance rules for macOS and iOS endpoints
- **Microsoft Entra ID Conditional Access**: Policy engine consuming Intune compliance and risk signals for access decisions
- **Okta Device Trust**: Device assurance policies integrating with CrowdStrike, Chrome Enterprise, and MDM platforms
- **Cloudflare Device Posture**: WARP client-based posture checks for disk encryption, OS version, and third-party EDR

## Common Scenarios

### Scenario: Enforcing Device Compliance for 2,000 Endpoints Across Windows and macOS

**Context**: A healthcare company with 2,000 endpoints (70% Windows, 30% macOS) must enforce HIPAA-compliant device posture before allowing access to patient data systems. Devices are managed by Intune (Windows) and Jamf (macOS) with CrowdStrike Falcon deployed on all endpoints.

**Approach**:
1. Define Windows compliance policy in Intune: BitLocker, Secure Boot, TPM, Defender enabled, OS >= 10.0.19045
2. Define macOS compliance policy in Jamf: FileVault, Gatekeeper, SIP, Firewall, OS >= 14.0
3. Configure CrowdStrike ZTA thresholds: >= 70 for general apps, >= 85 for patient data systems
4. Create Entra ID Conditional Access policies requiring compliant device + MFA for all cloud apps
5. Configure 24-hour grace period for newly non-compliant devices before blocking
6. Set up weekly compliance report for IT showing non-compliant devices and remediation actions
7. Implement automated remediation via Intune: push BitLocker enablement, deploy pending patches

**Pitfalls**: Grace periods must be long enough for IT to remediate but short enough to limit risk exposure. CrowdStrike ZTA scores can fluctuate with sensor updates; avoid setting thresholds too aggressively initially. BYOD devices may lack MDM enrollment; provide a separate Browser Access path with reduced functionality for unmanaged devices.

## Output Format

```
Device Posture Assessment Report
==================================================
Organization: HealthCorp
Report Date: 2026-02-23
Total Managed Devices: 2,000

COMPLIANCE BY PLATFORM:
  Windows (1,400 devices):
    Compliant:              1,302 (93.0%)
    Non-compliant:            98 (7.0%)
    Top Issue: Missing patches (45), BitLocker disabled (23)

  macOS (600 devices):
    Compliant:                567 (94.5%)
    Non-compliant:             33 (5.5%)
    Top Issue: OS outdated (18), FileVault disabled (8)

CROWDSTRIKE ZTA SCORES:
  Average Score:              78.4
  Devices >= 85 (Critical):  1,456 (72.8%)
  Devices >= 70 (Standard):  1,812 (90.6%)
  Devices < 50 (Blocked):       34 (1.7%)

CONDITIONAL ACCESS IMPACT (last 7 days):
  Total sign-in attempts:    45,678
  Blocked by posture:           312 (0.7%)
  Remediated within 24h:        289 (92.6%)
  Still non-compliant:           23

POSTURE DRIFT ALERTS:
  Encryption disabled:            5
  EDR sensor stopped:             3
  OS downgraded:                  1
```
