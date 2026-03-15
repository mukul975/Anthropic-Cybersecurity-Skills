# Device Posture Assessment - Compliance Requirements Template

## Organization Information
| Field | Value |
|-------|-------|
| Organization | HealthCorp Medical |
| Total Endpoints | 2,000 |
| MDM Platform | Microsoft Intune (Windows), Jamf Pro (macOS) |
| EDR Platform | CrowdStrike Falcon |
| IdP | Microsoft Entra ID |

## Device Posture Tiers

### Tier 1: Basic Access (General Applications)
| Requirement | Windows | macOS | iOS/Android |
|------------|---------|-------|-------------|
| OS Version | >= 10.0.19045 | >= 14.0 | Latest -2 |
| Screen Lock | Enabled | Enabled | Enabled (6-digit PIN) |
| Encryption | Recommended | Recommended | Required |
| Firewall | Enabled | Enabled | N/A |
| CrowdStrike ZTA | >= 50 | >= 50 | N/A |
| Applications | Email, Wiki, Chat | Email, Wiki, Chat | Email, Chat |

### Tier 2: Standard Access (Business Applications)
| Requirement | Windows | macOS |
|------------|---------|-------|
| OS Version | >= 10.0.22621 | >= 14.0 |
| Screen Lock | Enabled, 5min timeout | Enabled, 5min timeout |
| Disk Encryption | BitLocker Required | FileVault Required |
| Firewall | Enabled | Enabled |
| Antivirus | Defender Active | XProtect Active |
| CrowdStrike ZTA | >= 65 | >= 65 |
| Secure Boot | Required | N/A |
| Applications | CRM, Internal Tools, Intranet | CRM, Internal Tools, Intranet |

### Tier 3: Enhanced Access (Sensitive Data)
| Requirement | Windows | macOS |
|------------|---------|-------|
| OS Version | >= 10.0.22631 (latest) | >= 15.0 (latest) |
| Disk Encryption | BitLocker + TPM | FileVault + Secure Enclave |
| CrowdStrike ZTA | >= 80 | >= 80 |
| Patch Level | Within 14 days of release | Within 14 days of release |
| Admin Approval | Device admin-approved | Device admin-approved |
| MDM Managed | Required | Required |
| Applications | Financial Systems, HR Data, Source Code | Financial Systems, HR Data |

### Tier 4: Critical Access (Regulated Data)
| Requirement | Windows | macOS |
|------------|---------|-------|
| CrowdStrike ZTA | >= 90 | >= 90 |
| Patch Level | Within 7 days | Within 7 days |
| Code Integrity | HVCI Enabled | SIP Enabled |
| Certificate | Corporate certificate present | Corporate certificate present |
| Geo Restriction | US only | US only |
| Applications | Patient Records (HIPAA), PCI Data | Patient Records (HIPAA) |

## Compliance Policy Assignments

| Policy | Device Group | Grace Period | Non-Compliance Action |
|--------|-------------|-------------|----------------------|
| Tier 1 Baseline | All Managed Devices | 72 hours | Email notification |
| Tier 2 Standard | Corporate Workstations | 48 hours | Mark non-compliant |
| Tier 3 Enhanced | Sensitive Data Users | 24 hours | Block access |
| Tier 4 Critical | HIPAA/PCI Users | 4 hours | Block access + alert SOC |

## CrowdStrike ZTA Score Mapping

| ZTA Score Range | Access Tier | Conditional Access Action |
|----------------|-------------|--------------------------|
| 90-100 | Tier 4 (Critical) | Allow all applications |
| 80-89 | Tier 3 (Enhanced) | Allow up to sensitive apps |
| 65-79 | Tier 2 (Standard) | Allow business apps only |
| 50-64 | Tier 1 (Basic) | Allow general apps only |
| < 50 | BLOCKED | Block all access, notify IT |

## Current Compliance Dashboard

| Metric | Target | Current | Status |
|--------|--------|---------|--------|
| Overall Compliance Rate | >= 95% | 93.2% | At Risk |
| Encryption Coverage | 100% | 97.8% | On Track |
| EDR Coverage | 100% | 99.1% | On Track |
| Average ZTA Score | >= 75 | 78.4 | Meeting |
| Devices Below ZTA 50 | 0 | 34 | Action Needed |
| Stale Devices (>30d) | < 1% | 0.8% | Meeting |
| Patch Compliance (14d) | >= 90% | 87.3% | At Risk |

## Remediation Actions

| Issue | Automated Remediation | Manual Escalation |
|-------|----------------------|-------------------|
| BitLocker Disabled | Intune policy pushes enablement | IT ticket after 24h |
| FileVault Disabled | Jamf policy enables FileVault | IT ticket after 24h |
| OS Outdated | Intune/Jamf pushes update | IT ticket after 48h |
| CrowdStrike Stopped | Auto-restart via watchdog | SOC alert after 30min |
| Firewall Disabled | GPO re-enables | IT ticket after 4h |

## Sign-Off

| Role | Name | Date | Approved |
|------|------|------|----------|
| CISO | _________________ | __________ | [ ] |
| IT Operations Director | _________________ | __________ | [ ] |
| Compliance Officer | _________________ | __________ | [ ] |
