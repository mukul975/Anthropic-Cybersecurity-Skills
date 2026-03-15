---
name: implementing-endpoint-dlp-controls
description: >
  Implements endpoint Data Loss Prevention (DLP) controls to detect and prevent sensitive data
  exfiltration through email, USB, cloud storage, and printing. Use when deploying DLP agents,
  creating content inspection policies, or preventing unauthorized data movement from endpoints.
  Activates for requests involving DLP, data exfiltration prevention, content inspection, or
  sensitive data protection on endpoints.
domain: cybersecurity
subdomain: endpoint-security
tags: [endpoint, DLP, data-loss-prevention, data-protection, content-inspection]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Implementing Endpoint DLP Controls

## When to Use

Use this skill when:
- Deploying endpoint DLP to prevent sensitive data (PII, PHI, PCI) from leaving the organization
- Configuring content inspection rules for email attachments, USB transfers, and cloud uploads
- Implementing Microsoft Purview DLP or Symantec DLP endpoint policies
- Meeting compliance requirements for data protection (GDPR, HIPAA, PCI DSS)

**Do not use** for network DLP (inline proxy-based) or cloud-only DLP (CASB).

## Prerequisites

- Microsoft 365 E5 or standalone Microsoft Purview DLP license
- Microsoft Purview compliance portal access (compliance.microsoft.com)
- Sensitive Information Types (SITs) defined for organization data
- Endpoint onboarded to Microsoft Purview (via Intune or SCCM)

## Workflow

### Step 1: Define Sensitive Information Types

```
Microsoft Purview → Data Classification → Sensitive info types

Built-in SITs for common data:
- Credit card number (PCI)
- Social Security Number (PII)
- Health records (HIPAA)
- Passport number
- Bank account number

Custom SIT example (Employee ID):
  Pattern: EMP-[0-9]{6}
  Confidence: High
  Keywords: "employee id", "emp id", "staff number"
```

### Step 2: Create DLP Policy

```
Microsoft Purview → Data loss prevention → Policies → Create policy

Policy Configuration:
1. Template: Financial / Medical / PII (or custom)
2. Locations: Devices (endpoint DLP)
3. Conditions:
   - Content contains: Credit card numbers (min 5 instances)
   - OR Content contains: SSN (min 1 instance)
4. Actions:
   - Block: Prevent copy to USB, cloud, email
   - Audit: Log but allow (for initial deployment)
   - Notify: Show user notification with policy tip
5. User notifications:
   - "This file contains sensitive data and cannot be copied to this location"
   - Allow override with business justification (optional)
```

### Step 3: Configure Endpoint DLP Activities

```
Monitored endpoint activities:
- Upload to cloud service (OneDrive, Dropbox, Google Drive)
- Copy to removable media (USB drives)
- Copy to network share
- Print document
- Copy to clipboard
- Access by unallowed browser (non-managed browser)
- Access by unallowed app
- Copy to Remote Desktop session

For each activity, configure:
- Audit only (log the action)
- Block with override (user can justify and proceed)
- Block (prevent action entirely)
```

### Step 4: Deploy in Audit Mode

```
Deploy DLP policy in "Test mode with notifications" first:
1. Policy runs in audit mode for 2-4 weeks
2. Review DLP alerts in Activity Explorer
3. Identify false positives
4. Tune SIT patterns and conditions
5. Add exclusions for legitimate workflows
6. Switch to "Turn on the policy" (enforcement)
```

### Step 5: Monitor and Respond

```
Purview → Data loss prevention → Activity explorer

Key metrics:
- DLP policy matches per day/week
- Top matched sensitive info types
- Top users triggering DLP
- Top activities blocked (USB, cloud, email)
- Override rate (percentage of blocks overridden)

DLP incident response:
1. Review DLP alert with matched content
2. Verify sensitivity of detected data
3. Assess intent (accidental vs. intentional)
4. If intentional exfiltration → escalate to security incident
5. If accidental → educate user, refine policy
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **DLP** | Data Loss Prevention; technology that detects and prevents unauthorized transmission of sensitive data |
| **SIT** | Sensitive Information Type; pattern matching rules for identifying sensitive data (regex, keywords, ML classifiers) |
| **Policy Tip** | User-facing notification explaining why an action was blocked and how to request an override |
| **Content Inspection** | Deep inspection of file contents to identify sensitive data patterns |
| **Exact Data Match (EDM)** | DLP matching against a specific database of known sensitive values (exact SSNs, employee records) |

## Tools & Systems

- **Microsoft Purview DLP**: Cloud-managed endpoint DLP included in M365 E5
- **Symantec DLP (Broadcom)**: Enterprise DLP with endpoint, network, and cloud modules
- **Digital Guardian**: Endpoint DLP with data classification and protection
- **Forcepoint DLP**: Unified DLP platform with endpoint agent
- **Code42 Incydr**: Insider risk detection with file exfiltration monitoring

## Common Pitfalls

- **Over-blocking in enforcement mode**: Deploy DLP in audit mode first. Blocking common workflows without warning causes productivity loss.
- **Too many SIT false positives**: Phone numbers, dates, and random number sequences can match PCI/SSN patterns. Tune confidence levels and require corroborating keywords.
- **Ignoring user education**: DLP is most effective when users understand why data is protected. Policy tips should explain the restriction and provide approved alternatives.
- **Not monitoring overrides**: If users frequently override DLP blocks, the policy is either too restrictive or users are ignoring data protection requirements. Review override reasons.
