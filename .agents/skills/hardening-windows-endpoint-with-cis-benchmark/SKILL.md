---
name: hardening-windows-endpoint-with-cis-benchmark
description: >
  Hardens Windows endpoints using CIS (Center for Internet Security) Benchmark recommendations
  to reduce attack surface, enforce security baselines, and meet compliance requirements. Use when
  deploying new Windows workstations or servers, remediating audit findings, or establishing
  organization-wide security baselines. Activates for requests involving Windows hardening,
  CIS benchmarks, GPO security baselines, or endpoint configuration compliance.
domain: cybersecurity
subdomain: endpoint-security
tags: [endpoint, hardening, windows-security, CIS-benchmark, GPO, baseline-configuration]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Hardening Windows Endpoint with CIS Benchmark

## When to Use

Use this skill when:
- Deploying new Windows 10/11 or Server 2019/2022 endpoints that require security hardening
- Establishing organization-wide security baselines using CIS Level 1 or Level 2 profiles
- Remediating findings from compliance audits (PCI DSS, HIPAA, SOC 2) that reference CIS benchmarks
- Validating existing endpoint configurations against current CIS benchmark versions

**Do not use** this skill for Linux endpoints (use hardening-linux-endpoint-with-cis-benchmark) or for cloud-native workloads that require CIS cloud benchmarks.

## Prerequisites

- Windows 10/11 Enterprise or Windows Server 2019/2022 target endpoints
- Active Directory Group Policy Management Console (GPMC) for enterprise deployment
- CIS-CAT Pro Assessor or CIS-CAT Lite for automated benchmark assessment
- Administrative access to target endpoints or domain controller
- Current CIS Benchmark PDF for the target Windows version (download from cisecurity.org)

## Workflow

### Step 1: Select CIS Benchmark Profile Level

CIS provides two profile levels for Windows endpoints:

**Level 1 (L1) - Corporate/Enterprise Environment**:
- Practical hardening settings that can be applied to most organizations
- Minimal impact on functionality and user experience
- Covers: password policy, audit policy, user rights, security options, Windows Firewall

**Level 2 (L2) - High Security/Sensitive Data**:
- Includes all L1 settings plus additional restrictions
- May impact usability (disabling autorun, restricting remote desktop, enhanced audit logging)
- Appropriate for systems handling PII, PHI, PCI data, or classified information

Select profile based on data classification and risk tolerance of the endpoint.

### Step 2: Import CIS GPO Baselines

CIS provides pre-built GPO templates (Build Kits) for each benchmark version:

```powershell
# Download CIS Build Kit from CIS WorkBench (requires CIS SecureSuite membership)
# Extract the GPO backup to a staging directory

# Import the CIS GPO into Active Directory
Import-GPO -BackupGpoName "CIS Microsoft Windows 11 Enterprise v3.0.0 L1" `
  -TargetName "CIS-Win11-L1-Baseline" `
  -Path "C:\CIS-GPO-Backups\Win11-Enterprise" `
  -CreateIfNeeded

# Link GPO to target OU
New-GPLink -Name "CIS-Win11-L1-Baseline" `
  -Target "OU=Workstations,DC=corp,DC=example,DC=com" `
  -LinkEnabled Yes
```

### Step 3: Apply Key CIS Benchmark Categories

**Account Policies (Section 1)**:
```
Password Policy:
  - Minimum password length: 14 characters (1.1.4)
  - Maximum password age: 365 days (1.1.3)
  - Password complexity: Enabled (1.1.5)
  - Store passwords using reversible encryption: Disabled (1.1.6)

Account Lockout Policy:
  - Account lockout threshold: 5 invalid logon attempts (1.2.1)
  - Account lockout duration: 15 minutes (1.2.2)
  - Reset account lockout counter after: 15 minutes (1.2.3)
```

**Local Policies - Audit Policy (Section 17)**:
```
Audit Policy Configuration:
  - Audit Credential Validation: Success and Failure (17.1.1)
  - Audit Security Group Management: Success (17.2.5)
  - Audit Logon: Success and Failure (17.5.1)
  - Audit Process Creation: Success (17.6.1)
  - Audit Removable Storage: Success and Failure (17.6.4)
```

**Security Options (Section 2.3)**:
```
  - Interactive logon: Do not display last user name: Enabled (2.3.7.1)
  - Interactive logon: Machine inactivity limit: 900 seconds (2.3.7.3)
  - Network access: Do not allow anonymous enumeration of SAM accounts: Enabled (2.3.10.2)
  - Network security: LAN Manager authentication level: Send NTLMv2 response only (2.3.11.7)
  - UAC: Run all administrators in Admin Approval Mode: Enabled (2.3.17.6)
```

**Windows Firewall (Section 9)**:
```
  - Domain Profile: Firewall state: On (9.1.1)
  - Domain Profile: Inbound connections: Block (9.1.2)
  - Private Profile: Firewall state: On (9.2.1)
  - Public Profile: Firewall state: On (9.3.1)
  - Public Profile: Inbound connections: Block (9.3.2)
```

### Step 4: Validate with CIS-CAT Assessment

```powershell
# Run CIS-CAT Pro Assessor against target endpoint
# CIS-CAT produces an HTML/XML report with pass/fail per recommendation

.\Assessor-CLI.bat `
  -b "benchmarks\CIS_Microsoft_Windows_11_Enterprise_Benchmark_v3.0.0-xccdf.xml" `
  -p "Level 1 (L1) - Corporate/Enterprise Environment" `
  -rd "C:\CIS-Reports" `
  -nts

# Review report for failed controls
# Score target: 95%+ for L1, 90%+ for L2 (due to operational exceptions)
```

### Step 5: Document Exceptions and Compensating Controls

For each CIS recommendation that cannot be applied:
1. Document the specific recommendation ID and title
2. State the business justification for the exception
3. Define the compensating control that addresses the residual risk
4. Set a review date (quarterly) to reassess the exception
5. Obtain sign-off from the information security officer

Example exception:
```
Recommendation: 2.3.7.3 - Interactive logon: Machine inactivity limit: 900 seconds
Exception: Kiosk systems in manufacturing floor require 1800 seconds
Compensating Control: Physical badge-access to manufacturing area, CCTV monitoring
Review Date: 2026-06-01
Approved By: CISO
```

### Step 6: Continuous Compliance Monitoring

Configure recurring CIS-CAT scans via scheduled tasks or SCCM:
```powershell
# Create scheduled task for weekly CIS-CAT assessment
$action = New-ScheduledTaskAction -Execute "C:\CIS-CAT\Assessor-CLI.bat" `
  -Argument "-b benchmarks\CIS_Win11_v3.0.0-xccdf.xml -p Level1 -rd C:\CIS-Reports -nts"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2am
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "CIS-Benchmark-Scan" -Action $action `
  -Trigger $trigger -Principal $principal
```

Feed results into SIEM for drift detection and dashboard reporting.

## Key Concepts

| Term | Definition |
|------|-----------|
| **CIS Benchmark** | Consensus-based security configuration guide developed by CIS with input from government, industry, and academia |
| **Level 1 Profile** | Practical security baseline suitable for most organizations with minimal operational impact |
| **Level 2 Profile** | Extended security baseline for high-security environments that may reduce functionality |
| **CIS-CAT** | CIS Configuration Assessment Tool that automates benchmark compliance checking |
| **Build Kit** | Pre-configured GPO templates provided by CIS that implement benchmark recommendations |
| **Scoring** | CIS recommendations are either Scored (compliance-measurable) or Not Scored (best-practice guidance) |

## Tools & Systems

- **CIS-CAT Pro Assessor**: Automated benchmark compliance scanner (requires CIS SecureSuite license)
- **Microsoft Security Compliance Toolkit (SCT)**: Microsoft's own GPO baselines (complementary to CIS)
- **Group Policy Management Console (GPMC)**: Enterprise GPO deployment and management
- **LGPO.exe**: Microsoft tool for applying GPOs to standalone (non-domain) systems
- **Nessus/Tenable**: Vulnerability scanner with CIS benchmark audit files

## Common Pitfalls

- **Applying L2 to all endpoints**: Level 2 restrictions (disabling Autoplay, restricting Remote Desktop) break workflows on standard workstations. Reserve L2 for endpoints handling sensitive data.
- **Not testing GPOs in pilot OU**: Deploy CIS GPOs to a test OU with representative hardware/software before organization-wide rollout to avoid breaking line-of-business applications.
- **Ignoring CIS benchmark version updates**: CIS benchmarks update with each Windows feature release. Running an outdated benchmark misses new security settings and generates false compliance reports.
- **Forgetting local admin accounts**: CIS benchmarks assume domain-joined endpoints. Standalone systems require LGPO.exe or Microsoft Intune for baseline enforcement.
- **No exception process**: Applying 100% of CIS recommendations is rarely feasible. Without a formal exception process, teams either ignore hardening or break applications.
