---
name: implementing-anti-ransomware-group-policy
description: 'Configures Windows Group Policy Objects (GPO) to prevent ransomware
  execution and limit its spread. Implements AppLocker rules, Software Restriction
  Policies, Controlled Folder Access, attack surface reduction rules, and network
  protection settings. Activates for requests involving Windows GPO hardening against
  ransomware, AppLocker configuration, Controlled Folder Access setup, or endpoint
  protection via Group Policy.

  '
domain: cybersecurity
subdomain: ransomware-defense
tags:
- ransomware
- group-policy
- windows
- AppLocker
- hardening
- prevention
version: 1.0.0
author: mahipal
license: Apache-2.0
nist_csf:
- PR.DS-11
- RS.MA-01
- RC.RP-01
- PR.IR-01
mitre_attack:
- T1078
- T1190
- T1059
- T1486
- T1490
---

# Implementing Anti-Ransomware Group Policy

## When to Use

- Hardening a Windows Active Directory environment against ransomware execution and propagation
- Implementing defense-in-depth by blocking ransomware execution paths via Group Policy
- Configuring AppLocker or WDAC rules to prevent unauthorized executables from running in user-writable directories
- Enabling Controlled Folder Access to protect critical directories from unauthorized file modifications
- Restricting lateral movement vectors (RDP, SMB, WMI) that ransomware uses to spread across the domain

**Do not use** as a standalone ransomware defense. GPO settings complement but do not replace endpoint detection, backups, network segmentation, and user awareness training.

## Prerequisites

- Windows Server 2016+ Active Directory environment with Group Policy Management Console (GPMC)
- Domain Admin or Group Policy Creator Owners privileges
- Windows 10/11 Enterprise or Education (required for AppLocker and WDAC)
- Microsoft Defender Antivirus enabled (required for Controlled Folder Access and ASR rules)
- Python 3.8+ for audit script that validates GPO compliance
- Test OU for validating GPO settings before domain-wide deployment

## Workflow

### Step 1: Block Ransomware Execution Paths with AppLocker

Configure AppLocker to prevent executables from running in common ransomware staging locations:

```
AppLocker GPO Path:
  Computer Configuration → Policies → Windows Settings →
  Security Settings → Application Control Policies → AppLocker

Key Rules:
━━━━━━━━━
1. DENY executable rules for user-writable paths:
   - %USERPROFILE%\AppData\Local\Temp\*     (email attachment extraction)
   - %USERPROFILE%\AppData\Roaming\*         (CryptoLocker staging)
   - %USERPROFILE%\Downloads\*               (web downloads)
   - %TEMP%\*                                (temporary extraction)
   - %USERPROFILE%\Desktop\*                 (social engineering drops)

2. ALLOW default rules:
   - C:\Windows\* (signed by Microsoft)
   - C:\Program Files\* and C:\Program Files (x86)\*
   - Administrator group: all paths

3. Enable Application Identity service:
   Computer Configuration → Policies → Windows Settings →
   Security Settings → System Services →
   Application Identity → Automatic
```

### Step 2: Enable Controlled Folder Access

Protect critical directories from unauthorized modification:

```
Controlled Folder Access GPO Path:
  Computer Configuration → Administrative Templates →
  Windows Components → Microsoft Defender Antivirus →
  Microsoft Defender Exploit Guard → Controlled Folder Access

Settings:
━━━━━━━━━
1. Configure Controlled folder access: Enabled → Block mode
2. Configure protected folders: Add custom paths
   - \\fileserver\shares\finance
   - \\fileserver\shares\hr
   - C:\Users\*\Documents
   - C:\Users\*\Desktop

3. Configure allowed applications: Whitelist trusted apps
   - C:\Program Files\Microsoft Office\*
   - C:\Program Files\Adobe\*
   - Line-of-business applications

Default protected folders (automatic):
  Documents, Pictures, Videos, Music, Desktop, Favorites
```

### Step 3: Configure Attack Surface Reduction (ASR) Rules

Enable ASR rules that target ransomware delivery mechanisms:

```
ASR Rules GPO Path:
  Computer Configuration → Administrative Templates →
  Windows Components → Microsoft Defender Antivirus →
  Microsoft Defender Exploit Guard → Attack Surface Reduction

Critical ASR Rules for Ransomware Prevention:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
GUID                                    Rule
BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550   Block executable content from email
D4F940AB-401B-4EFC-AADC-AD5F3C50688A   Block Office apps from creating child processes
3B576869-A4EC-4529-8536-B80A7769E899   Block Office apps from creating executable content
75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84   Block Office apps from injecting into processes
D3E037E1-3EB8-44C8-A917-57927947596D   Block JavaScript/VBScript from launching downloads
5BEB7EFE-FD9A-4556-801D-275E5FFC04CC   Block execution of obfuscated scripts
92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B   Block Win32 API calls from Office macros
01443614-CD74-433A-B99E-2ECDC07BFC25   Block executable files unless they meet prevalence criteria

Set each rule to: Block (1) or Audit (2) for initial testing
```

### Step 4: Restrict Lateral Movement Vectors

Lock down SMB, RDP, and WMI to limit ransomware propagation:

```
Network Restrictions:
━━━━━━━━━━━━━━━━━━━━
1. Disable SMBv1:
   Computer Configuration → Administrative Templates →
   Network → Lanman Workstation → Enable insecure guest logons: Disabled

   Computer Configuration → Administrative Templates →
   MS Security Guide → Configure SMBv1 server: Disabled

2. Restrict Remote Desktop:
   Computer Configuration → Administrative Templates →
   Windows Components → Remote Desktop Services →
   Remote Desktop Session Host → Connections →
   Allow users to connect remotely: Disabled (or restricted to specific groups)

3. Disable remote WMI:
   Windows Firewall → Inbound Rules →
   Block Windows Management Instrumentation (WMI) inbound

4. Disable AutoPlay/AutoRun:
   Computer Configuration → Administrative Templates →
   Windows Components → AutoPlay Policies →
   Turn off AutoPlay: Enabled (All drives)

5. Disable PowerShell remoting for non-admin users:
   Computer Configuration → Administrative Templates →
   Windows Components → Windows PowerShell →
   Turn on Script Execution: Allow only signed scripts
```

### Step 5: Audit and Validate GPO Compliance

Verify that GPO settings are applied correctly across the domain:

```powershell
# Check GPO application on endpoint
gpresult /r /scope:computer

# Verify AppLocker rules
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections

# Check Controlled Folder Access status
Get-MpPreference | Select-Object EnableControlledFolderAccess

# List protected folders
Get-MpPreference | Select-Object -ExpandProperty ControlledFolderAccessProtectedFolders

# Check ASR rules
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions
```

## Verification

- Run `gpresult /r` on test endpoints to confirm GPO application
- Attempt to run an executable from `%AppData%\Temp` to verify AppLocker blocks it
- Modify a file in a protected folder from an unlisted application to confirm CFA blocks it
- Test ASR rules by opening a macro-enabled document and verifying child process blocking
- Validate that legitimate applications in the allowlist still function correctly
- Check Windows Event Log for AppLocker events (Event IDs 8003, 8004) and CFA events (1123, 1124)

## Key Concepts

| Term | Definition |
|------|------------|
| **AppLocker** | Windows application control feature that restricts which executables, scripts, and DLLs users can run based on publisher, path, or hash rules |
| **Controlled Folder Access** | Microsoft Defender feature that prevents untrusted applications from modifying files in protected directories |
| **Attack Surface Reduction (ASR)** | Set of rules in Microsoft Defender Exploit Guard that block specific attack behaviors like Office macro child processes |
| **Software Restriction Policies (SRP)** | Legacy Windows feature (deprecated in Win 11) for restricting executables; replaced by AppLocker and WDAC |
| **WDAC** | Windows Defender Application Control; the successor to AppLocker with stronger enforcement using code integrity policies |

## Tools & Systems

- **Group Policy Management Console (GPMC)**: Primary tool for creating and managing GPOs in Active Directory
- **AppLocker**: Built-in Windows application whitelisting and blacklisting engine
- **Microsoft Defender Exploit Guard**: Suite including CFA, ASR rules, and Network Protection
- **GPResult**: Command-line tool for verifying GPO application status on endpoints
- **PowerShell Get-MpPreference**: Cmdlet for querying Microsoft Defender configuration including ASR and CFA status
