---
name: deploying-ad-honeytokens-for-detection
description: >-
  Deploys decoy accounts, SPNs, and credentials in Active Directory to detect
  reconnaissance, Kerberoasting, credential theft, and lateral movement attempts.
  Honeytokens have no legitimate use; any access triggers high-confidence alerts
  for SIEM and EDR. Use when implementing deception-based detection, hardening AD
  against post-exploitation, detecting DCSync/Golden Ticket attacks, or augmenting
  ITDR (Identity Threat Detection and Response) capabilities. Covers deployment of
  decoy user accounts with high-privilege attributes, fake SPNs vulnerable to
  Kerberoasting, Group Policy honeypot objects, and SIEM correlation rules for
  Event IDs 4768, 4769, 4776. Mapped to MITRE ATT&CK T1003 (Credential Dumping),
  T1558 (Kerberoasting), and MITRE D3FEND D3-DUC (Decoy User Credential). Do not use for
  AdminCount=1, honeyroasting SPN and decoy-GPO cpassword trap patterns — use deploying-active-directory-honeytokens.
domain: cybersecurity
subdomain: deception-technology
tags:
- active-directory
- honeytokens
- deception
- kerberoasting
- credential-theft
- lateral-movement
- itdr
- decoy-accounts
- spn
- siem
version: "1.0"
author: dakshverma23
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.DP-04
mitre_attack:
- T1003
- T1558
- T1558.003
mitre_d3fend:
- D3-DUC
- D3-DACH
---

# Deploying Active Directory Honeytokens for Detection

## When to Use

- When implementing **deception-based detection** to catch attackers performing AD reconnaissance, credential theft, or lateral movement
- When **hardening Active Directory** security posture and seeking high-fidelity alerts (no false positives)
- After **penetration test findings** showing AD enumeration (BloodHound, SharpHound) or Kerberoasting attacks went undetected
- When deploying **ITDR (Identity Threat Detection and Response)** solutions like Microsoft Defender for Identity, SentinelOne Singularity Identity
- When **augmenting SIEM** with behavioral indicators beyond traditional log analysis (no legitimate user should touch honeytokens)
- During **incident response** to detect if attacker maintains persistence or continues reconnaissance
- When **legacy AD environments** lack modern EDR but have log aggregation (honeytokens work with Event Viewer + Splunk/ELK)

**Do not use** for:
- Basic AD honeytoken deployment - use **deploying-active-directory-honeytokens** for fundamental decoy accounts, SPNs, GPO traps, and BloodHound paths with Splunk/Sentinel detection
- This skill extends that foundation with multi-SIEM templates (Graylog, QRadar, LogRhythm, OSSIM), ACL honeypots, and DCSync/Golden Ticket detection; use the simpler skill first
- Sole security control (honeytokens are detection, not prevention); layer with PAM, LAPS, credential rotation, and Tier 0 segmentation

## Prerequisites

- **Domain Admin** or equivalent privileges to create users, modify SPNs, set ACLs
- Access to **Active Directory Users and Computers** (ADUC) or PowerShell RSAT cmdlets
- **SIEM or log aggregation** platform (Splunk, Microsoft Sentinel, ELK, Graylog) consuming Windows Security Event Logs
- **Domain Controllers** configured to forward Event IDs 4768 (Kerberos TGT Request), 4769 (Kerberos Service Ticket), 4776 (NTLM auth)
- Knowledge of **Kerberoasting attack vectors** (SPNs, GetUserSPNs.py, Rubeus)
- Understanding of **AD tiering model** (knowing where to place honeytokens for max attacker contact)
- **Naming convention** for honeytokens that appear legitimate (avoid "honeytoken", "decoy", "test")

## Workflow

### Phase 1: Design Honeytoken Strategy

**Honeytoken Types**:
1. Decoy User Accounts (SQL-Admin, Backup-Admin)
2. Decoy SPNs (Kerberoasting bait)
3. Decoy Credentials (scripts, config files)
4. Decoy ACLs (GenericAll permissions)

**Naming** (blend in):
- ✅ svc-sql-backup, adm-helpdesk-tier2, vmware-vcenter-svc
- ❌ honeytoken-user, decoy-admin, test-honeypot

**Placement**: Service Accounts OU, assign to security groups, enticing descriptions.



### Phase 2: Create Decoy User Accounts

```powershell
# Create decoy service account with SPN
New-ADUser -Name "svc-sql-backup" -SamAccountName "svc-sql-backup" `
           -UserPrincipalName "svc-sql-backup@corp.local" `
           -Description "SQL Server backup service - DO NOT MODIFY" `
           -Enabled $true -PasswordNeverExpires $true `
           -AccountPassword (ConvertTo-SecureString "NeverUsedP@ss123!" -AsPlainText -Force) `
           -Path "OU=Service Accounts,DC=corp,DC=local"

# Set SPN (Kerberoasting bait)
Set-ADUser -Identity "svc-sql-backup" -ServicePrincipalNames @{Add="MSSQLSvc/sql-backup.corp.local:1433"}

# Add to Domain Admins
Add-ADGroupMember -Identity "Domain Admins" -Members "svc-sql-backup"
```

**Batch Script** (see `scripts/Deploy-Honeytokens.ps1`).

### Phase 3: Configure SIEM Alerting

**Event IDs**: 4768 (TGT), 4769 (TGS/Kerberoasting), 4776 (NTLM), 4624 (logon), 4662 (LDAP)

**Splunk**:
```spl
index=wineventlog (EventCode=4768 OR EventCode=4769 OR EventCode=4776)
(TargetUserName="svc-sql-backup" OR TargetUserName="adm-tier1-backup")
| eval severity="critical", alert_message="🚨 HONEYTOKEN ACCESS"
| sendalert email to="security-team@corp.local"
```

**Microsoft Sentinel (KQL)**:
```kql
SecurityEvent
| where EventID in (4768, 4769, 4776, 4624)
| where TargetUserName in ("svc-sql-backup", "adm-tier1-backup")
| extend AlertSeverity = "High"
```

**Additional SIEM templates**: See `assets/siem-rules-templates.md` for Graylog, QRadar, LogRhythm, OSSIM.

### Phase 4: Detect Kerberoasting

**Indicator** (Event 4769):
- Service Name: honeytoken SPN
- Ticket Encryption: 0x17 (RC4) = Kerberoasting

**Splunk Detection**:
```spl
index=wineventlog EventCode=4769
(ServiceName="MSSQLSvc/sql-backup.corp.local" OR ServiceName="HTTP/vmware-mgmt.corp.local")
| eval is_kerberoast=if(TicketEncryptionType="0x17", "YES", "NO")
| where is_kerberoast="YES"
| sendalert pagerduty priority="critical"
```

**Microsoft Defender for Identity**: Automatically flags Kerberoasting against SPNs.

### Phase 5: Deploy Decoy Credentials

**PowerShell history**:
```powershell
$HistoryFile = (Get-PSReadlineOption).HistorySavePath
Add-Content -Path $HistoryFile -Value '$cred = Get-Credential -UserName "svc-sql-backup"'
```

**GPP cpassword** (attackers decrypt with Get-GPPPassword):
```xml
<!-- SYSVOL\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml -->
<User clsid="{DF5F1855}" name="svc-sql-backup" cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"/>
```

**Scripts**:
```powershell
# C:\Scripts\backup.ps1
$username = "corp\svc-sql-backup"
$password = ConvertTo-SecureString "NeverUsedP@ss!" -AsPlainText -Force
```

### Phase 6: Implement ACL Honeypots

Create fake permissions that appear in BloodHound graphs:

**Scenario**: Attacker runs BloodHound, sees honeytoken account has GenericAll on Domain Admins group

```powershell
# Grant honeytoken account GenericAll on Domain Admins (NEVER use legitimately)
$Identity = Get-ADUser "svc-sql-backup"
$Target = Get-ADGroup "Domain Admins"

$ACL = Get-ACL "AD:$($Target.DistinguishedName)"
$SID = [System.Security.Principal.SecurityIdentifier]$Identity.SID

$Rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $SID,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    [System.Security.AccessControl.AccessControlType]::Allow
)

$ACL.AddAccessRule($Rule)
Set-ACL -Path "AD:$($Target.DistinguishedName)" -AclObject $ACL

Write-Host "✓ Honeytoken svc-sql-backup now has GenericAll on Domain Admins (TRAP SET)"
```

**Detection**: Monitor Event ID 4662 (object access) for operations on Domain Admins group by honeytoken account.

```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4662
ObjectName="CN=Domain Admins,CN=Users,DC=corp,DC=local"
SubjectUserName="svc-sql-backup"
| eval alert="🚨 HONEYTOKEN PRIVILEGE ESCALATION ATTEMPT"
```

### Phase 7: Monitor for DCSync and Golden Ticket Attacks

**DCSync Detection** (Event 4662):
```spl
index=wineventlog EventCode=4662 ObjectType="domain"
Properties IN ("*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*", "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*")
(SubjectUserName="svc-sql-backup" OR SubjectUserName="adm-tier1-backup")
| eval alert="🚨 DCSYNC ATTACK - Honeytoken Requesting Replication"
```

**Golden Ticket**: Monitor Event 4768 for unusual TGT lifetime (10 years).

### Phase 8: Test Honeytoken Effectiveness

**Test Kerberoasting**:
```powershell
.\Rubeus.exe kerberoast /user:svc-sql-backup /nowrap
# Or: python3 GetUserSPNs.py -request -dc-ip 10.0.1.5 corp.local/normaluser:password
```
**Expected**: Event 4769 alert within seconds.

**Test Credential Usage**:
```powershell
$cred = Get-Credential -UserName "svc-sql-backup"
Test-Connection -ComputerName dc01.corp.local -Credential $cred
```
**Expected**: Event 4776/4768 alert.

**Test BloodHound**: Run SharpHound, verify honeytokens visible in graph.

## Key Concepts

| Term | Definition |
|------|------------|
| **Honeytoken** | Decoy credential, account, or object with no legitimate use; any access indicates compromise |
| **Kerberoasting** | Attack extracting Kerberos service tickets (TGS) for accounts with SPNs, cracking offline to obtain plaintext passwords |
| **SPN (Service Principal Name)** | Identifier linking service instance to AD account; required for Kerberos authentication; makes account Kerberoastable |
| **DCSync** | Attack simulating domain controller replication to extract password hashes (NTLM, Kerberos keys) for all domain users |
| **Golden Ticket** | Forged Kerberos TGT using compromised krbtgt account hash, granting unlimited domain access with arbitrary privileges |
| **ITDR (Identity Threat Detection & Response)** | Security category focused on detecting identity-based attacks (Kerberoasting, DCSync, lateral movement) in AD/Entra ID |
| **BloodHound** | Graph-based AD reconnaissance tool mapping attack paths to Domain Admins by analyzing ACLs, group memberships, and trusts |
| **Event ID 4768** | Kerberos TGT Request (initial authentication); logged on DC when user/service requests Ticket Granting Ticket |
| **Event ID 4769** | Kerberos Service Ticket Request; logged when TGS requested for SPN (Kerberoasting generates this for target SPNs) |
| **Deception Technology** | Security approach using decoys (honeypots, honeytokens, honey credentials) to detect attackers with high confidence |

## Tools & Systems

- **Microsoft Defender for Identity (MDI)**: Cloud-based ITDR detecting Kerberoasting, DCSync, Golden Ticket, Pass-the-Hash; automatic honeytoken integration
- **SentinelOne Singularity Identity**: Autonomous ITDR with real-time AD query monitoring and automated honeytoken deployment
- **Cayosoft Guardian**: AD security platform with built-in Kerberoasting detection via honeytoken SPNs
- **Splunk Enterprise Security**: SIEM with AD monitoring; custom correlation rules detect honeytoken access patterns
- **Microsoft Sentinel**: Cloud-native SIEM consuming Windows Security Events; KQL queries detect honeytoken triggers
- **BloodHound**: AD attack path analyzer; used by attackers but also defenders to verify honeytoken visibility
- **Rubeus**: C# Kerberos abuse toolkit; used to test Kerberoasting detection against honeytoken SPNs
- **Impacket**: Python toolkit for SMB/Kerberos attacks; GetUserSPNs.py extracts SPNs (including honeytokens)
- **CyberArk EPM / BeyondTrust**: PAM solutions with honeytoken integration for privileged account monitoring

## Common Scenarios

### Scenario: Post-Phishing Reconnaissance

**Context**: Employee phished, attacker runs BloodHound, discovers honeytoken "svc-sql-backup", performs Kerberoasting. SOC receives critical alert within 30 seconds.

**Response**:
1. Isolate compromised workstation via EDR
2. Disable user account, reset password
3. Review PowerShell logs, Sysmon events, network connections
4. Extract Rubeus artifacts, check for Mimikatz
5. Remove persistence, reimage workstation, rotate credentials

### Scenario: Mass Kerberoasting

**Context**: Automated script extracts 50+ TGS tickets including 3 honeytokens. SOC receives burst of alerts in 2-minute window.

**Response**:
1. Correlate honeytoken + legitimate SPN requests = mass attack
2. Identify all SPNs requested, correlate with EDR
3. Rotate passwords for ALL requested SPNs
4. Disable RC4 encryption, audit SPN assignments
5. Deploy additional diverse honeytokens

## Output Format

```
AD HONEYTOKEN DETECTION ALERT
==============================
Alert ID: SOC-2026-07-15-0042 | Timestamp: 2026-07-15 14:23:17 UTC
Severity: CRITICAL | Confidence: HIGH (No False Positives)

HONEYTOKEN ACCESSED
━━━━━━━━━━━━━━━━━━━
Account: svc-sql-backup | SPN: MSSQLSvc/sql-backup.corp.local:1433
Attack: Kerberoasting (TGS + RC4)

SOURCE
━━━━━━
Workstation: WKS-MARKETING-042 | IP: 10.2.45.78
User: CORP\jdoe | Process: powershell.exe (PID 3842)
Command: powershell.exe -ep bypass -c "IEX (...Invoke-Kerberoast.ps1)"

EVENT DETAILS
━━━━━━━━━━━━━
Event 4769 | DC: DC01.corp.local | Encryption: RC4-HMAC-MD5

TIMELINE
━━━━━━━━
14:20:15  jdoe logs in
14:22:45  PowerShell downloads Invoke-Kerberoast.ps1 from 192.168.1.99
14:23:12  TGS requests for 50 SPNs (3 honeytokens)
14:23:17  🚨 ALERT TRIGGERED

ACTIONS
━━━━━━━
1. [NOW] Isolate WKS-MARKETING-042, disable CORP\jdoe
2. [URGENT] Rotate ALL SPN passwords
3. [24H] Forensics: memory dump, disk image
4. [48H] Disable RC4 encryption domain-wide

MITRE ATT&CK: T1558.003 (Kerberoasting)
```

## Verification Checklist

- [ ] Honeytoken accounts created with realistic names (not "test", "decoy", "honey")
- [ ] SPNs configured on honeytoken accounts (makes them Kerberoastable)
- [ ] Passwords set to complex values (prevent accidental compromise)
- [ ] `PasswordNeverExpires` enabled (prevents lockout from failed attempts)
- [ ] Accounts added to high-privilege groups (Domain Admins, Enterprise Admins)
- [ ] SIEM rules configured for Event IDs 4768, 4769, 4776, 4624, 4662
- [ ] Alert severity set to CRITICAL (no false positives expected)
- [ ] SOC runbook created for honeytoken alert response
- [ ] Test Kerberoasting performed; alert validated within 60 seconds
- [ ] BloodHound graph verified; honeytokens visible in attack paths
- [ ] Decoy credentials planted in scripts, GPP, config files
- [ ] ACL honeypots configured (GenericAll on sensitive groups)
- [ ] DCSync detection enabled (Event 4662 replication requests)
- [ ] Monthly honeytoken audit scheduled (verify still deployed, not disabled)
- [ ] Honeytoken account list documented and secured (access restricted to SOC)

