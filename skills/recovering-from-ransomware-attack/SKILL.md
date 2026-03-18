---
name: recovering-from-ransomware-attack
description: >
  Executes structured recovery from a ransomware incident following NIST and CISA
  frameworks, including environment isolation, forensic evidence preservation, clean
  infrastructure rebuild, prioritized system restoration from verified backups,
  credential reset, and validation against re-infection. Covers Active Directory
  recovery, database restoration, and application stack rebuild in dependency order.
  Activates for requests involving ransomware recovery, post-encryption restoration,
  or disaster recovery from ransomware.
domain: cybersecurity
subdomain: ransomware-defense
tags: [ransomware, recovery, incident-response, backup, defense]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Recovering from Ransomware Attack

## When to Use

- After ransomware has encrypted production systems and the decision has been made to recover from backups
- When building or validating a ransomware recovery runbook before an actual incident
- After receiving a decryption key (paid ransom or law enforcement provided) and needing to safely decrypt
- When partial recovery is needed alongside decryption of remaining systems
- Conducting a recovery drill to validate RTO commitments

**Do not use** before completing containment and forensic scoping. Premature recovery without understanding the attacker's access and persistence mechanisms risks re-infection.

## Prerequisites

- Incident declared and containment phase completed (all attacker access severed)
- Forensic evidence preserved (disk images, memory dumps, network captures)
- Backup integrity verified (immutable/air-gapped copies confirmed clean)
- Clean build media available (OS installation media, golden images)
- Recovery environment prepared (clean network segment isolated from compromised infrastructure)
- Recovery priority list documented (Tier 1/2/3 systems in dependency order)

## Workflow

### Step 1: Establish Clean Recovery Environment

Build recovery infrastructure isolated from the compromised network:

```bash
# Create isolated recovery VLAN
# No connectivity to compromised network segments
# Dedicated internet access for patch downloads only (via proxy)

# Recovery network architecture:
# VLAN 999 (Recovery) - 10.99.0.0/24
#   - Recovery workstations (10.99.0.10-20)
#   - Recovered DCs (10.99.0.50-55)
#   - Recovered servers (10.99.0.100+)
#   - Proxy for internet (10.99.0.1) - patches and updates only

# Firewall rules: DENY all from recovery VLAN to production VLANs
# Allow: Recovery VLAN -> Internet (HTTPS only, via proxy)
# Allow: Recovery VLAN -> Backup infrastructure (restore traffic only)
```

### Step 2: Recover Identity Infrastructure First

Active Directory must be recovered before any domain-joined systems:

```powershell
# AD Recovery Procedure
# Step 2a: Restore AD from known-good backup
# Use DSRM (Directory Services Restore Mode) boot

# 1. Build clean Windows Server from ISO
# 2. Promote as DC using AD restore
# 3. Restore System State from immutable backup

# Verify AD backup is pre-compromise
# Check backup timestamp against earliest known compromise date
wbadmin get versions -backuptarget:E: -machine:DC01

# Restore system state in DSRM
wbadmin start systemstaterecovery -version:02/15/2026-04:00 -backuptarget:E: -machine:DC01 -quiet

# After restore, reset critical accounts
# Reset krbtgt password TWICE (invalidates all Kerberos tickets)
# This prevents Golden Ticket persistence
Import-Module ActiveDirectory
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString "NewKrbtgt2026!Complex#1" -AsPlainText -Force)
# Wait for replication (minimum 12 hours), then reset again
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString "NewKrbtgt2026!Complex#2" -AsPlainText -Force)

# Reset all privileged account passwords
$privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
foreach ($group in $privilegedGroups) {
    Get-ADGroupMember -Identity $group -Recursive | ForEach-Object {
        Set-ADAccountPassword -Identity $_.SamAccountName -Reset `
            -NewPassword (ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force)
        Set-ADUser -Identity $_.SamAccountName -ChangePasswordAtLogon $true
    }
}

# Validate AD health
dcdiag /v /c /d /e /s:DC01
repadmin /showrepl
```

### Step 3: Validate Backup Integrity Before Restoration

```bash
# Scan backup files for ransomware artifacts before restoring
# Use offline antivirus scanning on backup mount

# Mount backup as read-only
mount -o ro,noexec /dev/backup_lv /mnt/backup_verify

# Scan with ClamAV
clamscan -r --infected --log=/var/log/backup_scan.log /mnt/backup_verify

# Check for known ransomware indicators
find /mnt/backup_verify -name "*.encrypted" -o -name "*.locked" \
    -o -name "*.lockbit" -o -name "DECRYPT_*" -o -name "readme.txt" \
    -o -name "RECOVER-*" -o -name "HOW_TO_*" | tee /var/log/ransomware_check.log

# Verify database consistency (SQL Server example)
# Restore database to temporary instance for validation
RESTORE VERIFYONLY FROM DISK = '/mnt/backup_verify/databases/erp_db.bak'
    WITH CHECKSUM
```

### Step 4: Restore Systems in Priority Order

Follow dependency-based recovery sequence:

```
Recovery Order:
Phase 1 (Hours 0-4): Identity & Infrastructure
  1. Domain Controllers (AD, DNS, DHCP)
  2. Certificate Authority (if applicable)
  3. Core network services (DHCP, NTP)

Phase 2 (Hours 4-12): Critical Business Systems
  4. Database servers (SQL, Oracle, PostgreSQL)
  5. Core business applications (ERP, CRM)
  6. Email (Exchange, M365 hybrid)

Phase 3 (Hours 12-24): Important Systems
  7. File servers
  8. Web applications
  9. Monitoring and security tools (SIEM, EDR)

Phase 4 (Hours 24-48): Remaining Systems
  10. Development environments
  11. Archive systems
  12. Non-critical applications
```

```powershell
# Veeam Instant Recovery - fastest restore for VMware/Hyper-V
# Boots VM directly from backup file, then migrates to production storage

# Instant recovery for Tier 1 system
Start-VBRInstantRecovery -RestorePoint (Get-VBRRestorePoint -Name "DC01" |
    Sort-Object CreationTime -Descending | Select-Object -First 1) `
    -VMName "DC01-Recovered" `
    -Server (Get-VBRServer -Name "esxi01.recovery.local") `
    -Datastore "recovery-datastore"

# After validation, migrate to production storage
Start-VBRQuickMigration -VM "DC01-Recovered" `
    -Server (Get-VBRServer -Name "esxi01.prod.local") `
    -Datastore "production-datastore"
```

### Step 5: Validate Recovered Systems and Harden

Before connecting recovered systems to production:

```powershell
# Check for persistence mechanisms
# Scheduled Tasks
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} |
    Select-Object TaskName, TaskPath, State, Author |
    Export-Csv C:\recovery\scheduled_tasks.csv

# Services
Get-Service | Where-Object {$_.StartType -eq "Automatic"} |
    Select-Object Name, DisplayName, StartType, Status |
    Export-Csv C:\recovery\auto_services.csv

# Startup items
Get-CimInstance Win32_StartupCommand |
    Select-Object Name, Command, Location, User |
    Export-Csv C:\recovery\startup_items.csv

# WMI event subscriptions (common persistence)
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class __EventConsumer

# Registry run keys
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# Verify no unauthorized admin accounts
Get-LocalGroupMember -Group "Administrators"
Get-ADGroupMember -Identity "Domain Admins"

# Apply latest patches before connecting to production
Install-WindowsUpdate -AcceptAll -AutoReboot
```

### Step 6: Phased Network Reconnection

```
Phase 1: Reconnect identity infrastructure
  - DCs online in production VLAN
  - Validate replication and authentication
  - Monitor for suspicious authentication patterns

Phase 2: Reconnect Tier 1 systems
  - One system at a time
  - Monitor EDR for 1 hour before proceeding to next
  - Validate application functionality

Phase 3: Reconnect remaining systems
  - Groups of 5-10 systems
  - Continue monitoring for re-infection indicators

Throughout: SOC monitoring on high alert
  - EDR in aggressive blocking mode
  - All previous IOCs loaded in detection rules
  - Canary files deployed on recovered systems
```

## Key Concepts

| Term | Definition |
|------|------------|
| **DSRM** | Directory Services Restore Mode: special boot mode for domain controllers that allows AD database restoration |
| **krbtgt Reset** | Resetting the krbtgt account password twice invalidates all Kerberos tickets, defeating Golden Ticket persistence |
| **Instant Recovery** | Backup technology that boots a VM directly from backup storage for immediate availability while migrating data in background |
| **Evidence Preservation** | Maintaining forensic images and logs before recovery begins, required for law enforcement and insurance claims |
| **Clean Build** | Rebuilding systems from trusted installation media rather than attempting to clean infected systems |
| **Dependency Chain** | The order in which systems must be recovered based on service dependencies (e.g., AD before domain members) |

## Tools & Systems

- **Veeam Instant Recovery**: Boots VMs directly from backup with near-zero RTO, then live-migrates to production
- **Microsoft DSRM**: AD-specific recovery mode for restoring domain controllers from backup
- **DSInternals PowerShell Module**: Validates AD database integrity and identifies compromised credentials post-recovery
- **Rubrik Instant Recovery**: Mounts backup as live VM in seconds for rapid recovery validation
- **ClamAV**: Open-source antivirus for scanning backup files before restoration

## Common Scenarios

### Scenario: Manufacturing Company Full Recovery After LockBit Attack

**Context**: A manufacturer with 300 servers has 80% of infrastructure encrypted by LockBit. Immutable backups from 48 hours ago are verified clean. Production lines are down, costing $500K/day.

**Approach**:
1. Establish recovery VLAN (10.99.0.0/24) isolated from compromised network
2. Restore 2 domain controllers from immutable backup using Veeam Instant Recovery (2 hours)
3. Reset krbtgt password twice with 12-hour gap, reset all admin passwords
4. Validate AD with dcdiag, scan for Golden Ticket indicators with DSInternals
5. Restore ERP database (SAP) and verify data consistency (4 hours)
6. Restore MES (Manufacturing Execution System) and SCADA historians (3 hours)
7. Bring production line controllers online in isolated OT network first
8. Phased reconnection over 48 hours with continuous EDR monitoring
9. Total recovery: 72 hours (within 96-hour RTO commitment)

**Pitfalls**:
- Rushing to reconnect systems without validating absence of persistence mechanisms, causing re-infection
- Restoring from the most recent backup without verifying it predates the compromise (attacker may have poisoned recent backups)
- Not resetting the krbtgt password twice, allowing attackers to maintain Golden Ticket access
- Restoring systems in the wrong order (application servers before their database dependencies)

## Output Format

```
## Ransomware Recovery Status Report

**Incident ID**: [ID]
**Recovery Start**: [Timestamp]
**Current Phase**: [1-4]
**Estimated Completion**: [Timestamp]

### Recovery Progress
| Phase | Systems | Status | Started | Completed | RTO Target |
|-------|---------|--------|---------|-----------|------------|
| 1 - Identity | DC01, DC02, DNS | Complete | HH:MM | HH:MM | 4 hours |
| 2 - Critical | ERP, DB01, DB02 | In Progress | HH:MM | -- | 12 hours |
| 3 - Important | FS01, Email, Web | Pending | -- | -- | 24 hours |
| 4 - Remaining | Dev, Archive | Pending | -- | -- | 48 hours |

### Validation Checklist
- [ ] AD integrity verified (dcdiag, repadmin)
- [ ] krbtgt password reset (2x with interval)
- [ ] All admin passwords reset
- [ ] Persistence mechanisms scanned
- [ ] EDR deployed and active on recovered systems
- [ ] IOCs loaded in detection rules
- [ ] Canary files deployed
```
