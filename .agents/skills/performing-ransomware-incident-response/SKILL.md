---
name: performing-ransomware-incident-response
description: Execute a structured ransomware incident response including containment, decryption assessment, recovery from backups, and eradication of ransomware persistence mechanisms.
domain: cybersecurity
subdomain: incident-response
tags: [incident-response, ransomware, dfir, recovery, eradication, encryption]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Ransomware Incident Response

## When to Use
- Ransomware encryption detected on one or more endpoints
- Ransom note files discovered on file shares or endpoints
- File extensions changed to known ransomware variants (.locked, .encrypted, .ryuk, etc.)
- Volume Shadow Copies deleted or backup systems targeted
- EDR/AV alerts for known ransomware families (LockBit, BlackCat/ALPHV, Cl0p, Royal, Play)

## Prerequisites
- Incident Response Plan with ransomware-specific playbook
- Offline/immutable backup infrastructure
- EDR platform with ransomware rollback capability
- No Ransom (nomoreransom.org) decryptor database access
- Network segmentation capability for rapid isolation
- Communication plan for stakeholders and potentially law enforcement

## Workflow

### Step 1: Detect and Confirm Ransomware
```bash
# Check for ransom note files across file shares
find /mnt/shares -name "README*.txt" -o -name "DECRYPT*.txt" -o -name "HOW_TO_RECOVER*" \
  -o -name "RESTORE_FILES*" -newer /tmp/baseline_timestamp 2>/dev/null

# Check for mass file encryption indicators
find /mnt/shares -name "*.encrypted" -o -name "*.locked" -o -name "*.BlackCat" \
  -o -name "*.lockbit" -mmin -60 2>/dev/null | head -50

# Identify ransomware variant from ransom note
strings ransom_note.txt | grep -iE "(bitcoin|wallet|tor|onion|decrypt|payment)"

# Upload sample to ID Ransomware for variant identification
curl -X POST "https://id-ransomware.malwarehunterteam.com/api/upload" \
  -F "ransom_note=@ransom_note.txt" -F "encrypted_file=@sample.encrypted"
```

### Step 2: Isolate Infected Systems Immediately
```bash
# CrowdStrike Falcon - Mass contain infected hosts
for device_id in $(cat infected_device_ids.txt); do
  curl -X POST "https://api.crowdstrike.com/devices/entities/devices-actions/v2?action_name=contain" \
    -H "Authorization: Bearer $FALCON_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"ids\": [\"$device_id\"]}"
done

# Block known ransomware C2 IPs at firewall
while read ip; do
  iptables -A INPUT -s "$ip" -j DROP
  iptables -A OUTPUT -d "$ip" -j DROP
done < ransomware_c2_ips.txt

# Disable SMB/lateral movement protocols between segments
# Palo Alto firewall
set rulebase security rules block-smb-lateral from internal to internal application ms-ds-smb action deny
commit force
```

### Step 3: Assess Encryption Scope and Impact
```bash
# Splunk query - identify affected hosts by file modification patterns
index=endpoint sourcetype=sysmon EventCode=11
| stats dc(TargetFilename) as files_created by Computer
| where files_created > 1000
| sort -files_created

# Check if Volume Shadow Copies were deleted
wevtutil qe Application /q:"*[System[Provider[@Name='VSS']]]" /f:text /c:20

# Check backup integrity
veeam-backup-check --repository "primary_backup" --verify-integrity
restic -r /backup/repo check --read-data-subset=1/10
```

### Step 4: Check for Available Decryptors
```bash
# Check No More Ransom project for free decryptors
# https://www.nomoreransom.org/en/decryption-tools.html

# Check Kaspersky decryptor database
# https://noransom.kaspersky.com/

# Check Emsisoft decryptor database
# https://www.emsisoft.com/en/ransomware-decryption/

# Test if files can be recovered from shadow copies (if not deleted)
vssadmin list shadows
mklink /D C:\ShadowCopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\

# Check previous file versions
wmic shadowcopy list brief
```

### Step 5: Eradicate Ransomware and Persistence
```bash
# Scan all systems for ransomware artifacts
yara -r ransomware_rules.yar /mnt/infected_disk/

# Check common persistence locations
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /s
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /s
schtasks /query /fo CSV /v | findstr /i "encrypt lock ransom"

# Check for ransomware loader in Group Policy
find /mnt/sysvol -name "*.exe" -o -name "*.dll" -o -name "*.bat" -newer /tmp/baseline

# Remove ransomware artifacts
# After forensic imaging is complete
Get-ChildItem -Path C:\ -Include *.encrypted,*.locked -Recurse | Remove-Item -Force
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "malicious_entry" /f
```

### Step 6: Recover Systems from Clean Backups
```bash
# Verify backup integrity before restoration
sha256sum backup_image_server01.vhdx
restic -r /backup/repo restore latest --target /mnt/restore --verify

# Restore from Veeam backup
# Veeam PowerShell
Start-VBRRestoreSession -BackupObject (Get-VBRBackup -Name "Server01_Backup") \
  -RestorePoint (Get-VBRRestorePoint -Backup "Server01_Backup" | Sort-Object -Property CreationTime -Descending | Select-Object -First 1)

# Rebuild from golden images if backups compromised
packer build -var "os_version=2022" golden_image.pkr.hcl
terraform apply -var="image_id=ami-golden-2024" -auto-approve
```

### Step 7: Post-Recovery Validation
```bash
# Verify no ransomware persistence remains
Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Name, Command, Location
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Select-Object TaskName, TaskPath

# Verify file integrity post-restore
fciv -r C:\restored_data\ -sha256 > post_restore_hashes.txt
diff pre_infection_hashes.txt post_restore_hashes.txt

# Enhanced monitoring for re-infection
# Deploy canary files in sensitive directories
for dir in /mnt/shares/*/; do
  echo "CANARY_$(date +%s)" > "$dir/.canary_monitor.txt"
done
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Double Extortion | Attacker encrypts data AND exfiltrates it, threatening public release |
| Triple Extortion | Adding DDoS threats or contacting victims' customers to increase pressure |
| Ransomware-as-a-Service (RaaS) | Criminal business model where affiliates pay operators for ransomware tools |
| Decryptor Availability | Free decryptors may exist for some ransomware families via No More Ransom |
| Immutable Backups | Backup copies that cannot be modified or deleted, critical for ransomware recovery |
| Dwell Time | Time between initial compromise and ransomware deployment (often weeks) |
| IOC Sharing | Sharing indicators with ISACs and law enforcement improves collective defense |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| ID Ransomware | Identify ransomware variant from samples |
| No More Ransom | Free decryptor database (nomoreransom.org) |
| CrowdStrike Falcon | Endpoint containment and ransomware rollback |
| Veeam/Commvault | Backup verification and restoration |
| YARA | Ransomware artifact scanning |
| Volatility | Memory forensics for ransomware analysis |
| Splunk/Elastic | Log analysis for encryption scope assessment |

## Common Scenarios

1. **LockBit 3.0 Enterprise Attack**: Attacker compromises VPN, deploys LockBit across domain via GPO. Isolate domain controllers first, verify backup integrity, restore from immutable backups.
2. **BlackCat/ALPHV Double Extortion**: Data exfiltrated before encryption. Engage legal for breach notification, restore from backups, negotiate through authorized channels if needed.
3. **Cl0p MOVEit Exploitation**: Mass exploitation of file transfer application. Patch vulnerability, identify exfiltrated data, rebuild affected systems.
4. **Targeted Healthcare Ransomware**: Patient data encrypted. Activate emergency manual procedures, engage HHS, prioritize clinical system recovery.
5. **Ransomware via Compromised MSP**: Attacker accesses multiple clients through MSP tools. Disconnect MSP access, contain per-client, coordinate multi-tenant response.

## Output Format
- Ransomware variant identification report
- Encryption scope assessment with affected systems list
- Backup integrity verification results
- Recovery timeline and prioritized restoration plan
- Eradication verification report
- Lessons learned document with prevention recommendations
