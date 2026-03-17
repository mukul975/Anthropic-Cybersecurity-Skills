---
name: building-soc-playbook-for-ransomware
description: >
  Builds a structured SOC incident response playbook for ransomware attacks covering detection,
  containment, eradication, and recovery phases with specific SIEM queries, isolation procedures,
  and decision trees. Use when SOC teams need formalized response procedures for ransomware
  incidents aligned to NIST SP 800-61 and MITRE ATT&CK ransomware techniques.
domain: cybersecurity
subdomain: soc-operations
tags: [soc, ransomware, incident-response, playbook, nist, mitre-attack, containment]
mitre_attack: ["T1486", "T1490", "T1489", "T1570"]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Building SOC Playbook for Ransomware

## When to Use

Use this skill when:
- SOC teams need a standardized ransomware response playbook for Tier 1-3 analysts
- An organization lacks documented procedures for ransomware containment and recovery
- Tabletop exercises reveal gaps in ransomware response coordination
- Compliance requirements (NIST CSF, ISO 27001) mandate documented incident playbooks

**Do not use** during an active ransomware incident as the sole guide — have pre-built playbooks tested and rehearsed before incidents occur.

## Prerequisites

- SIEM platform (Splunk ES, Elastic Security, or Sentinel) with endpoint and network data
- EDR solution (CrowdStrike, SentinelOne, or Microsoft Defender for Endpoint) with network isolation capability
- Backup infrastructure with tested recovery procedures and offline/immutable backups
- Communication plan with legal, executive leadership, and external IR retainer contacts
- MITRE ATT&CK knowledge for ransomware technique chains

## Workflow

### Step 1: Define Detection Triggers

Create SIEM detection rules for early ransomware indicators:

**Mass File Encryption Detection (Splunk):**
```spl
index=sysmon EventCode=11
| bin _time span=1m
| stats dc(TargetFilename) AS unique_files, values(TargetFilename) AS sample_files by Computer, Image, _time
| where unique_files > 100
| eval suspicious_extensions = if(match(mvjoin(sample_files, ","), "\.(encrypted|locked|crypt|enc|ransom)"), "YES", "NO")
| where suspicious_extensions="YES" OR unique_files > 500
| sort - unique_files
```

**Shadow Copy Deletion (T1490):**
```spl
index=wineventlog sourcetype="WinEventLog:Security" OR index=sysmon EventCode=1
(CommandLine="*vssadmin*delete*shadows*" OR CommandLine="*wmic*shadowcopy*delete*"
 OR CommandLine="*bcdedit*/set*recoveryenabled*no*" OR CommandLine="*wbadmin*delete*catalog*")
| table _time, Computer, User, ParentImage, Image, CommandLine
```

**Ransomware Note File Creation:**
```spl
index=sysmon EventCode=11
TargetFilename IN ("*README*.txt", "*DECRYPT*.txt", "*RANSOM*.txt", "*RECOVER*.html", "*HOW_TO*.txt")
| stats count by Computer, Image, TargetFilename
| where count > 5
```

**Elastic Security EQL variant:**
```eql
sequence by host.name with maxspan=2m
  [process where event.type == "start" and
    process.args : ("*vssadmin*", "*delete*", "*shadows*")]
  [file where event.type == "creation" and
    file.name : ("*README*DECRYPT*", "*RANSOM*", "*HOW_TO_RECOVER*")]
```

### Step 2: Build Triage Decision Tree

```
RANSOMWARE ALERT TRIAGE
│
├── Is encryption actively occurring?
│   ├── YES → IMMEDIATE: Isolate host from network (Step 3)
│   │         Do NOT power off (preserve memory for forensics)
│   └── NO → Is this a pre-encryption indicator?
│       ├── Shadow copy deletion → HIGH PRIORITY: Isolate and investigate
│       ├── Known ransomware hash → HIGH PRIORITY: Block hash, scan enterprise
│       └── Suspicious process behavior → MEDIUM: Investigate, prepare isolation
│
├── How many hosts affected?
│   ├── Single host → Contained incident, follow host isolation procedure
│   ├── Multiple hosts (2-10) → Escalate to Tier 2, begin enterprise-wide scan
│   └── Enterprise-wide (>10) → Activate full IR team, engage external retainer
│
└── Is data exfiltration confirmed?
    ├── YES → Double extortion scenario, engage legal for breach notification
    └── NO/UNKNOWN → Check for Cobalt Strike/C2 beacons, review outbound transfers
```

### Step 3: Containment Procedures

**Network Isolation via EDR (CrowdStrike Falcon):**
```bash
# Isolate host using CrowdStrike Falcon API
curl -X POST "https://api.crowdstrike.com/devices/entities/devices-actions/v2?action_name=contain" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ids": ["device_id_here"]}'
```

**Network Isolation via Microsoft Defender for Endpoint:**
```powershell
# Isolate machine via MDE API
$headers = @{Authorization = "Bearer $token"}
$body = @{Comment = "Ransomware containment - IR-2024-0500"; IsolationType = "Full"} | ConvertTo-Json
Invoke-RestMethod -Uri "https://api.securitycenter.microsoft.com/api/machines/$machineId/isolate" `
    -Method Post -Headers $headers -Body $body -ContentType "application/json"
```

**Firewall Emergency Rules:**
```
# Palo Alto — Block SMB lateral spread
set rulebase security rules RansomwareContainment from Trust to Trust
set rulebase security rules RansomwareContainment application ms-ds-smb
set rulebase security rules RansomwareContainment action deny
set rulebase security rules RansomwareContainment disabled no
commit
```

**Active Directory Emergency Actions:**
```powershell
# Disable compromised account
Disable-ADAccount -Identity "compromised_user"

# Reset Kerberos TGT (if domain admin compromised)
# WARNING: This resets krbtgt and requires two resets 12+ hours apart
Reset-KrbtgtKeys -Server "DC-PRIMARY" -Force

# Block lateral movement by disabling remote services
Set-Service -Name "RemoteRegistry" -StartupType Disabled -Status Stopped
```

### Step 4: Evidence Collection and Preservation

Collect forensic artifacts before remediation:

```powershell
# Capture running processes and network connections
Get-Process | Export-Csv "C:\IR\processes_$(hostname).csv"
Get-NetTCPConnection | Export-Csv "C:\IR\netstat_$(hostname).csv"

# Capture memory dump (if host still running)
winpmem_mini_x64.exe C:\IR\memory_$(hostname).raw

# Collect ransomware artifacts
Copy-Item "C:\Users\*\Desktop\*README*" "C:\IR\ransom_notes\" -Recurse
Copy-Item "C:\Users\*\Desktop\*.encrypted" "C:\IR\encrypted_samples\" -Force

# Capture event logs
wevtutil epl Security "C:\IR\Security_$(hostname).evtx"
wevtutil epl System "C:\IR\System_$(hostname).evtx"
wevtutil epl "Microsoft-Windows-Sysmon/Operational" "C:\IR\Sysmon_$(hostname).evtx"
```

### Step 5: Eradication and Recovery

**Identify ransomware variant:**
- Upload encrypted sample and ransom note to ID Ransomware (https://id-ransomware.malwarehunterteam.com/)
- Check No More Ransom Project (https://www.nomoreransom.org/) for available decryptors
- Search for ransomware family IOCs in MalwareBazaar

**Enterprise-wide IOC scan in Splunk:**
```spl
index=sysmon (EventCode=1 OR EventCode=11 OR EventCode=3)
(TargetFilename="*ransomware_binary_name*" OR sha256="KNOWN_HASH"
 OR DestinationIp="C2_IP_ADDRESS" OR CommandLine="*malicious_command*")
| stats count by Computer, EventCode, Image, CommandLine
| sort - count
```

**Recovery from backups:**
1. Verify backup integrity (offline/immutable backups not affected)
2. Rebuild affected systems from known-good images
3. Restore data from last clean backup
4. Validate restored systems before reconnecting to network
5. Monitor restored systems for 72 hours for reinfection

### Step 6: Post-Incident Documentation

Structure the playbook conclusion with lessons learned:

```
POST-INCIDENT REVIEW TEMPLATE
1. Timeline of events (detection to full recovery)
2. Initial access vector identification
3. Dwell time analysis (time from initial compromise to encryption)
4. Detection gaps identified
5. Response effectiveness metrics (MTTD, MTTC, MTTR)
6. Playbook improvements recommended
7. New detection rules deployed
8. Backup and recovery procedure updates
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Double Extortion** | Ransomware tactic combining data encryption with data theft, threatening public release if ransom unpaid |
| **Dwell Time** | Duration between initial compromise and detection — ransomware operators average 5-9 days before encryption |
| **MTTC** | Mean Time to Contain — time from detection to successful isolation of affected systems |
| **Kill Chain** | Ransomware progression: Initial Access -> Execution -> Persistence -> Privilege Escalation -> Lateral Movement -> Collection -> Exfiltration -> Impact |
| **Immutable Backup** | Backup storage that cannot be modified or deleted for a defined retention period (WORM storage) |
| **RTO/RPO** | Recovery Time Objective / Recovery Point Objective — maximum acceptable downtime and data loss thresholds |

## Tools & Systems

- **CrowdStrike Falcon / SentinelOne**: EDR platforms with network isolation, process kill, and threat hunting capabilities
- **Splunk ES / Elastic Security**: SIEM platforms for detection rule deployment and enterprise-wide IOC scanning
- **ID Ransomware**: Online service identifying ransomware variants from encrypted file samples and ransom notes
- **No More Ransom Project**: Europol-backed initiative providing free decryption tools for known ransomware families
- **Veeam / Rubrik**: Enterprise backup solutions with immutable backup support and instant recovery capabilities

## Common Scenarios

- **LockBit Attack**: Detected via SMB lateral movement and mass file encryption — isolate, scan for Cobalt Strike beacons
- **BlackCat/ALPHV**: Detected via ransomware note creation — check for data exfiltration via Rclone or Mega upload
- **Conti/Royal**: Detected via shadow copy deletion — check for prior BazarLoader/Emotet initial access
- **RansomHub**: Detected via anomalous process execution — investigate for compromised VPN or RDP credentials
- **Play Ransomware**: Detected via service account abuse — audit AD for newly created accounts and group membership changes

## Output Format

```
RANSOMWARE PLAYBOOK EXECUTION — IR-2024-0500
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Phase 1 - Detection:
  Alert:      Mass file encryption detected on FILESERVER-03
  Variant:    LockBit 3.0 (confirmed via ID Ransomware)
  MTTD:       12 minutes from first encryption to SOC alert

Phase 2 - Containment:
  [DONE] FILESERVER-03 isolated via CrowdStrike at 14:35 UTC
  [DONE] SMB blocked enterprise-wide via firewall emergency rule
  [DONE] Compromised service account disabled in AD
  MTTC:       23 minutes

Phase 3 - Eradication:
  [DONE] 3 additional hosts with C2 beacon identified and isolated
  [DONE] Cobalt Strike C2 domain (c2[.]evil[.]com) sinkholed
  [DONE] Enterprise-wide IOC scan completed — no additional infections

Phase 4 - Recovery:
  [DONE] FILESERVER-03 rebuilt from gold image
  [DONE] Data restored from immutable Veeam backup (RPO: 4 hours)
  [DONE] Systems monitored 72 hours — no reinfection
  MTTR:       18 hours

Total Affected: 1 server, 3 workstations
Data Loss:      4 hours of file modifications (backup RPO)
Exfiltration:   No evidence of data exfiltration confirmed
```
