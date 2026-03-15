---
name: analyzing-windows-event-logs-in-splunk
description: >
  Analyzes Windows Security, System, and Sysmon event logs in Splunk to detect authentication attacks,
  privilege escalation, persistence mechanisms, and lateral movement using SPL queries mapped to
  MITRE ATT&CK techniques. Use when SOC analysts need to investigate Windows-based threats,
  build detection queries, or perform forensic timeline analysis of Windows endpoints and domain controllers.
domain: cybersecurity
subdomain: soc-operations
tags: [soc, splunk, windows-events, sysmon, event-logs, mitre-attack, active-directory]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Analyzing Windows Event Logs in Splunk

## When to Use

Use this skill when:
- SOC analysts investigate alerts related to Windows authentication, process execution, or AD changes
- Detection engineers build SPL queries for Windows-based threat detection
- Incident responders need forensic timelines of Windows endpoint or domain controller activity
- Periodic threat hunting targets Windows-specific ATT&CK techniques

**Do not use** for Linux/macOS endpoint analysis or network-only investigations.

## Prerequisites

- Splunk with Windows Event Log data ingested (sourcetype `WinEventLog:Security`, `WinEventLog:System`, `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`)
- Sysmon deployed on endpoints with SwiftOnSecurity or Olaf Hartong configuration
- CIM data model acceleration for Endpoint and Authentication data models
- Knowledge of Windows Security Event IDs and Sysmon event types

## Workflow

### Step 1: Authentication Attack Detection

**Brute Force Detection (EventCode 4625 — Failed Logon):**
```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625
| stats count, dc(TargetUserName) AS unique_users, values(TargetUserName) AS targeted_users
  by src_ip, Logon_Type, Status
| where count > 20
| eval attack_type = case(
    Logon_Type=3, "Network Brute Force",
    Logon_Type=10, "RDP Brute Force",
    Logon_Type=2, "Interactive Brute Force",
    1=1, "Other"
  )
| eval status_meaning = case(
    Status="0xc000006d", "Bad Username or Password",
    Status="0xc000006a", "Incorrect Password (valid user)",
    Status="0xc0000234", "Account Locked Out",
    Status="0xc0000072", "Account Disabled",
    1=1, Status
  )
| sort - count
| table src_ip, attack_type, status_meaning, count, unique_users, targeted_users
```

**Password Spray Detection:**
```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625 Logon_Type=3
| bin _time span=10m
| stats dc(TargetUserName) AS unique_users, count AS total_attempts,
  values(TargetUserName) AS users_targeted by src_ip, _time
| where unique_users > 10 AND total_attempts < unique_users * 3
| eval spray_confidence = if(unique_users > 25, "HIGH", "MEDIUM")
```

**Successful Logon After Failures (Compromise Indicator):**
```spl
index=wineventlog sourcetype="WinEventLog:Security"
(EventCode=4625 OR EventCode=4624) src_ip!="127.0.0.1"
| sort _time
| stats earliest(_time) AS first_seen, latest(_time) AS last_seen,
  sum(eval(if(EventCode=4625,1,0))) AS failures,
  sum(eval(if(EventCode=4624,1,0))) AS successes
  by src_ip, TargetUserName, ComputerName
| where failures > 10 AND successes > 0
| eval time_to_success = round((last_seen - first_seen)/60, 1)
| sort - failures
```

### Step 2: Privilege Escalation Detection

**New Admin Account Created (T1136.001):**
```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4720
| join TargetUserName type=left [
    search index=wineventlog EventCode=4732 TargetUserName="Administrators"
    | rename MemberName AS TargetUserName
  ]
| table _time, SubjectUserName, TargetUserName, ComputerName
| eval alert = "New account created and added to Administrators group"
```

**Special Privileges Assigned (EventCode 4672):**
```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4672
SubjectUserName!="SYSTEM" SubjectUserName!="LOCAL SERVICE" SubjectUserName!="NETWORK SERVICE"
| stats count, values(PrivilegeList) AS privileges by SubjectUserName, ComputerName
| where count > 0
| search privileges IN ("SeDebugPrivilege", "SeTcbPrivilege", "SeBackupPrivilege",
  "SeRestorePrivilege", "SeAssignPrimaryTokenPrivilege")
```

**Token Manipulation Detection (T1134):**
```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
GrantedAccess IN ("0x1010", "0x1038", "0x1fffff", "0x40")
| stats count by SourceImage, SourceUser, Computer, GrantedAccess
| where NOT match(SourceImage, "(svchost|csrss|wininit|MsMpEng|CrowdStrike)")
| sort - count
```

### Step 3: Persistence Mechanism Detection

**Scheduled Task Creation (T1053.005):**
```spl
index=wineventlog (sourcetype="WinEventLog:Security" EventCode=4698)
  OR (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
      Image="*\\schtasks.exe")
| eval task_info = coalesce(TaskContent, CommandLine)
| search task_info="*powershell*" OR task_info="*cmd*" OR task_info="*http*" OR task_info="*\\Temp\\*"
| table _time, Computer, SubjectUserName, TaskName, task_info
```

**Registry Run Key Modification (T1547.001):**
```spl
index=sysmon EventCode=13
TargetObject IN (
  "*\\CurrentVersion\\Run\\*",
  "*\\CurrentVersion\\RunOnce\\*",
  "*\\CurrentVersion\\RunServices\\*",
  "*\\Explorer\\Shell Folders\\*"
)
| stats count by Computer, Image, TargetObject, Details
| where NOT match(Image, "(explorer\.exe|msiexec\.exe|setup\.exe)")
| sort - count
```

**WMI Event Subscription (T1546.003):**
```spl
index=sysmon EventCode=20 OR EventCode=21
| stats count by Computer, Operation, Consumer, EventNamespace
| where count > 0
```

### Step 4: Lateral Movement Detection

**Remote Service Exploitation (T1021.002 — SMB/Windows Admin Shares):**
```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=3
| stats dc(ComputerName) AS unique_destinations, values(ComputerName) AS targets
  by src_ip, TargetUserName
| where unique_destinations > 3
| sort - unique_destinations
| table src_ip, TargetUserName, unique_destinations, targets
```

**PsExec Detection (T1021.002):**
```spl
index=sysmon EventCode=1
(Image="*\\psexec.exe" OR Image="*\\psexesvc.exe"
 OR ParentImage="*\\psexesvc.exe"
 OR OriginalFileName="psexec.c")
| table _time, Computer, User, ParentImage, Image, CommandLine
```

**RDP Lateral Movement (T1021.001):**
```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=10
| stats count, dc(ComputerName) AS rdp_targets, values(ComputerName) AS destinations
  by src_ip, TargetUserName
| where rdp_targets > 2
| sort - rdp_targets
```

### Step 5: Build Forensic Timeline

Create comprehensive timeline for a compromised host:

```spl
(index=wineventlog OR index=sysmon) Computer="WORKSTATION-042"
earliest="2024-03-14T00:00:00" latest="2024-03-16T00:00:00"
| eval event_description = case(
    EventCode=4624, "Logon: ".TargetUserName." (Type ".Logon_Type.")",
    EventCode=4625, "Failed Logon: ".TargetUserName,
    EventCode=4688 OR (sourcetype="XmlWinEventLog:*Sysmon*" AND EventCode=1),
      "Process: ".Image." CMD: ".CommandLine,
    EventCode=4698, "Scheduled Task: ".TaskName,
    EventCode=3, "Network: ".DestinationIp.":".DestinationPort,
    EventCode=11, "File Created: ".TargetFilename,
    EventCode=13, "Registry: ".TargetObject,
    1=1, "Event ".EventCode
  )
| sort _time
| table _time, EventCode, event_description, User, src_ip
```

### Step 6: Create Lookup Tables for Enrichment

Build reference lookups for Windows Event ID context:

```spl
| inputlookup windows_eventcode_lookup.csv
| table EventCode, Description, ATT_CK_Technique, Severity
```

If lookup doesn't exist, create it:

```csv
EventCode,Description,ATT_CK_Technique,Severity
4624,Successful Logon,T1078,Informational
4625,Failed Logon,T1110,Low
4648,Explicit Credential Logon,T1078,Medium
4672,Special Privileges Assigned,T1134,Medium
4688,New Process Created,T1059,Informational
4698,Scheduled Task Created,T1053.005,Medium
4720,User Account Created,T1136.001,High
4732,Member Added to Security Group,T1098,High
4768,Kerberos TGT Requested,T1558,Informational
4769,Kerberos Service Ticket,T1558.003,Low
4771,Kerberos Pre-Auth Failed,T1110,Low
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **EventCode 4624** | Successful logon event — Logon_Type 2 (interactive), 3 (network), 10 (RDP), 7 (unlock) |
| **EventCode 4625** | Failed logon event — Status code indicates failure reason (bad password, account locked, disabled) |
| **Sysmon EventCode 1** | Process creation with full command line, parent process, and hash information |
| **Sysmon EventCode 3** | Network connection initiated by a process — source/dest IP, port, and process context |
| **Logon Type 3** | Network logon (SMB, WMI, PowerShell Remoting) — key indicator of lateral movement |
| **Logon Type 10** | Remote interactive logon via RDP/Terminal Services |

## Tools & Systems

- **Splunk Enterprise**: SIEM platform with SPL query engine for Windows event log analysis and correlation
- **Sysmon (System Monitor)**: Microsoft Sysinternals tool providing detailed process, network, and file activity logging
- **Splunk CIM**: Common Information Model mapping Windows events to normalized fields for cross-source queries
- **Windows Event Forwarding (WEF)**: Built-in Windows mechanism for centralizing event logs to a collector server

## Common Scenarios

- **Kerberoasting (T1558.003)**: Detect EventCode 4769 with encryption type 0x17 (RC4) for non-standard service accounts
- **DCSync (T1003.006)**: Detect EventCode 4662 with DS-Replication-Get-Changes from non-DC sources
- **Golden Ticket (T1558.001)**: Detect EventCode 4769 with abnormal ticket properties (long lifetime, non-standard encryption)
- **Pass-the-Hash (T1550.002)**: Detect EventCode 4624 Logon_Type 3 with NTLM authentication from unexpected sources
- **DLL Side-Loading (T1574.002)**: Sysmon EventCode 7 showing unsigned DLLs loaded by legitimate processes

## Output Format

```
WINDOWS EVENT LOG ANALYSIS — HOST: WORKSTATION-042
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Period:     2024-03-14 to 2024-03-15
Events:     12,847 total (Security: 9,231 | Sysmon: 3,616)

Authentication Summary:
  Successful Logons (4624):    487 (Type 3: 312, Type 10: 45, Type 2: 130)
  Failed Logons (4625):        847 (from 192.168.1.105 — BRUTE FORCE)
  Explicit Creds (4648):       12

Suspicious Findings:
  [HIGH]   847 failed logons followed by success at 14:35 from 192.168.1.105
  [HIGH]   New user "backdoor_admin" created (4720) at 14:38
  [HIGH]   User added to Administrators group (4732) at 14:38
  [MEDIUM] schtasks.exe creating persistence task at 14:42
  [MEDIUM] PowerShell encoded command execution at 14:45

ATT&CK Mapping:
  T1110.001 — Password Guessing (847 failed logons)
  T1136.001 — Local Account Creation (backdoor_admin)
  T1053.005 — Scheduled Task (persistence)
  T1059.001 — PowerShell (encoded execution)
```
