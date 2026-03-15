---
name: detecting-credential-dumping-with-edr
description: Detect OS credential dumping techniques including LSASS access, SAM extraction, and DCSync using EDR telemetry and Sysmon logs.
domain: cybersecurity
subdomain: threat-hunting
tags: [threat-hunting, mitre-attack, credential-dumping, edr, lsass, t1003, proactive-detection]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Detecting Credential Dumping with EDR

## When to Use

- When hunting for post-exploitation credential theft in compromised environments
- After detecting suspicious LSASS process access in EDR alerts
- When investigating potential Active Directory compromise
- During incident response to determine scope of credential exposure
- When proactively hunting for T1003 sub-techniques across endpoints

## Prerequisites

- EDR platform with process access monitoring (CrowdStrike, MDE, SentinelOne)
- Sysmon deployed with Event ID 10 (Process Access) configured for LSASS
- Windows Security Event Log 4688 with command-line auditing enabled
- Active Directory event forwarding for DCSync detection (Event ID 4662)
- Windows Security Event Log 4656/4663 for SAM registry access

## Workflow

1. **Identify Credential Dumping Vectors**: Map the T1003 sub-techniques relevant to your environment (LSASS Memory, SAM, NTDS, DCSync, /etc/passwd, Cached Credentials).
2. **Query LSASS Access Events**: Search for Sysmon Event ID 10 where TargetImage is lsass.exe with suspicious GrantedAccess masks (0x1010, 0x1038, 0x1FFFFF).
3. **Analyze Process Context**: Examine the source process accessing LSASS - legitimate security tools vs. unknown or suspicious binaries.
4. **Hunt for SAM/NTDS Access**: Query for reg.exe save operations against SAM/SECURITY/SYSTEM hives and ntdsutil/vssadmin shadow copy access.
5. **Detect DCSync Activity**: Monitor for DS-Replication-Get-Changes requests from non-domain-controller sources (Event ID 4662).
6. **Correlate with Network Activity**: Cross-reference credential dumping with subsequent lateral movement or authentication anomalies.
7. **Assess Impact and Report**: Determine which credentials were potentially exposed and recommend password resets and containment.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1003 | OS Credential Dumping - parent technique |
| T1003.001 | LSASS Memory - dumping credentials from LSASS process |
| T1003.002 | Security Account Manager (SAM) - extracting local password hashes |
| T1003.003 | NTDS - extracting AD database from Domain Controllers |
| T1003.004 | LSA Secrets - accessing stored service credentials |
| T1003.005 | Cached Domain Credentials (DCC2) |
| T1003.006 | DCSync - replicating AD credentials via DRSUAPI |
| LSASS | Local Security Authority Subsystem Service |
| GrantedAccess | Bitmask indicating the access rights requested for a process |
| Minidump | Memory dump technique used by tools like comsvcs.dll |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| CrowdStrike Falcon | LSASS access detection and process tree analysis |
| Microsoft Defender for Endpoint | Advanced hunting for credential access events |
| Sysmon | Process access monitoring (Event ID 10) |
| Velociraptor | Endpoint artifact collection for LSASS analysis |
| Elastic Security | Correlation of credential dumping indicators |
| Splunk | SPL queries for credential access event analysis |
| Volatility | Memory forensics for LSASS credential extraction |

## Common Scenarios

1. **Mimikatz LSASS Dump**: Attacker runs `sekurlsa::logonpasswords` causing direct LSASS memory read with GrantedAccess 0x1010.
2. **Comsvcs.dll MiniDump**: Process uses `rundll32.exe comsvcs.dll MiniDump [LSASS PID]` to create LSASS memory dump file.
3. **ProcDump LSASS**: Attacker uses Microsoft-signed procdump.exe with `-ma lsass.exe` to dump LSASS memory.
4. **SAM Registry Export**: Adversary runs `reg save HKLM\SAM sam.bak` to extract local password hashes.
5. **DCSync Replication**: Compromised account with Replicating Directory Changes permissions performs DCSync from a workstation.
6. **NTDS Shadow Copy**: Attacker uses `vssadmin create shadow /for=C:` then copies ntds.dit from the shadow copy.

## Output Format

```
Hunt ID: TH-CRED-DUMP-[DATE]-[SEQ]
Technique: T1003.[Sub-technique]
Source Process: [Process accessing LSASS/SAM/NTDS]
Target: [lsass.exe / SAM / NTDS.dit / DC Replication]
Host: [Hostname]
User: [Account context]
GrantedAccess: [Access mask if applicable]
Timestamp: [UTC]
Risk Level: [Critical/High/Medium/Low]
Evidence: [Log entries, process tree, network activity]
Recommended Action: [Password reset scope, containment steps]
```
