---
name: detecting-dcsync-attack-in-active-directory
description: Detect DCSync attacks where adversaries abuse Active Directory replication privileges to extract password hashes by monitoring for non-domain-controller accounts requesting directory replication via DsGetNCChanges.
domain: cybersecurity
subdomain: threat-hunting
tags: [threat-hunting, active-directory, dcsync, credential-theft, mitre-t1003-006, mimikatz, kerberos]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Detecting DCSync Attack in Active Directory

## When to Use

- When hunting for credential theft in Active Directory environments
- After compromise of accounts with Replicating Directory Changes permissions
- When investigating suspected use of Mimikatz or Impacket secretsdump
- During incident response involving lateral movement with domain admin credentials
- When auditing AD replication permissions as part of security hardening

## Prerequisites

- Windows Security Event Logs with Event ID 4662 (Object Access) enabled
- Advanced Audit Policy: Audit Directory Service Access enabled
- Domain Controller event forwarding to SIEM
- Knowledge of legitimate domain controller hostnames and IPs
- Directory Service Access auditing with SACL on domain object

## Workflow

1. **Identify Legitimate Replication Sources**: Document all domain controllers in the environment by hostname, IP, and computer account. Only these should perform directory replication.
2. **Enable Required Auditing**: Configure Advanced Audit Policy to capture Event ID 4662 on domain controllers with specific GUID monitoring for replication rights.
3. **Monitor Replication Rights Access**: Track access to three critical GUIDs -- DS-Replication-Get-Changes (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2), DS-Replication-Get-Changes-All (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2), and DS-Replication-Get-Changes-In-Filtered-Set (89e95b76-444d-4c62-991a-0facbeda640c).
4. **Detect Non-DC Replication Requests**: Alert when any account NOT associated with a domain controller requests replication rights.
5. **Correlate with Network Traffic**: DCSync generates replication traffic (MS-DRSR/RPC) from the attacker's machine to the DC. Monitor for DrsGetNCChanges RPC calls from non-DC IP addresses.
6. **Investigate Source Context**: Examine the process, user account, and machine originating the replication request.
7. **Check for Credential Abuse**: After DCSync detection, audit for subsequent use of extracted hashes (pass-the-hash, golden ticket creation).

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1003.006 | OS Credential Dumping: DCSync |
| DCSync | Mimicking domain controller replication to extract credentials |
| DsGetNCChanges | RPC function used to request AD replication data |
| DS-Replication-Get-Changes | AD permission required (GUID: 1131f6aa-...) |
| DS-Replication-Get-Changes-All | Permission including confidential attributes (GUID: 1131f6ad-...) |
| MS-DRSR | Microsoft Directory Replication Service Remote Protocol |
| KRBTGT Hash | Key target of DCSync enabling Golden Ticket attacks |
| Event ID 4662 | Directory service object access audit event |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Mimikatz (lsadump::dcsync) | Primary DCSync attack tool |
| Impacket secretsdump.py | Python-based DCSync implementation |
| DSInternals | PowerShell module for AD replication |
| BloodHound | Map accounts with replication rights |
| Splunk / Elastic | SIEM correlation of 4662 events |
| Microsoft Defender for Identity | Native DCSync detection |
| CrowdStrike Falcon | EDR-based DCSync detection |

## Detection Queries

### Splunk -- DCSync Detection via Event 4662
```spl
index=wineventlog EventCode=4662
| where Properties IN ("*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*",
    "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*",
    "*89e95b76-444d-4c62-991a-0facbeda640c*")
| where NOT match(SubjectUserName, ".*\\$$")
| where NOT SubjectUserName IN ("known_svc_account1", "known_svc_account2")
| stats count values(Properties) as ReplicationRights by SubjectUserName SubjectDomainName Computer
| where count > 0
| table SubjectUserName SubjectDomainName Computer count ReplicationRights
```

### KQL -- Microsoft Sentinel DCSync Detection
```kql
SecurityEvent
| where EventID == 4662
| where Properties has "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    or Properties has "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
| where SubjectUserName !endswith "$"
| where SubjectUserName !in ("AzureADConnect", "MSOL_*")
| project TimeGenerated, SubjectUserName, SubjectDomainName, Computer, Properties
| sort by TimeGenerated desc
```

### Sigma Rule -- DCSync Activity
```yaml
title: DCSync Activity Detected - Non-DC Replication Request
status: stable
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        Properties|contains:
            - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
            - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    filter_dc:
        SubjectUserName|endswith: '$'
    condition: selection and not filter_dc
level: critical
tags:
    - attack.credential_access
    - attack.t1003.006
```

## Common Scenarios

1. **Mimikatz DCSync**: Attacker with Domain Admin privileges runs `lsadump::dcsync /user:krbtgt` to extract KRBTGT hash for Golden Ticket creation.
2. **Impacket secretsdump**: Remote DCSync via `secretsdump.py domain/user:password@dc-ip` extracting all domain hashes.
3. **Delegated Replication Rights**: Attacker grants themselves Replicating Directory Changes rights via ACL modification before performing DCSync.
4. **Azure AD Connect Abuse**: Compromising the Azure AD Connect service account which has legitimate replication rights.
5. **DSInternals PowerShell**: Using `Get-ADReplAccount` cmdlet to replicate specific account credentials.

## Output Format

```
Hunt ID: TH-DCSYNC-[DATE]-[SEQ]
Alert Severity: Critical
Source Account: [Account requesting replication]
Source Machine: [Hostname/IP of requestor]
Target DC: [Domain controller receiving request]
Replication Rights: [GUIDs accessed]
Timestamp: [Event time]
Legitimate DC: [Yes/No]
Known Service Account: [Yes/No]
Risk Assessment: [Critical - non-DC replication detected]
```
