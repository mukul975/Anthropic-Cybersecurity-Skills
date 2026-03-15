---
name: conducting-internal-reconnaissance-with-bloodhound-ce
description: Conduct internal Active Directory reconnaissance using BloodHound Community Edition to map attack paths, identify privilege escalation chains, and discover misconfigurations in domain environments.
domain: cybersecurity
subdomain: red-teaming
tags: [red-team, reconnaissance, bloodhound, active-directory, attack-paths, privilege-escalation, graph-analysis]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Conducting Internal Reconnaissance with BloodHound CE

## Overview

BloodHound Community Edition (CE) is a modern, web-based Active Directory reconnaissance platform developed by SpecterOps that uses graph theory to reveal hidden relationships and attack paths within AD environments. Unlike the legacy BloodHound application, BloodHound CE uses a PostgreSQL backend with a dedicated graph database, providing improved performance, a modern web UI, and enhanced API capabilities. Red teams use BloodHound CE to collect AD objects, ACLs, sessions, group memberships, and trust relationships, then visualize attack paths from compromised low-privileged accounts to high-value targets like Domain Admins. The SharpHound collector (v2 for CE) gathers data from Active Directory, while AzureHound collects from Azure AD / Entra ID environments.

## Objectives

- Deploy BloodHound CE server using Docker Compose
- Collect AD data using SharpHound v2 or BloodHound.py
- Import collected data into BloodHound CE for graph analysis
- Identify shortest attack paths from owned principals to Domain Admins
- Discover ACL-based attack paths, Kerberoastable accounts, and delegation abuse
- Execute custom Cypher queries for advanced attack path analysis
- Generate attack path reports for engagement documentation

## MITRE ATT&CK Mapping

- **T1087.002** - Account Discovery: Domain Account
- **T1069.002** - Permission Groups Discovery: Domain Groups
- **T1482** - Domain Trust Discovery
- **T1615** - Group Policy Discovery
- **T1018** - Remote System Discovery
- **T1033** - System Owner/User Discovery
- **T1016** - System Network Configuration Discovery

## Implementation Steps

### Phase 1: BloodHound CE Deployment
1. Deploy BloodHound CE using Docker Compose:
   ```bash
   curl -L https://ghst.ly/getbhce -o docker-compose.yml
   docker compose pull
   docker compose up -d
   ```
2. Access the web interface at https://localhost:8080
3. Log in with the default admin credentials (displayed in Docker logs):
   ```bash
   docker compose logs | grep "Initial Password"
   ```
4. Change the default admin password immediately

### Phase 2: Data Collection with SharpHound v2
1. Transfer SharpHound v2 to the compromised Windows host:
   ```powershell
   # Execute full collection
   .\SharpHound.exe -c All --outputdirectory C:\Temp

   # DCOnly collection (LDAP only, stealthier)
   .\SharpHound.exe -c DCOnly

   # Session collection for logged-on user mapping
   .\SharpHound.exe -c Session --loop --loopduration 02:00:00

   # Collect from specific domain
   .\SharpHound.exe -c All -d child.domain.local
   ```
2. Alternative: Use BloodHound.py from Linux:
   ```bash
   bloodhound-python -u user -p 'Password123' -d domain.local -ns 10.10.10.1 -c All
   ```
3. Exfiltrate the generated ZIP file to the analysis workstation

### Phase 3: Data Import and Initial Analysis
1. Upload collected data via the BloodHound CE web interface (File Ingest)
2. Mark compromised accounts as "Owned" in the interface
3. Run built-in analysis queries:
   - Shortest Path to Domain Admin
   - Kerberoastable Users with Path to DA
   - AS-REP Roastable Users
   - Users with DCSync Rights
   - Computers with Unconstrained Delegation

### Phase 4: Custom Cypher Queries
1. Execute custom Cypher queries in the BloodHound CE search bar:
   ```cypher
   // Find shortest path from owned principals to Domain Admins
   MATCH p=shortestPath((n {owned:true})-[*1..]->(m:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}))
   RETURN p

   // Find Kerberoastable users with path to DA
   MATCH (u:User {hasspn:true})
   MATCH p=shortestPath((u)-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}))
   RETURN p

   // Find computers with sessions of DA members
   MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"})
   RETURN c.name, u.name

   // Find ACL-based attack paths (GenericAll, WriteDACL, GenericWrite)
   MATCH p=(u:User)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword*1..]->(t)
   WHERE u.owned = true
   RETURN p

   // Find users who can DCSync
   MATCH (u)-[:MemberOf*0..]->()-[:DCSync|GetChanges|GetChangesAll*1..]->(d:Domain)
   RETURN u.name, d.name

   // Find computers with LAPS but readable by non-admins
   MATCH (c:Computer {haslaps:true})
   MATCH p=(u:User)-[:ReadLAPSPassword]->(c)
   RETURN p
   ```

### Phase 5: Attack Path Prioritization
1. Score identified attack paths by:
   - Number of hops (shorter = higher priority)
   - Stealth requirements (avoid noisy techniques)
   - Tool availability for each hop
   - Likelihood of detection at each step
2. Create an execution plan for the highest-priority paths
3. Identify required tools for each step in the chain
4. Plan OPSEC considerations for each technique

## Tools and Resources

| Tool | Purpose | Platform |
|------|---------|----------|
| BloodHound CE | Web-based graph analysis platform | Docker |
| SharpHound v2 | AD data collection (.NET, for CE) | Windows |
| BloodHound.py | AD data collection (Python) | Linux |
| AzureHound | Azure AD / Entra ID data collection | Cross-platform |
| PlumHound | Automated BloodHound reporting | Python |
| BloodHound Query Library | Community Cypher query repository | Web |

## Key Attack Path Types

| Path Type | Description | Example |
|-----------|-------------|---------|
| ACL Abuse | Exploit misconfigured ACLs | GenericAll on DA group |
| Kerberoasting | Crack service account passwords | SPN account → DA |
| AS-REP Roasting | Attack accounts without pre-auth | No-preauth user → password crack |
| Delegation Abuse | Exploit unconstrained/constrained delegation | Computer → impersonate DA |
| GPO Abuse | Modify GPOs applied to privileged OUs | GPO write → code execution on DA |
| Session Hijack | Leverage DA sessions on compromised hosts | Admin session → token theft |

## Validation Criteria

- [ ] BloodHound CE deployed and accessible
- [ ] SharpHound v2 data collected from all domains in scope
- [ ] Data successfully imported into BloodHound CE
- [ ] Owned principals marked in the interface
- [ ] Shortest paths to Domain Admin identified
- [ ] ACL-based attack paths documented
- [ ] Kerberoastable and AS-REP roastable accounts listed
- [ ] Custom Cypher queries executed for advanced analysis
- [ ] Attack paths prioritized by feasibility and stealth
- [ ] Report generated with all identified paths and evidence
