---
name: mapping-attack-paths-with-bloodhound-ce
description: Collect Active Directory data with SharpHound and Entra ID data with AzureHound, ingest into BloodHound Community Edition, and analyze on-prem, cloud, and hybrid attack paths using built-in queries and custom Cypher. Use when mapping privilege-escalation chains toward domain/tenant compromise during authorized red-team or penetration-test engagements. Do not use for internal-network reconnaissance and collection with BloodHound CE - use conducting-internal-reconnaissance-with-bloodhound-ce.
domain: cybersecurity
subdomain: red-teaming
tags:
- bloodhound-ce
- sharphound
- azurehound
- active-directory
- entra-id
- attack-paths
- cypher
- hybrid-identity
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- ID.AM-03
mitre_attack:
- T1069
---
# Mapping Attack Paths with BloodHound CE

> **Legal Notice:** This skill is for authorized security testing, red-team engagements, and educational purposes only. Active Directory and Entra ID reconnaissance reveals privilege-escalation chains that lead to full domain/tenant compromise. Use only against environments you own or have explicit written authorization (rules of engagement) to test. Unauthorized use violates the Computer Fraud and Abuse Act and equivalent laws.

## Overview

BloodHound Community Edition (CE) is SpecterOps's graph-based attack-path-management platform. It models security principals (users, computers, groups, OUs, GPOs, Entra ID users/groups/apps/roles) as nodes and the permissions, group memberships, sessions, trusts, and ACLs between them as edges. By framing Active Directory and Entra ID as a directed graph, BloodHound turns the question "can this low-privileged account reach Domain Admins / Global Administrator?" into a shortest-path query that finds escalation chains a human reviewer would miss.

BloodHound CE replaced the legacy Neo4j-only BloodHound with a containerized stack: a Go API server, a PostgreSQL relational store, and a Neo4j graph database, all behind a modern web UI and REST API. Data is gathered by two collectors maintained by SpecterOps:

- **SharpHound** (the CE/.NET collector, run on or against a domain-joined Windows host) gathers on-prem AD: objects, group membership, ACLs, sessions, local-admin rights, trusts, GPOs, certificate services (ADCS), and LAPS readability. It emits a ZIP of JSON.
- **AzureHound** (a cross-platform Go binary) gathers Entra ID and Azure Resource Manager data via the Microsoft Graph and Azure REST APIs: users, groups, app registrations, service principals, directory roles, subscription/role assignments, and key vaults. It emits a single JSON file.

As of recent CE releases, when both an AD domain and its synced Entra ID tenant are ingested, BloodHound automatically renders **Hybrid Attack Paths** — chains that cross the on-prem/cloud boundary (for example, an on-prem user synced to a cloud account that holds a privileged Entra role). Mapped to MITRE ATT&CK, the core activity is **T1069 – Permission Groups Discovery**, supported by T1087 (Account Discovery), T1482 (Domain Trust Discovery), and T1018 (Remote System Discovery).

## When to Use

- During an authorized internal penetration test or red-team engagement after obtaining any domain foothold or Entra credentials
- When you need to prioritize escalation routes from owned principals to Tier-0 assets (Domain Admins, Global Administrator)
- When assessing hybrid identity risk where on-prem AD is synced to Entra ID
- During purple-team exercises to validate that detections fire on collection and on path-execution steps
- When producing attack-path evidence and remediation guidance for a defensive client

## Prerequisites

- Authorized scope covering AD/Entra reconnaissance
- A foothold: any valid domain user (for SharpHound) and/or valid Entra credentials or a token (for AzureHound)
- Docker + Docker Compose on the analysis workstation
- The collectors:
  ```bash
  # Deploy BloodHound CE (pulls Postgres, Neo4j, and the BloodHound API)
  curl -L https://ghst.ly/getbhce -o docker-compose.yml
  docker compose pull
  docker compose up -d
  # Reveal the randomly generated initial admin password
  docker compose logs bloodhound | grep -i "Initial Password"

  # AzureHound (download the release binary for your OS from the GitHub releases page)
  #   https://github.com/SpecterOps/AzureHound/releases
  chmod +x ./azurehound

  # SharpHound CE collector: download SharpHound.zip from the BloodHound CE
  # web UI (Administration -> Download Collectors), transfer to a domain-joined host.
  ```

## Objectives

- Deploy BloodHound CE and authenticate to the web UI and API
- Collect AD data with SharpHound and Entra data with AzureHound
- Ingest both datasets and mark compromised principals as Owned
- Run built-in analysis (Shortest Path to Domain Admins, Kerberoastable accounts, ADCS abuse)
- Author custom Cypher queries for bespoke and hybrid attack paths
- Prioritize and document escalation routes for the engagement report

## MITRE ATT&CK Mapping

| ID | Technique | Application in this skill |
|----|-----------|---------------------------|
| T1069 | Permission Groups Discovery | Enumerating AD/Entra group memberships and the permissions between principals to build the attack graph |
| T1087 | Account Discovery | SharpHound/AzureHound enumeration of users, computers, and service principals |
| T1482 | Domain Trust Discovery | Collecting and analyzing domain/forest trust relationships as graph edges |
| T1018 | Remote System Discovery | Enumerating domain computers and their relationships (sessions, local admin) |

## Workflow

### Step 1: Deploy BloodHound CE and log in
Bring up the stack, retrieve the generated password, and reset it on first login.

```bash
docker compose up -d
docker compose logs bloodhound 2>&1 | grep -i "Initial Password"
# Browse to http://localhost:8080  (default user: admin)
```

### Step 2: Collect on-prem AD data with SharpHound
On a domain-joined Windows host (or via `runas`/token of a domain user), run the CE collector. `-c All` gathers every collection method; `--outputdirectory` controls where the ZIP lands.

```powershell
# Full collection
.\SharpHound.exe -c All --outputdirectory C:\Temp

# Stealthier LDAP-only collection (no host touch for sessions/local-admin)
.\SharpHound.exe -c DCOnly --outputdirectory C:\Temp

# Looped session collection to map logged-on Tier-0 users over time
.\SharpHound.exe -c Session --loop --loopduration 02:00:00 --outputdirectory C:\Temp
```

From Linux, the Python collector (`bloodhound-ce-python`) is an alternative when you only have credentials and network access:

```bash
pip install bloodhound-ce
bloodhound-ce-python -u 'jdoe' -p 'Passw0rd!' -d corp.local -ns 10.0.0.10 -c All --zip
```

### Step 3: Collect Entra ID / Azure data with AzureHound
Run AzureHound `list` with credentials, a JWT, or a refresh token, writing a single JSON file.

```bash
# Username/password (where allowed by CA/MFA policy)
./azurehound list -u "user@corp.com" -p "$PASSWORD" -t "corp.com" -o entra.json

# Using a previously acquired JWT (e.g., from roadtx / device-code phishing)
./azurehound list --jwt "$JWT" -o entra.json

# Using a refresh token
./azurehound list --refresh-token "$REFRESH_TOKEN" -t "<tenant-id>" -o entra.json
```

### Step 4: Ingest data into BloodHound CE
Upload the SharpHound ZIP and the AzureHound JSON through **Administration -> File Ingest**, or POST to the API.

```bash
# API ingest (after obtaining a JWT from /api/v2/login)
TOKEN=$(curl -s http://localhost:8080/api/v2/login \
  -H 'Content-Type: application/json' \
  -d '{"login_method":"secret","username":"admin","secret":"<password>"}' \
  | python -c "import sys,json;print(json.load(sys.stdin)['data']['session_token'])")

# Start a file-upload job, then PUT the collector ZIP/JSON to it
JOB=$(curl -s -X POST http://localhost:8080/api/v2/file-upload/start \
  -H "Authorization: Bearer $TOKEN" | python -c "import sys,json;print(json.load(sys.stdin)['data']['id'])")
curl -s -X PUT "http://localhost:8080/api/v2/file-upload/$JOB" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/zip' \
  --data-binary @C:/Temp/BloodHound.zip
curl -s -X POST "http://localhost:8080/api/v2/file-upload/$JOB/end" \
  -H "Authorization: Bearer $TOKEN"
```

### Step 5: Mark owned principals
In the UI, search for each compromised account/computer, open the node, and toggle **Mark as Owned**. Owned principals seed pathfinding queries (`{owned:true}`).

### Step 6: Run built-in analysis queries
Open the **Cypher** tab or use the pre-built queries in the search panel:

- Shortest Path to Domain Admins
- Kerberoastable accounts with a path to high value
- AS-REP roastable users
- Principals with DCSync rights
- ADCS misconfigurations (ESC1-ESC8 edges in CE)
- Computers with unconstrained delegation

### Step 7: Author custom Cypher for bespoke paths
Use Cypher for paths the built-ins do not cover, including hybrid AD-to-Entra chains.

```cypher
// Shortest path from any owned principal to Domain Admins
MATCH p=shortestPath((n {owned:true})-[*1..]->(g:Group))
WHERE g.objectid ENDS WITH "-512"
RETURN p

// Kerberoastable users (SPN set) with a path to Domain Admins
MATCH (u:User {hasspn:true})
MATCH p=shortestPath((u)-[*1..]->(g:Group))
WHERE g.objectid ENDS WITH "-512"
RETURN p

// Principals who can DCSync the domain
MATCH (n)-[:MemberOf*0..]->()-[:DCSync|GetChanges|GetChangesAll*1..]->(d:Domain)
RETURN n.name, d.name

// ACL abuse from owned principals (GenericAll/WriteDacl/WriteOwner/ForceChangePassword)
MATCH p=(n {owned:true})-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword*1..]->(t)
RETURN p

// Hybrid: on-prem user synced to an Entra account holding a privileged directory role
MATCH p=(u:User)-[:SyncedToEntraUser]->(:AZUser)-[:AZHasRole|AZGlobalAdmin*1..]->(r)
RETURN p
```

### Step 8: Prioritize and document
Rank paths by hop count, stealth (avoid noisy edges like HasSession requiring host touch), and tooling availability. Record each path with the principals, edges, required actions, and a remediation note (e.g., remove the abusable ACL, tier the account).

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| BloodHound CE | Graph attack-path platform (Docker stack) | https://github.com/SpecterOps/BloodHound |
| SharpHound (CE) | On-prem AD collector | https://github.com/SpecterOps/SharpHound |
| AzureHound | Entra ID / Azure RM collector | https://github.com/SpecterOps/AzureHound |
| bloodhound-ce-python | Linux Python AD collector | https://github.com/dirkjanm/BloodHound.py |
| CE Quickstart | Official deployment docs | https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart |
| BloodHound Cypher refs | Edge/query documentation | https://bloodhound.specterops.io/ |

## Key Edge / Path Types

| Edge / Path | Meaning | Escalation example |
|-------------|---------|--------------------|
| MemberOf | Group membership | Nested group reaches Domain Admins |
| GenericAll / WriteDacl | Full/ACL control over an object | Reset a privileged user's password |
| ForceChangePassword | Can reset another principal's password | Take over a Tier-0 account |
| HasSession | A user is logged into a computer | Steal a DA token from a compromised host |
| ADCSESC1..ESC8 | Certificate services misconfig | Enroll a cert as a privileged principal |
| SyncedToEntraUser / AZGlobalAdmin | Hybrid identity edges | On-prem foothold -> cloud Global Admin |

## Validation Criteria

- [ ] BloodHound CE deployed and reachable; default admin password rotated
- [ ] SharpHound data collected from all in-scope domains
- [ ] AzureHound JSON collected for the in-scope tenant (if hybrid/cloud in scope)
- [ ] Both datasets ingested successfully (no failed upload jobs)
- [ ] Compromised principals marked as Owned
- [ ] Shortest paths to Domain Admins / Global Administrator identified
- [ ] ADCS and ACL-abuse paths enumerated
- [ ] At least one custom Cypher query (including a hybrid query where applicable) executed
- [ ] Paths prioritized by hops/stealth and documented with remediation
