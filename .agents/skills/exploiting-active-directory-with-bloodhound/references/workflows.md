# BloodHound Active Directory Exploitation Workflows

## Workflow 1: Data Collection

### SharpHound Collection (Windows)
```powershell
# Basic collection - all methods
.\SharpHound.exe -c All

# DCOnly collection (less noise, requires domain user)
.\SharpHound.exe -c DCOnly

# Session collection with loop (continuous session data gathering)
.\SharpHound.exe -c Session --Loop --LoopDuration 02:00:00 --LoopInterval 00:05:00

# Collection from specific domain
.\SharpHound.exe -c All -d targetdomain.local

# Stealth collection (avoid noisy queries)
.\SharpHound.exe -c DCOnly,Session --Stealth

# Collection via LDAP with specific credentials
.\SharpHound.exe -c All -d targetdomain.local --LdapUsername user --LdapPassword pass

# Output to specific directory
.\SharpHound.exe -c All --OutputDirectory C:\Users\Public\

# Exclude domain controllers from session collection
.\SharpHound.exe -c All --ExcludeDomainControllers
```

### BloodHound.py Collection (Linux/Kali)
```bash
# Basic collection with username/password
bloodhound-python -d targetdomain.local -u user -p 'Password123' -c All -ns 10.0.0.1

# Collection with NTLM hash
bloodhound-python -d targetdomain.local -u user --hashes aad3b435b51404eeaad3b435b51404ee:hash -c All -ns 10.0.0.1

# DNS resolution via domain controller
bloodhound-python -d targetdomain.local -u user -p 'Password123' -c All -dc dc01.targetdomain.local -ns 10.0.0.1

# Collection with specific methods
bloodhound-python -d targetdomain.local -u user -p 'Password123' -c Group,LocalAdmin,Session -ns 10.0.0.1
```

## Workflow 2: BloodHound CE Setup and Data Import

### Setup BloodHound Community Edition
```bash
# Docker Compose setup
curl -L https://ghst.ly/getbhce -o docker-compose.yml
docker compose pull
docker compose up -d

# Access at https://localhost:8080
# Default credentials in docker compose output
# Upload SharpHound ZIP files via UI
```

### Legacy BloodHound Setup
```bash
# Install Neo4j
sudo apt install neo4j
sudo neo4j console

# Download and run BloodHound
wget https://github.com/BloodHoundAD/BloodHound/releases/latest
chmod +x BloodHound
./BloodHound --no-sandbox

# Import data via drag-and-drop of ZIP files
```

## Workflow 3: Attack Path Discovery

### Pre-Built Queries
```cypher
-- Shortest Path to Domain Admins from Owned
MATCH p=shortestPath((n {owned:true})-[*1..]->(m:Group {name:"DOMAIN ADMINS@TARGETDOMAIN.LOCAL"}))
RETURN p

-- Find All Kerberoastable Users
MATCH (u:User {hasspn:true}) RETURN u.name, u.serviceprincipalnames

-- Kerberoastable Users with Path to DA
MATCH (u:User {hasspn:true})
MATCH p=shortestPath((u)-[*1..]->(g:Group {name:"DOMAIN ADMINS@TARGETDOMAIN.LOCAL"}))
RETURN u.name, LENGTH(p)
ORDER BY LENGTH(p) ASC

-- AS-REP Roastable Users
MATCH (u:User {dontreqpreauth:true}) RETURN u.name, u.displayname

-- Users with DCSync Rights
MATCH p=(n)-[:MemberOf|GetChanges|GetChangesAll*1..]->(d:Domain)
WHERE n.name IS NOT NULL
RETURN p

-- Computers with Unconstrained Delegation
MATCH (c:Computer {unconstraineddelegation:true})
WHERE NOT c.name CONTAINS "DC"
RETURN c.name

-- Find Users with Local Admin on Multiple Computers
MATCH (u:User)-[:AdminTo]->(c:Computer)
WITH u, COUNT(c) as adminCount
WHERE adminCount > 1
RETURN u.name, adminCount
ORDER BY adminCount DESC

-- GPOs Modifying Local Group Memberships
MATCH (g:GPO)-[:GpLink]->(ou:OU)-[:Contains*1..]->(c:Computer)
RETURN g.name, ou.name, COLLECT(c.name)

-- Find Shortest Path from Domain Users to DA
MATCH p=shortestPath((g:Group {name:"DOMAIN USERS@TARGETDOMAIN.LOCAL"})-[*1..]->(h:Group {name:"DOMAIN ADMINS@TARGETDOMAIN.LOCAL"}))
RETURN p

-- Accounts with Constrained Delegation
MATCH (c) WHERE c.allowedtodelegate IS NOT NULL
RETURN c.name, c.allowedtodelegate
```

### ACL-Based Attack Path Queries
```cypher
-- Find GenericAll Rights
MATCH p=(n)-[:GenericAll]->(m)
WHERE n <> m AND NOT n.name STARTS WITH "DVTA"
RETURN p

-- Find WriteDACL Rights to Domain Object
MATCH p=(n)-[:WriteDacl]->(d:Domain)
RETURN p

-- Find ForceChangePassword Paths
MATCH p=(n)-[:ForceChangePassword]->(m:User)
RETURN p

-- Find AddMember Rights to Admin Groups
MATCH p=(n)-[:AddMember]->(g:Group)
WHERE g.name CONTAINS "ADMIN"
RETURN p

-- Find WriteOwner Abuse Paths
MATCH p=(n)-[:WriteOwner]->(m)
WHERE m:Group OR m:User
RETURN p

-- Find LAPS Password Readers
MATCH p=(n)-[:ReadLAPSPassword]->(c:Computer)
RETURN p
```

## Workflow 4: Exploitation Chain Examples

### Chain 1: ACL Abuse to Domain Admin
```
Step 1: Owned user has GenericWrite on Service Account
  -> Set SPN on service account (Targeted Kerberoasting)

Step 2: Crack service account Kerberos ticket
  -> Obtain service account password

Step 3: Service account has GenericAll on admin group
  -> Add ourselves to admin group

Step 4: Admin group is member of Domain Admins
  -> Domain Admin achieved
```

### Chain 2: Session-Based Lateral Movement
```
Step 1: BloodHound shows Domain Admin session on WORKSTATION01
Step 2: Owned user has local admin on WORKSTATION01
Step 3: Lateral move to WORKSTATION01 via PsExec/WMI
Step 4: Dump credentials from LSASS
Step 5: Obtain Domain Admin NTLM hash or Kerberos ticket
```

### Chain 3: GPO Abuse Path
```
Step 1: Owned user has WriteDACL on GPO
Step 2: Modify GPO to add immediate scheduled task
Step 3: GPO is linked to OU containing Domain Controller
Step 4: Scheduled task executes payload on DC
Step 5: Domain compromise achieved
```

### Chain 4: Constrained Delegation Abuse
```
Step 1: Compromised service account with constrained delegation to DC
Step 2: Request TGT for compromised service account
Step 3: Use S4U2Self to get ticket for high-priv user
Step 4: Use S4U2Proxy to forward ticket to target service on DC
Step 5: Access DC as Domain Admin
```

## Workflow 5: Reporting with PlumHound

### Automated Report Generation
```bash
# Install PlumHound
git clone https://github.com/PlumHound/PlumHound.git
pip install -r requirements.txt

# Generate default reports
python PlumHound.py -x tasks/default.tasks -s "bolt://localhost:7687" -u neo4j -p password

# Generate specific report
python PlumHound.py --easy -s "bolt://localhost:7687" -u neo4j -p password

# Custom task file for red team reporting
python PlumHound.py -x tasks/redteam.tasks -s "bolt://localhost:7687" -u neo4j -p password
```
