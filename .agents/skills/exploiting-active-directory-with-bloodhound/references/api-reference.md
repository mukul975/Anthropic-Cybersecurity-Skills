# API Reference: Active Directory Analysis with BloodHound

## SharpHound — Data Collection

### Syntax
```cmd
SharpHound.exe -c All -d domain.local
SharpHound.exe -c DCOnly --ldapusername user --ldappassword pass
```

### Collection Methods
| Flag | Data Collected |
|------|----------------|
| `All` | Everything below |
| `Default` | Group, Session, Trusts, ACL, ObjectProps |
| `DCOnly` | LDAP-only (no sessions) |
| `Session` | Active sessions |
| `ACL` | Access control lists |
| `ObjectProps` | User/computer properties |

## bloodhound-python — Cross-Platform

### Syntax
```bash
bloodhound-python -d domain.local -u user -p pass -c all --zip -ns 10.10.10.1
```

### Options
| Flag | Description |
|------|-------------|
| `-d` | Domain name |
| `-u` | Username |
| `-p` | Password |
| `-c` | Collection method |
| `-ns` | Nameserver (DC IP) |
| `--zip` | Output as ZIP |

## Neo4j Cypher Queries

### Shortest Path to Domain Admins
```cypher
MATCH p=shortestPath(
    (u:User {owned:true})-[*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})
) RETURN p
```

### Kerberoastable Users
```cypher
MATCH (u:User) WHERE u.hasspn=true AND u.enabled=true
RETURN u.name, u.serviceprincipalnames
```

### Unconstrained Delegation
```cypher
MATCH (c:Computer {unconstraineddelegation:true})
RETURN c.name, c.operatingsystem
```

### DCSync Rights
```cypher
MATCH p=(u)-[:GetChanges|GetChangesAll]->(d:Domain)
RETURN u.name, d.name
```

### AS-REP Roastable
```cypher
MATCH (u:User {dontreqpreauth:true})
RETURN u.name, u.enabled
```

## BloodHound JSON Format

### Users JSON
```json
{
  "data": [{
    "Properties": {
      "name": "USER@DOMAIN.LOCAL",
      "enabled": true,
      "admincount": true,
      "hasspn": false
    },
    "Aces": [],
    "MemberOf": []
  }]
}
```

## Neo4j Python Driver

### Connection
```python
from neo4j import GraphDatabase
driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "bloodhound"))
with driver.session() as session:
    result = session.run("MATCH (n:User) RETURN count(n)")
```

## BloodHound CE API

### Authentication
```http
POST https://bloodhound:8080/api/v2/login
Content-Type: application/json

{"login_method": "secret", "secret": "api-key-here"}
```

### Search
```http
GET https://bloodhound:8080/api/v2/search?q=admin
Authorization: Bearer {token}
```
