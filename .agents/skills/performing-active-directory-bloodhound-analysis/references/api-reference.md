# API Reference: BloodHound AD Attack Path Analysis

## neo4j Python Driver
```python
from neo4j import GraphDatabase
driver = GraphDatabase.driver(uri, auth=(user, password))
driver.verify_connectivity()
with driver.session() as session:
    results = session.run(query, parameters)
    records = [dict(record) for record in results]
driver.close()
```

## Key BloodHound Cypher Queries

### Domain Admins
```cypher
MATCH (u:User)-[:MemberOf*1..]->(g:Group)
WHERE g.name STARTS WITH 'DOMAIN ADMINS'
RETURN u.name, u.enabled
```

### Shortest Path to DA
```cypher
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group))
WHERE g.name STARTS WITH 'DOMAIN ADMINS'
RETURN u.name, length(p) AS hops ORDER BY hops
```

### Kerberoastable Users
```cypher
MATCH (u:User) WHERE u.hasspn=true AND u.enabled=true
RETURN u.name, u.serviceprincipalnames
```

### Unconstrained Delegation
```cypher
MATCH (c:Computer) WHERE c.unconstraineddelegation=true
RETURN c.name, c.operatingsystem
```

## BloodHound Node Types
| Node | Properties |
|------|-----------|
| User | name, enabled, hasspn, admincount, owned, dontreqpreauth |
| Computer | name, operatingsystem, unconstraineddelegation, enabled |
| Group | name, admincount, objectid |
| GPO | name, gpcpath |
| OU | name, guid |

## BloodHound Edge Types
| Edge | Meaning |
|------|---------|
| MemberOf | Group membership |
| AdminTo | Local admin rights |
| HasSession | Active session on computer |
| GenericAll | Full object control |
| WriteDacl | Can modify ACL |
| GpLink | GPO linked to OU |
