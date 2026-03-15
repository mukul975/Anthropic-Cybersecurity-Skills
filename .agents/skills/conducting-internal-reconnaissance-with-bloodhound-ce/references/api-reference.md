# BloodHound CE Reconnaissance — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| neo4j | `pip install neo4j` | Neo4j graph database driver for Cypher queries |
| bloodhound | `pip install bloodhound` | Python ingestor for AD data collection |
| requests | `pip install requests` | BloodHound CE REST API client |

## Key neo4j Driver Methods

| Method | Description |
|--------|-------------|
| `GraphDatabase.driver(uri, auth=(user, pass))` | Connect to Neo4j |
| `driver.session()` | Open a session for queries |
| `session.run(cypher, **params)` | Execute Cypher query |
| `driver.close()` | Close driver connection |

## Critical Cypher Queries

| Query Purpose | Cypher Pattern |
|---------------|----------------|
| Path to DA | `MATCH p=shortestPath((u:User)-[*1..]->(g:Group {name:"DOMAIN ADMINS@..."}))` |
| Kerberoastable | `MATCH (u:User) WHERE u.hasspn = true AND u.enabled = true` |
| Unconstrained Delegation | `MATCH (c:Computer) WHERE c.unconstraineddelegation = true` |
| AS-REP Roastable | `MATCH (u:User) WHERE u.dontreqpreauth = true` |
| DCSync rights | `MATCH p=(u)-[:GetChanges|GetChangesAll]->(d:Domain)` |

## BloodHound Python Ingestor

```bash
bloodhound-python -d domain.local -u user -p pass -ns DC_IP -c all --zip
```

Collection methods: `all`, `group`, `localadmin`, `session`, `trusts`, `objectprops`, `acl`

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|----|
| Account Discovery | T1087 |
| Permission Groups Discovery | T1069 |
| Domain Trust Discovery | T1482 |

## External References

- [BloodHound CE Documentation](https://bloodhound.readthedocs.io/)
- [neo4j Python Driver](https://neo4j.com/docs/python-manual/current/)
- [BloodHound Cypher Cheatsheet](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/)
