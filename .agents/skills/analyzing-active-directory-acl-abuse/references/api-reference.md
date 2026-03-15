# Active Directory ACL Abuse API Reference

## ldap3 Python Connection

```python
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE

server = Server("192.168.1.10", get_info=ALL, use_ssl=False)
conn = Connection(server, user="DOMAIN\\user", password="pass",
                  authentication=NTLM, auto_bind=True)

# Search with nTSecurityDescriptor
conn.search(
    "DC=corp,DC=example,DC=com",
    "(objectClass=group)",
    search_scope=SUBTREE,
    attributes=["distinguishedName", "sAMAccountName",
                "objectClass", "nTSecurityDescriptor"],
)
```

## SDDL ACE Format

```
ACE String: (ace_type;ace_flags;rights;object_guid;inherit_guid;trustee_sid)
Example:    (A;;GA;;;S-1-5-21-xxx-512)
```

| Component | Description |
|-----------|-------------|
| `A` | Access Allowed |
| `D` | Access Denied |
| `OA` | Object Access Allowed |
| `GA` | Generic All |
| `GW` | Generic Write |
| `WD` | Write DACL |
| `WO` | Write Owner |

## Dangerous Permission Bitmasks

| Permission | Hex Mask | Risk |
|-----------|----------|------|
| GenericAll | `0x10000000` | Full control over object |
| GenericWrite | `0x40000000` | Modify all writable attributes |
| WriteDACL | `0x00040000` | Modify object permissions |
| WriteOwner | `0x00080000` | Take object ownership |
| WriteProperty | `0x00000020` | Write specific properties |
| ExtendedRight | `0x00000100` | Extended rights (password reset, etc.) |
| Self | `0x00000008` | Self-membership modification |
| Delete | `0x00010000` | Delete the object |

## BloodHound Cypher Queries for ACL Paths

```cypher
-- Find all users with GenericAll on Domain Admins
MATCH p=(n:User)-[r:GenericAll]->(g:Group {name:"DOMAIN ADMINS@CORP.COM"})
RETURN p

-- Find WriteDACL paths from non-admins to high-value targets
MATCH (n:User {admincount:false})
MATCH p=allShortestPaths((n)-[r:WriteDacl|WriteOwner|GenericAll*1..]->(m:Group))
WHERE m.highvalue = true
RETURN p

-- Find GenericWrite on computers for RBCD attacks
MATCH p=(n:User)-[r:GenericWrite]->(c:Computer)
WHERE NOT n.admincount
RETURN n.name, c.name

-- Enumerate all outbound ACL edges for a principal
MATCH p=(n {name:"HELPDESK@CORP.COM"})-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns]->(m)
RETURN type(r), m.name, labels(m)

-- Find shortest ACL abuse path to Domain Admin
MATCH (n:User {name:"JSMITH@CORP.COM"})
MATCH (da:Group {name:"DOMAIN ADMINS@CORP.COM"})
MATCH p=shortestPath((n)-[r:MemberOf|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns|ForceChangePassword*1..]->(da))
RETURN p
```

## PowerView Commands for ACL Enumeration

```powershell
# Get ACL for Domain Admins group
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs

# Find interesting ACEs for non-admin users
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner"
}

# Get ACL for specific OU
Get-DomainObjectAcl -SearchBase "OU=Servers,DC=corp,DC=com" -ResolveGUIDs
```
