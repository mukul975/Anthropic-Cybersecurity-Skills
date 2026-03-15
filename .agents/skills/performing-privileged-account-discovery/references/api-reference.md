# Privileged Account Discovery — API Reference

## ldap3 Library

Python LDAP client used for querying Active Directory.

### Connection Setup
```python
from ldap3 import Server, Connection, ALL, SUBTREE
server = Server("ldaps://dc.example.com", get_info=ALL, use_ssl=True)
conn = Connection(server, user="DOMAIN\user", password="pass", auto_bind=True)
```

### Key Search Filters

| Purpose | LDAP Filter |
|---------|-------------|
| Privileged group | `(&(objectClass=group)(cn=Domain Admins))` |
| Nested membership | `(memberOf:1.2.840.113556.1.4.1941:=<group_dn>)` |
| Service accounts | `(&(objectClass=user)(servicePrincipalName=*))` |
| AdminCount flag | `(&(objectClass=user)(adminCount=1))` |
| Disabled accounts | `(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))` |

### LDAP Matching Rules (OIDs)

- `1.2.840.113556.1.4.1941` — `LDAP_MATCHING_RULE_IN_CHAIN` (recursive group membership)
- `1.2.840.113556.1.4.803` — `LDAP_MATCHING_RULE_BIT_AND` (bitwise AND for UAC flags)

### UserAccountControl Flags

| Flag | Hex | Description |
|------|-----|-------------|
| ACCOUNTDISABLE | 0x0002 | Account is disabled |
| PASSWD_NOTREQD | 0x0020 | No password required |
| DONT_EXPIRE_PASSWORD | 0x10000 | Password never expires |
| NOT_DELEGATED | 0x100000 | Account is sensitive for delegation |

## Default Privileged Groups

Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Backup Operators, Server Operators, Print Operators, DnsAdmins.

## Output Schema

```json
{
  "report": "privileged_account_discovery",
  "domain": "DC=example,DC=com",
  "privileged_groups": [{"group": "Domain Admins", "member_count": 5, "members": []}],
  "service_accounts": [{"username": "svc_sql", "spns": ["MSSQLSvc/db01:1433"]}],
  "admin_count_users": ["oldadmin", "testuser"]
}
```

## CLI Usage

```bash
python agent.py --server ldaps://dc.example.com --username "DOMAIN\analyst" --password "pass" --output report.json
```
