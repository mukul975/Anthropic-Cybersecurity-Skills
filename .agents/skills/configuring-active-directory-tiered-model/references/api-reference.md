# Active Directory Tiered Model — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| ldap3 | `pip install ldap3` | LDAP queries for AD group and account enumeration |
| pyad | `pip install pyad` | Windows AD object manipulation |

## Key ldap3 Methods

| Method | Description |
|--------|-------------|
| `Connection(server, user, password, authentication=NTLM)` | NTLM-authenticated LDAP bind |
| `conn.search(base_dn, filter, attributes)` | Search AD objects |
| `conn.entries` | Result entries from search |

## AD Tier Definitions (Microsoft ESAE)

| Tier | Assets | Admin Accounts |
|------|--------|----------------|
| Tier 0 | Domain Controllers, AD, PKI, ADFS | Domain Admins, Enterprise Admins |
| Tier 1 | Member servers, applications | Server admins, app admins |
| Tier 2 | Workstations, end users | Help desk, workstation admins |

## Critical AD Groups (Tier 0)

| Group | SID Suffix |
|-------|-----------|
| Domain Admins | -512 |
| Enterprise Admins | -519 |
| Schema Admins | -518 |
| Administrators | -544 |
| Account Operators | -548 |
| Backup Operators | -551 |

## UserAccountControl Flags

| Flag | Value | Description |
|------|-------|-------------|
| ACCOUNTDISABLE | 0x2 | Account is disabled |
| DONT_EXPIRE_PASSWORD | 0x10000 | Password never expires |
| NOT_DELEGATED | 0x100000 | Account is sensitive for delegation |

## External References

- [Microsoft ESAE Architecture](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model)
- [ldap3 Documentation](https://ldap3.readthedocs.io/)
- [AD Security Best Practices](https://adsecurity.org/)
