# API Reference: Active Directory Attack Simulation Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| impacket | >=0.11.0 | Kerberos attacks, SMB interaction, DCSync |
| ldap3 | >=2.9 | LDAP enumeration of users, groups, SPNs |

## CLI Usage

```bash
python scripts/agent.py \
  --dc-ip 10.10.10.1 \
  --domain corp.local \
  --username testuser \
  --password 'P@ssw0rd' \
  --output ad_report.json
```

## Functions

### `ldap_enum_users(dc_ip, domain, username, password) -> list`
Enumerates all domain user objects via LDAP. Returns list of dicts with `samaccountname`, `spns`, `no_preauth`, `admin_count`.

### `find_kerberoastable(users) -> list`
Filters user list for accounts with `servicePrincipalName` set (targets for Kerberoasting via `impacket-GetUserSPNs`).

### `find_asrep_roastable(users) -> list`
Filters for accounts with UAC flag `DONT_REQUIRE_PREAUTH` (0x400000) set.

### `enum_groups(dc_ip, domain, username, password) -> dict`
Queries LDAP for membership of Domain Admins, Enterprise Admins, Schema Admins, Backup Operators, Account Operators.

### `check_smb_signing(target_ip) -> bool`
Connects to SMB on port 445 and checks whether signing is required. Returns `False` when relay attacks are possible.

### `generate_report(users, groups, dc_ip) -> dict`
Aggregates findings into a JSON report with risk summary.

## Output Schema

```json
{
  "assessment_date": "ISO-8601",
  "total_users": 500,
  "kerberoastable_accounts": ["svc-sql", "svc-web"],
  "asrep_roastable_accounts": ["old-account"],
  "high_value_groups": {"Domain Admins": 5},
  "dc_smb_signing_required": true,
  "risk_summary": ["CRITICAL: 2 accounts are Kerberoastable"]
}
```

## Key Impacket Modules

- `impacket.krb5.kerberosv5`: TGT/TGS request functions
- `impacket.smbconnection.SMBConnection`: SMB negotiation and signing check
- `impacket.dcerpc.v5.samr`: SAM Remote Protocol for user/group enumeration
- `ldap3.Connection.search()`: LDAP search with filter and attribute list
