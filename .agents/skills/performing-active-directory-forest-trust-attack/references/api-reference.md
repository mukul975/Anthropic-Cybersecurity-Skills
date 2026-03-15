# API Reference — Performing Active Directory Forest Trust Attack

## Libraries Used
- **impacket**: SMB/RPC transport for LSA SID lookups via `lsat.hLsarLookupSids2()`
- **ldap3**: LDAP queries against `trustedDomain` objects and `foreignSecurityPrincipal` containers
- **json**: JSON serialization for audit reports

## CLI Interface
```
python agent.py --dc 10.0.0.1 --domain corp.local --username admin --password Pass123 trusts
python agent.py --dc 10.0.0.1 --domain corp.local --username admin --password Pass123 foreign
python agent.py --dc 10.0.0.1 --domain corp.local --username admin --password Pass123 lookup-sid --sid S-1-5-21-...
python agent.py --dc 10.0.0.1 --domain corp.local --username admin --password Pass123 full
```

## Core Functions

### `enumerate_trusts_ldap(dc_host, domain, username, password)` — Trust enumeration
LDAP search: `(objectClass=trustedDomain)` under `CN=System,DC=...`.
Attributes: trustPartner, trustDirection, trustType, trustAttributes, flatName.
Decodes trust attribute bitmask for SID filtering, forest transitivity, RC4 encryption.

### `enumerate_foreign_principals(dc_host, domain, username, password)` — Cross-forest members
LDAP search: `(objectClass=foreignSecurityPrincipal)` under `CN=ForeignSecurityPrincipals`.
Filters well-known SIDs (S-1-5-x with 3 dashes). Returns group memberships.

### `lookup_sid_cross_forest(dc_host, domain, username, password, target_sid)` — LSA SID resolution
Opens SMB transport to `\lsarpc`, binds MSRPC_UUID_LSAT, calls `hLsarLookupSids2()`.
Resolves SIDs across trust boundaries.

### `assess_trust_risk(trusts, foreign_principals)` — Risk scoring
Scoring: +40 SID filtering disabled, +20 RC4 encryption, +15 bidirectional trust,
+10 forest transitive.

### `full_audit(dc_host, domain, username, password)` — Comprehensive audit

## Trust Direction Values
| Value | Direction |
|-------|-----------|
| 0 | Disabled |
| 1 | Inbound |
| 2 | Outbound |
| 3 | Bidirectional |

## Trust Attribute Flags
| Flag | Hex | Description |
|------|-----|-------------|
| NON_TRANSITIVE | 0x01 | Trust does not extend transitively |
| QUARANTINED_DOMAIN | 0x04 | SID filtering enabled |
| FOREST_TRANSITIVE | 0x08 | Forest-wide transitive trust |
| USES_RC4_ENCRYPTION | 0x80 | RC4 trust key (weaker than AES) |

## Impacket RPC Calls
| Call | Module | Purpose |
|------|--------|---------|
| `hLsarOpenPolicy2` | lsad | Open LSA policy handle |
| `hLsarLookupSids2` | lsat | Resolve SIDs to names across trust |
| SMBTransport(`\lsarpc`) | transport | RPC transport over SMB |

## Dependencies
- `impacket` >= 0.11.0
- `ldap3` >= 2.9.0
- Network access to DC ports 389 (LDAP), 445 (SMB), 88 (Kerberos)
