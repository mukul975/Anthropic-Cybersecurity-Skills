# API Reference — Performing Kerberoasting Attack

## Libraries Used
- **subprocess**: Execute ldapsearch, PowerShell, Impacket GetUserSPNs, wevtutil
- **python-evtx**: Parse Windows Security EVTX for Event ID 4769
- **xml.etree.ElementTree**: Parse EVTX XML event data
- **impacket** (external): GetUserSPNs.py for TGS ticket requests

## CLI Interface
```
python agent.py enum --domain corp.example.com
python agent.py roast --domain corp.example.com [--user svc_account]
python agent.py analyze --file kerberoast_hashes.txt
python agent.py detect [--evtx security.evtx]
```

## Core Functions

### `enumerate_spn_accounts(domain)` — Find SPN-enabled accounts
LDAP query for `(servicePrincipalName=*)`. Falls back to PowerShell Get-ADUser.
Identifies high-value targets with admin group membership.

### `request_tgs_tickets(domain, username)` — Execute Kerberoasting
Uses Impacket GetUserSPNs with `-request` flag. Outputs $krb5tgs$ hashes.

### `analyze_kerberoast_hashes(hash_file)` — Assess hash crackability
Categorizes by encryption type: RC4 (etype 23, crackable) vs AES (etype 17/18).

### `detect_kerberoasting(evtx_file)` — Detect attack via Event ID 4769
Flags TGS requests with RC4 encryption (0x17) as suspicious Kerberoasting indicators.

## Encryption Types
| Etype | Algorithm | Crackability |
|-------|-----------|-------------|
| 0x17 (23) | RC4-HMAC | HIGH — fast offline cracking |
| 0x11 (17) | AES128 | LOW — computationally expensive |
| 0x12 (18) | AES256 | LOW — computationally expensive |

## Dependencies
```
pip install impacket python-evtx
```
System: ldapsearch (optional), PowerShell with AD module (Windows)
