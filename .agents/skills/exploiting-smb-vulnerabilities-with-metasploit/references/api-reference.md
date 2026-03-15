# API Reference: SMB Vulnerability Assessment Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| impacket | >=0.11.0 | SMB connection, negotiation, share enumeration |

## CLI Usage

```bash
python scripts/agent.py \
  --targets 10.10.0.0/24 \
  --username testuser --password 'P@ss' --domain CORP \
  --output smb_report.json
```

## Functions

### `check_smb_port(target, port, timeout) -> bool`
TCP connect check on port 445.

### `enumerate_smb(target, username, password, domain) -> dict`
Connects via `SMBConnection`, checks signing status, enumerates OS info and shares. Tests null session if no credentials provided.

### `scan_network(targets, username, password, domain) -> list`
Iterates over targets calling `enumerate_smb` on each.

### `find_relay_targets(results) -> list`
Returns IPs where `isSigningRequired()` returns `False` (vulnerable to NTLM relay).

### `check_null_sessions(results) -> list`
Returns IPs accepting anonymous SMB connections.

### `expand_cidr(cidr) -> list`
Expands CIDR notation to individual host IPs using `ipaddress.ip_network`.

### `generate_report(results) -> dict`
Compiles findings: signing status, null sessions, accessible shares, risk summary.

## Impacket SMBConnection Methods

| Method | Purpose |
|--------|---------|
| `SMBConnection(host, host)` | Initialize SMB connection |
| `negotiateSession()` | Negotiate SMB dialect |
| `isSigningRequired()` | Check if message signing is enforced |
| `login(user, pass, domain)` | Authenticate with credentials |
| `listShares()` | Enumerate available SMB shares |
| `getServerOS()` | Retrieve OS version string |

## Output Schema

```json
{
  "smb_hosts_found": 15,
  "signing_disabled_hosts": ["10.10.0.5", "10.10.0.12"],
  "null_session_hosts": ["10.10.0.5"],
  "accessible_shares": [{"host": "10.10.0.5", "share": "Users"}],
  "findings": ["HIGH: 2/15 hosts have SMB signing disabled"]
}
```
