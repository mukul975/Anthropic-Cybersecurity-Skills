# Authenticated Vulnerability Scan — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| requests | `pip install requests` | Nessus REST API client |

## Nessus REST API Authentication

```
Header: X-ApiKeys: accessKey=<key>; secretKey=<key>
```

## Nessus API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/scans` | List all scans |
| GET | `/scans/{id}` | Scan details with results |
| GET | `/scans/{id}/hosts/{host_id}` | Per-host vulnerability details |
| POST | `/scans` | Create new scan |
| POST | `/scans/{id}/launch` | Launch existing scan |
| POST | `/scans/{id}/export` | Export results (nessus/csv/html) |
| GET | `/policies` | List scan policies |
| GET | `/credentials` | List stored credentials |

## Severity Levels

| Index | Name | CVSS Range |
|-------|------|-----------|
| 4 | Critical | 9.0 - 10.0 |
| 3 | High | 7.0 - 8.9 |
| 2 | Medium | 4.0 - 6.9 |
| 1 | Low | 0.1 - 3.9 |
| 0 | Info | Informational |

## Credential Types for Authenticated Scans

| Type | Protocol | Checks Enabled |
|------|----------|---------------|
| SSH | Linux/macOS | Package versions, file permissions, configs |
| SMB | Windows | Patch levels, registry, installed software |
| ESXi | VMware | Hypervisor patches, VM configurations |
| SNMP | Network devices | Device firmware, community string audit |
| Database | SQL Server/Oracle | DB-level patches, user permissions |

## Key Nessus Plugin Families

| Family | Description |
|--------|-------------|
| Windows: Microsoft Bulletins | Microsoft security patches |
| Ubuntu Local Security Checks | Ubuntu package vulnerabilities |
| CGI abuses | Web application vulnerabilities |
| Misc. | Miscellaneous security checks |
| Service detection | Network service identification |

## External References

- [Nessus REST API Docs](https://docs.tenable.com/nessus/Content/API.htm)
- [Tenable Developer Portal](https://developer.tenable.com/)
- [Nessus Credentialed Scanning](https://docs.tenable.com/nessus/Content/CredentialedChecksOnWindows.htm)
