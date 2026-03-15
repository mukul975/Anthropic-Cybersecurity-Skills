# API Reference: Scanning Infrastructure with Nessus

## Nessus REST API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/session` | Authenticate and get token |
| GET | `/scans` | List all scans |
| POST | `/scans` | Create new scan |
| POST | `/scans/{id}/launch` | Launch a scan |
| GET | `/scans/{id}` | Get scan results |
| POST | `/scans/{id}/export` | Export scan results |
| GET | `/scans/{id}/export/{fid}/status` | Check export status |
| GET | `/scans/{id}/hosts/{hid}` | Get host details |

## Scan Types

| Type | Template UUID | Use Case |
|------|--------------|----------|
| Basic Network Scan | `ab4bacd2-...` | Standard vulnerability scan |
| Advanced Scan | `ad629e16-...` | Custom plugin selection |
| Credentialed Patch Audit | `0c3a6b1f-...` | Authenticated patch check |
| Web Application Tests | `1c35d5a5-...` | Web vulnerability scan |
| Compliance Audit | `bbd4f805-...` | CIS/STIG/PCI checks |

## Severity Levels

| Level | Value | CVSS Range | SLA |
|-------|-------|-----------|-----|
| Critical | 4 | 9.0 - 10.0 | Immediate |
| High | 3 | 7.0 - 8.9 | 7-14 days |
| Medium | 2 | 4.0 - 6.9 | 30 days |
| Low | 1 | 0.1 - 3.9 | Next window |
| Info | 0 | N/A | No action |

## Export Formats

| Format | Description |
|--------|-------------|
| `nessus` | XML format for import into other tools |
| `csv` | Comma-separated for spreadsheet analysis |
| `html` | Human-readable HTML report |
| `pdf` | Formatted PDF report |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | Nessus REST API calls |
| `json` | stdlib | Parse API responses |
| `urllib3` | >=1.26 | SSL warning suppression |

## References

- Nessus REST API: https://developer.tenable.com/reference/navigate
- Tenable Documentation: https://docs.tenable.com/nessus/
- Nessus CLI: https://docs.tenable.com/nessus/Content/NessusCLI.htm
