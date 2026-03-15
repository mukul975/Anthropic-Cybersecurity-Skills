# API Reference: Investigating Phishing Email Incident

## URLScan.io API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/scan/` | POST | Submit URL for scanning (returns task UUID) |
| `/api/v1/result/{uuid}/` | GET | Retrieve scan results including screenshot and DOM |
| `/api/v1/search/?q=domain:example.com` | GET | Search for previous scans of a domain |

## VirusTotal API v3

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v3/urls` | POST | Submit URL for analysis |
| `/api/v3/analyses/{id}` | GET | Get URL analysis results with engine verdicts |
| `/api/v3/files/{hash}` | GET | Look up file hash (MD5/SHA-256) for reputation |
| `/api/v3/files` | POST | Upload file for scanning |

## MalwareBazaar API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `https://mb-api.abuse.ch/api/v1/` | POST | Query by hash, tag, or signature name |

## Microsoft Graph (Email Operations)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1.0/users/{id}/messages` | GET | Search mailbox for phishing message copies |
| `/security/alerts_v2` | GET | Retrieve Defender for O365 phishing alerts |
| `/security/incidents/{id}` | GET | Get incident details with affected entities |

## Exchange Online (Compliance Search)

| Cmdlet | Description |
|--------|-------------|
| `New-ComplianceSearch` | Create search across all mailboxes by subject/sender |
| `Start-ComplianceSearch` | Execute the compliance search |
| `New-ComplianceSearchAction -Purge` | Purge matched emails (SoftDelete or HardDelete) |

## Key Libraries

- **requests**: HTTP client for URLScan.io, VirusTotal, and MalwareBazaar APIs
- **email** (stdlib): Parse .eml files and extract headers, body, and attachments
- **hashlib** (stdlib): Calculate MD5/SHA-256 hashes for attachment analysis
- **vt-py**: Official VirusTotal Python SDK for enrichment queries

## Configuration

| Variable | Description |
|----------|-------------|
| `VT_API_KEY` | VirusTotal API key for URL and file hash lookups |
| `URLSCAN_API_KEY` | URLScan.io API key for URL submission |
| `GRAPH_ACCESS_TOKEN` | Microsoft Graph bearer token for email search |

## References

- [URLScan.io API Docs](https://urlscan.io/docs/api/)
- [VirusTotal API v3](https://docs.virustotal.com/reference/overview)
- [MalwareBazaar API](https://bazaar.abuse.ch/api/)
- [Microsoft Compliance Search](https://learn.microsoft.com/en-us/purview/ediscovery-content-search)
