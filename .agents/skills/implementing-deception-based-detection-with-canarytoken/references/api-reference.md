# API Reference — Implementing Deception-Based Detection with Canarytoken

## Libraries Used
- **requests**: HTTP client for Thinkst Canary Console REST API
- **json**: JSON serialization for audit reports

## CLI Interface
```
python agent.py --console abc123 --auth-token TOKEN ping
python agent.py --console abc123 --auth-token TOKEN list
python agent.py --console abc123 --auth-token TOKEN alerts
python agent.py --console abc123 --auth-token TOKEN create --kind http --memo "Web server token"
python agent.py --console abc123 --auth-token TOKEN create --kind dns --memo "DNS honeypot"
python agent.py --console abc123 --auth-token TOKEN coverage
python agent.py --console abc123 --auth-token TOKEN full
```

## Core Functions

### `CanaryClient(console_domain, auth_token)` — API client
Base URL: `https://{console_domain}.canary.tools/api/v1`
Auth: `auth_token` parameter on every request.

### `create_token(kind, memo, **kwargs)` — Create Canarytoken
POST `/canarytoken/create` with `kind`, `memo`, `auth_token`.
For doc-msword: uploads file via multipart form with MIME type
`application/vnd.openxmlformats-officedocument.wordprocessingml.document`.

### `list_tokens()` — List all deployed tokens
GET `/canarytokens/fetch`. Returns array of token objects with kind, memo, url, enabled.

### `get_alerts(newer_than)` — Fetch triggered token alerts
GET `/incidents/all`. Optional `newer_than` timestamp filter.
Returns src_host (source IP), description, timestamp, acknowledged status.

### `ack_alert(incident_id)` — Acknowledge an alert
POST `/incident/acknowledge` with incident ID.

### `audit_token_coverage(client)` — Coverage analysis
Calculates: tokens by kind, triggered vs untriggered, missing token types,
coverage score as percentage of TOKEN_KINDS deployed.

### `full_audit(client)` — Comprehensive deception audit

## Canary Console API Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ping` | GET | Test API connectivity |
| `/canarytoken/create` | POST | Create new token |
| `/canarytokens/fetch` | GET | List all tokens |
| `/canarytoken/fetch` | GET | Get specific token |
| `/canarytoken/delete` | POST | Delete a token |
| `/incidents/all` | GET | Fetch all alerts |
| `/canarytoken/incidents` | GET | Alerts for specific token |
| `/incident/acknowledge` | POST | Acknowledge alert |

## Supported Token Types
| Kind | Description |
|------|-------------|
| http | Web bug — triggers on HTTP request |
| dns | DNS token — triggers on DNS resolution |
| doc-msword | MS Word document with embedded beacon |
| pdf-acrobat-reader | PDF with embedded beacon |
| aws-id | Fake AWS API key pair |
| web-image | Image with tracking pixel |
| cloned-web | Cloned website detection |
| qr-code | QR code with tracking URL |
| sensitive-cmd | Triggers on command execution |
| windows-dir | Windows folder open detection |

## Dependencies
- `requests` >= 2.28.0
- Thinkst Canary Console account with API auth token
