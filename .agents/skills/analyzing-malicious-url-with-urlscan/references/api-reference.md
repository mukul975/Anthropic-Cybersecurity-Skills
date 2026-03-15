# API Reference: urlscan.io URL Analysis

## Base URL
```
https://urlscan.io/api/v1
```

## Authentication
```
API-Key: YOUR_API_KEY
```

## Submit Scan
```
POST /scan/
```
```json
{"url": "https://example.com", "visibility": "private"}
```
| Field | Values | Description |
|-------|--------|-------------|
| `url` | URL string | URL to scan |
| `visibility` | public/unlisted/private | Scan visibility |

Response: `{"uuid": "...", "result": "https://urlscan.io/result/UUID/", "api": "..."}`

## Get Result
```
GET /result/{uuid}/
```
Returns 404 while scanning, 200 when complete.

## Search
```
GET /search/?q=domain:example.com&size=100
```
Query fields: `domain:`, `ip:`, `server:`, `country:`, `filename:`, `hash:`

## Result Structure
| Field | Description |
|-------|-------------|
| `page.url` | Final URL after redirects |
| `page.domain` | Domain name |
| `page.ip` | Resolved IP |
| `page.country` | Server country |
| `page.status` | HTTP status code |
| `page.title` | Page title |
| `page.server` | Server header |
| `page.tlsIssuer` | TLS certificate issuer |
| `verdicts.overall.malicious` | Boolean malicious verdict |
| `verdicts.overall.score` | Risk score (0-100) |
| `lists.ips` | List of contacted IPs |
| `lists.certificates` | TLS certificates observed |
| `stats.resourceStats` | Resource type statistics |

## Screenshot
```
GET /screenshots/{uuid}.png
```

## DOM Snapshot
```
GET /dom/{uuid}/
```

## Rate Limits
- Free: 100 scans/day, 1000 searches/day
- Paid: Higher limits per plan
