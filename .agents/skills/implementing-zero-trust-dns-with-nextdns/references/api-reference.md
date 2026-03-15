# API Reference: Zero Trust DNS with NextDNS

## NextDNS REST API

### Authentication
```
Header: X-Api-Key: <your-api-key>
Base URL: https://api.nextdns.io
```

### Profile Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/profiles/{id}` | Get profile configuration |
| GET | `/profiles/{id}/security` | Get security feature settings |
| GET | `/profiles/{id}/denylist` | Get blocked domains list |
| GET | `/profiles/{id}/allowlist` | Get allowed domains list |
| GET | `/profiles/{id}/logs` | Get DNS query logs |
| GET | `/profiles/{id}/analytics/status` | Query volume analytics |
| GET | `/profiles/{id}/analytics/domains` | Top queried domains |
| GET | `/profiles/{id}/analytics/blockedReasons` | Block reason breakdown |

### Security Feature Keys
| Key | Feature |
|-----|---------|
| `threatIntelligenceFeeds` | Real-time threat intel blocking |
| `aiDetection` | AI-based threat detection |
| `googleSafeBrowsing` | Google Safe Browsing integration |
| `cryptojacking` | Cryptomining domain blocking |
| `dnsRebinding` | DNS rebinding attack protection |
| `idnHomographs` | IDN homograph attack protection |
| `typosquatting` | Typosquatting domain detection |
| `dga` | Domain generation algorithm blocking |
| `nrd` | Newly registered domain blocking |

### Log Entry Fields
| Field | Description |
|-------|-------------|
| `domain` | Queried domain name |
| `status` | `allowed`, `blocked`, or `default` |
| `reasons` | Array of block reasons |
| `clientIp` | Requesting client IP |
| `timestamp` | Query timestamp (ISO 8601) |

## References
- NextDNS API: https://nextdns.github.io/api/
- NextDNS Security: https://nextdns.io/security
