# API Reference: Testing API Security with OWASP Top 10

## requests Library

### Installation
```bash
pip install requests
```

### Key Methods
| Method | Description |
|--------|-------------|
| `requests.get(url, headers=, params=, timeout=)` | Send GET request |
| `requests.post(url, json=, headers=, timeout=)` | Send POST request |
| `requests.put(url, json=, headers=)` | Send PUT request |
| `requests.patch(url, json=, headers=)` | Send PATCH request |
| `requests.delete(url, headers=)` | Send DELETE request |
| `requests.options(url, headers=)` | Send OPTIONS preflight |

### Response Object
| Attribute | Description |
|-----------|-------------|
| `resp.status_code` | HTTP status code (200, 401, 403, 429) |
| `resp.headers` | Response headers dict |
| `resp.json()` | Parse response body as JSON |
| `resp.text` | Response body as string |
| `resp.elapsed` | Response time as timedelta |

## OWASP API Security Top 10 (2023)
| ID | Risk | Test Approach |
|----|------|---------------|
| API1 | Broken Object Level Auth | Iterate object IDs with another user's token |
| API2 | Broken Authentication | Brute-force login, test JWT weaknesses |
| API3 | Broken Object Property Level Auth | Check excessive data + mass assignment |
| API4 | Unrestricted Resource Consumption | Test pagination limits, rate limiting |
| API5 | Broken Function Level Auth | Access admin endpoints as regular user |
| API6 | Unrestricted Access to Sensitive Flows | Abuse OTP, reset, registration flows |
| API7 | Server-Side Request Forgery | Inject internal URLs in URL parameters |
| API8 | Security Misconfiguration | Check headers, CORS, error verbosity |
| API9 | Improper Inventory Management | Find deprecated API versions |
| API10 | Unsafe Consumption of APIs | Test trust boundaries with third-party data |

## Security Header Checks
| Header | Expected Value |
|--------|---------------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` |
| `Content-Security-Policy` | Restrictive policy |

## References
- OWASP API Security Top 10: https://owasp.org/API-Security/
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- requests docs: https://docs.python-requests.org/
