# API Reference: Testing for Host Header Injection

## Alternative Host Headers

| Header | Description |
|--------|-------------|
| `X-Forwarded-Host` | Proxy-set original host |
| `X-Host` | Alternative host header |
| `X-Forwarded-Server` | Forwarded server name |
| `X-HTTP-Host-Override` | Host override |
| `Forwarded: host=` | RFC 7239 forwarded header |
| `X-Original-URL` | URL rewrite override |

## Attack Scenarios

| Attack | Severity | Impact |
|--------|----------|--------|
| Password reset poisoning | Critical | Token theft via poisoned link |
| Web cache poisoning | Critical | Stored XSS via cached response |
| SSRF via Host | High | Internal service access |
| Virtual host bypass | Medium | Access to other vhosts |
| Open redirect | Medium | Phishing via redirect |

## Test Techniques

| Technique | Payload Example |
|-----------|----------------|
| Direct Host override | `Host: evil.com` |
| Alternative header | `X-Forwarded-Host: evil.com` |
| Port injection | `Host: target.com:@evil.com` |
| Double Host | Two Host headers |
| Absolute URL | `GET http://target.com/ Host: evil.com` |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | HTTP requests with custom headers |
| `json` | stdlib | Report generation |

## References

- PortSwigger Host Header: https://portswigger.net/web-security/host-header
- OWASP Host Header: https://owasp.org/www-project-web-security-testing-guide/
