# API Rate Limiting Bypass — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| requests | `pip install requests` | HTTP request sending with custom headers |

## Rate Limit Response Headers

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests per window |
| `X-RateLimit-Remaining` | Requests remaining in window |
| `X-RateLimit-Reset` | Timestamp when limit resets |
| `Retry-After` | Seconds to wait before retrying |
| `RateLimit-Policy` | IETF draft rate limit policy |

## IP Spoofing Bypass Headers

| Header | Description |
|--------|-------------|
| `X-Forwarded-For` | Standard proxy forwarding header |
| `X-Real-IP` | NGINX real client IP |
| `X-Originating-IP` | Client originating IP |
| `X-Client-IP` | Client IP identifier |
| `True-Client-IP` | Akamai/CDN client IP |
| `CF-Connecting-IP` | Cloudflare client IP |
| `Forwarded` | RFC 7239 forwarded header |

## Bypass Techniques

| Technique | Description | Severity |
|-----------|-------------|----------|
| Header IP rotation | Rotate X-Forwarded-For per request | HIGH |
| HTTP method switching | GET rate-limited but POST is not | MEDIUM |
| Path variation | `/api/users` vs `/api/users/` | MEDIUM |
| Case variation | `/API/Users` vs `/api/users` | MEDIUM |
| URL encoding | `%2Fapi%2Fusers` instead of `/api/users` | MEDIUM |
| Null byte injection | Append `%00` to URL path | HIGH |
| API version switching | `/v1/users` vs `/v2/users` | MEDIUM |
| Parameter pollution | Duplicate query parameters | MEDIUM |

## OWASP API4:2023 — Unrestricted Resource Consumption

| Risk | Description |
|------|-------------|
| Missing rate limits | No throttling on sensitive endpoints |
| Per-IP only limits | Bypassed with header spoofing |
| No auth-based limiting | Rate limit tied to IP, not user |
| Inconsistent enforcement | Different limits per method/version |

## External References

- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [IETF RateLimit Header Fields](https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/)
- [HackTricks Rate Limit Bypass](https://book.hacktricks.xyz/pentesting-web/rate-limit-bypass)
