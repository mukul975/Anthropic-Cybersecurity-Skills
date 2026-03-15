# API Reference: Security Headers Audit

## Security Headers Checked

| Header | Recommended Value | Purpose |
|--------|------------------|---------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | Force HTTPS |
| `Content-Security-Policy` | `script-src 'self' 'nonce-{random}'` | Restrict resource loading |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Control referrer leakage |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Restrict browser features |

## Cookie Security Attributes

| Attribute | Description |
|-----------|-------------|
| `Secure` | Only send over HTTPS |
| `HttpOnly` | Not accessible via JavaScript |
| `SameSite=Strict` | No cross-site cookie sending |
| `Path=/` | Restrict cookie scope |

## Online Scanners

| Tool | URL | Description |
|------|-----|-------------|
| SecurityHeaders.com | https://securityheaders.com/ | Letter-grade assessment |
| Mozilla Observatory | https://observatory.mozilla.org/ | Comprehensive scoring |
| CSP Evaluator | https://csp-evaluator.withgoogle.com/ | CSP weakness analysis |
| Hardenize | https://www.hardenize.com/ | TLS and header monitoring |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | Fetch HTTP response headers |
| `re` | stdlib | Parse CSP directives and HSTS values |

## References

- OWASP Secure Headers: https://owasp.org/www-project-secure-headers/
- MDN Security Headers: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
- HSTS Preload: https://hstspreload.org/
- CSP reference: https://content-security-policy.com/
