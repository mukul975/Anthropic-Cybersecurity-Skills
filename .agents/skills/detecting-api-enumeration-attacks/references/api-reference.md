# API Enumeration Attack Detection — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| requests | `pip install requests` | WAF and SIEM API queries |

## Detection Techniques

| Technique | Indicator | Severity |
|-----------|-----------|----------|
| Sequential ID enumeration | /api/users/1, /api/users/2, ... | HIGH |
| Endpoint fuzzing | High 404 rate on /api/* paths | HIGH |
| Rate abuse | >50 API requests/minute from single IP | MEDIUM |
| Path discovery | Requests to /swagger, /api-docs, /graphql | HIGH |
| BOLA/IDOR probing | Access to other users' resource IDs | CRITICAL |

## NGINX Combined Log Format

```
$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
```

## Common Enumeration Paths

| Pattern | Description |
|---------|-------------|
| `/api/v1/users/{id}` | User ID enumeration |
| `/api/v1/accounts/{uuid}` | Account UUID guessing |
| `/graphql?query={__schema}` | GraphQL introspection |
| `/swagger/v1/swagger.json` | API documentation discovery |
| `/api-docs`, `/.well-known` | Endpoint discovery |

## WAF Rule Categories

| Category | Description |
|----------|-------------|
| `rate-limit` | Request rate exceeds threshold |
| `api-abuse` | Automated API enumeration |
| `bola` | Broken Object Level Authorization |
| `scanner` | Known scanner/fuzzer user-agent |

## OWASP API Security Top 10

| ID | Risk |
|----|------|
| API1 | Broken Object Level Authorization |
| API2 | Broken Authentication |
| API3 | Broken Object Property Level Auth |
| API4 | Unrestricted Resource Consumption |
| API5 | Broken Function Level Authorization |

## External References

- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [OWASP Testing Guide — API Testing](https://owasp.org/www-project-web-security-testing-guide/)
- [ModSecurity API Protection Rules](https://coreruleset.org/)
