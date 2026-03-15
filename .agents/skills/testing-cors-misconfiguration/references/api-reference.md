# API Reference: Testing CORS Misconfiguration

## requests Library

### Key Methods for CORS Testing
```python
# Test origin reflection
resp = requests.get(url, headers={"Origin": "https://evil.com"})

# Test preflight
resp = requests.options(url, headers={
    "Origin": "https://evil.com",
    "Access-Control-Request-Method": "PUT",
    "Access-Control-Request-Headers": "Authorization"
})
```

## CORS Response Headers
| Header | Description |
|--------|-------------|
| `Access-Control-Allow-Origin` | Specifies allowed origin(s) |
| `Access-Control-Allow-Credentials` | Whether cookies/auth headers are sent |
| `Access-Control-Allow-Methods` | Allowed HTTP methods for cross-origin |
| `Access-Control-Allow-Headers` | Allowed request headers |
| `Access-Control-Expose-Headers` | Headers accessible to JavaScript |
| `Access-Control-Max-Age` | Preflight cache duration in seconds |

## Vulnerability Patterns
| Pattern | Severity | Description |
|---------|----------|-------------|
| Origin reflection + credentials | Critical | Any site can read authenticated responses |
| Null origin + credentials | High | Exploitable via sandboxed iframes |
| Wildcard + credentials | Critical | Invalid but sometimes misconfigured |
| Subdomain wildcard trust | Medium | XSS on subdomain enables CORS abuse |
| Regex bypass | High | Prefix/suffix matching allows attacker domains |
| Internal origins trusted | Medium | localhost/10.x accepted in production |

## Testing Checklist
1. Send `Origin: https://evil.com` - check if reflected in ACAO
2. Send `Origin: null` - check if null is accepted
3. Test subdomain variations of target domain
4. Test prefix/suffix bypass: `target.com.evil.com`
5. Test protocol downgrade: `http://` instead of `https://`
6. Check preflight Max-Age (>86400 is excessive)
7. Verify wildcard `*` is not combined with credentials

## References
- MDN CORS: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
- PortSwigger CORS: https://portswigger.net/web-security/cors
- OWASP CORS Testing: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing
