# API Security Testing with Postman — API Reference

## Tools

| Tool | Install | Purpose |
|------|---------|---------|
| Newman | `npm install -g newman` | CLI runner for Postman collections |
| Postman | Desktop app from postman.com | Collection creation and manual testing |

## Newman CLI Commands

| Command | Description |
|---------|-------------|
| `newman run <collection.json>` | Execute collection |
| `newman run <col> -e <env.json>` | Run with environment variables |
| `newman run <col> --reporters cli,json` | Output in CLI and JSON format |
| `newman run <col> --reporter-json-export out.json` | Export JSON results |
| `newman run <col> --timeout-request 10000` | 10s request timeout |
| `newman run <col> --delay-request 100` | 100ms delay between requests |

## Postman Test Script Functions

| Function | Description |
|----------|-------------|
| `pm.response.code` | HTTP response status code |
| `pm.response.text()` | Response body as string |
| `pm.response.json()` | Parsed JSON response |
| `pm.expect(val).to.equal(x)` | Chai assertion |
| `pm.expect(val).to.be.oneOf([])` | Value in expected set |
| `pm.expect(val).to.not.include(s)` | String not present |
| `pm.environment.set(k, v)` | Set environment variable |

## Collection Schema (v2.1.0)

```json
{
  "info": {"name": "...", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
  "item": [{"name": "...", "request": {...}, "event": [{"listen": "test", "script": {...}}]}]
}
```

## OWASP API Security Tests

| Test | Postman Assertion |
|------|-------------------|
| BOLA/IDOR | Expect 403/404 when accessing other user's resource |
| Auth bypass | Expect 401 without valid token |
| Mass assignment | Expect role field ignored in response |
| Injection | Expect no 500 or stack trace in response |
| Data exposure | Expect sensitive fields not in response |

## External References

- [Postman Learning Center](https://learning.postman.com/)
- [Newman Documentation](https://github.com/postmanlabs/newman)
- [Postman Test Scripts](https://learning.postman.com/docs/writing-scripts/test-scripts/)
