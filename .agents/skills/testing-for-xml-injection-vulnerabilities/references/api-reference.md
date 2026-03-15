# API Reference: Testing for XML Injection Vulnerabilities

## XXE Payload Types

| Payload | Severity | Description |
|---------|----------|-------------|
| File read (Linux) | Critical | `file:///etc/passwd` entity inclusion |
| File read (Windows) | Critical | `file:///c:/windows/win.ini` entity |
| SSRF via HTTP | Critical | Entity fetching internal metadata URL |
| Parameter entity | High | External DTD loading via `%entity` |
| Billion laughs | High | Recursive entity expansion (DoS) |
| UTF-7 encoding | High | Encoding bypass for WAF evasion |

## XPath Injection Payloads

| Payload | Purpose |
|---------|---------|
| `' or '1'='1` | Boolean-based auth bypass |
| `'] \| //user/password \| //foo['` | Data extraction via union |
| `1 or 1=1` | Numeric context injection |

## Detection Indicators

| Attack | Success Indicator |
|--------|-------------------|
| Linux file read | `root:` in response body |
| Windows file read | `[fonts]` or `extensions` in response |
| SSRF metadata | `ami-id` or `instance-id` in response |
| Billion laughs | Response time > 5 seconds |
| Content-type switch | XML accepted when JSON expected |
| SVG XXE | `root:` in upload response |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | HTTP POST with XML payloads |
| `json` | stdlib | Report generation |
| `pathlib` | stdlib | Output directory management |

## References

- OWASP XXE Prevention: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- PortSwigger XXE: https://portswigger.net/web-security/xxe
- PayloadsAllTheThings XXE: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection
