# API Reference: Testing for Open Redirect Vulnerabilities

## Common Redirect Parameters

| Parameter | Context |
|-----------|---------|
| url, redirect, redirect_uri | OAuth/login flows |
| next, return, returnTo | Post-auth redirect |
| goto, target, dest | Navigation |
| continue, forward, callback | Multi-step flows |

## Bypass Techniques

| Technique | Payload | Bypass Type |
|-----------|---------|-------------|
| Protocol-relative | `//evil.com` | Scheme omission |
| Backslash | `/\evil.com` | Parser confusion |
| At-sign | `target.com@evil.com` | URL authority |
| Subdomain | `target.com.evil.com` | Domain confusion |
| Fragment | `evil.com#target.com` | Fragment bypass |
| URL encoding | `evil%2Ecom` | Encoded dot |
| CRLF | `/%0d/evil.com` | Header injection |

## HTTP Redirect Codes

| Code | Description | Caches |
|------|-------------|--------|
| 301 | Moved Permanently | Yes |
| 302 | Found | No |
| 303 | See Other | No |
| 307 | Temporary Redirect | No |
| 308 | Permanent Redirect | Yes |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | HTTP redirect testing |
| `urllib.parse` | stdlib | URL parsing and encoding |
| `json` | stdlib | Report generation |

## References

- OWASP Unvalidated Redirects: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- PortSwigger Open Redirect: https://portswigger.net/kb/issues/00500100_open-redirection-reflected
