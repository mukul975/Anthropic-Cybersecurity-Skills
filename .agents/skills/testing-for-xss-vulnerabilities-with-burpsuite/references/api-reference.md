# API Reference: Testing for XSS Vulnerabilities with Burp Suite

## Burp Suite Professional Components

### Scanner
- Active scan: Automatically tests parameters for XSS
- Passive scan: Identifies reflected inputs and missing security headers
- Scan configuration: XSS-focused audit checks

### Repeater
- Send individual requests for manual payload testing
- Compare request/response pairs across payload variations
- Test character encoding behavior

### Intruder
- Positions: Mark injectable parameters
- Payloads: Load XSS wordlists
- Grep-Match: Flag responses containing `alert(`, `onerror=`, `<script>`
- Attack types: Sniper (single param), Battering Ram (same payload all positions)

### DOM Invader
- Built-in browser extension for DOM XSS testing
- Canary injection and sink monitoring
- Source-to-sink data flow tracing

## requests Library (Companion Script)

### Reflection Detection
```python
canary = "xsscanary12345"
resp = requests.get(f"{url}?q={canary}")
if canary in resp.text:
    # Determine context and fuzz with payloads
```

### Character Encoding Test
```python
resp = requests.get(f'{url}?q={quote("<>\"\'&/")}'
unencoded = [ch for ch in '<>"\'&/' if ch in resp.text]
```

## Burp Extensions for XSS
| Extension | Purpose |
|-----------|---------|
| Hackvertor | Advanced payload encoding/transformation |
| XSS Validator | Confirm XSS execution in headless browser |
| Reflector | Highlight reflected parameters in proxy |
| Active Scan++ | Enhanced active scanning rules |

## CSP Bypass Techniques
| Weakness | Bypass |
|----------|--------|
| `unsafe-inline` | Direct `<script>` injection |
| `unsafe-eval` | Use `eval()`, `setTimeout()` |
| Whitelisted CDN | JSONP callback or Angular gadgets |
| Missing `base-uri` | `<base>` tag hijack for relative scripts |

## References
- Burp Suite docs: https://portswigger.net/burp/documentation
- PortSwigger XSS labs: https://portswigger.net/web-security/cross-site-scripting
- DOM Invader: https://portswigger.net/burp/documentation/desktop/tools/dom-invader
- Dalfox (CLI scanner): https://github.com/hahwul/dalfox
