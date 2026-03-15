# API Reference: Performing Clickjacking Attack Test

## HTTP Security Headers

| Header | Values | Description |
|--------|--------|-------------|
| `X-Frame-Options` | `DENY`, `SAMEORIGIN`, `ALLOW-FROM uri` | Legacy frame embedding control |
| `Content-Security-Policy: frame-ancestors` | `'none'`, `'self'`, URLs | Modern CSP-based frame control |

## requests Library

| Method | Description |
|--------|-------------|
| `requests.get(url, allow_redirects=True)` | Fetch page and follow redirects |
| `response.headers.get("X-Frame-Options")` | Extract frame protection header |
| `response.headers.get("Content-Security-Policy")` | Extract CSP header |

## PoC HTML Elements

| Element | Purpose |
|---------|---------|
| `<iframe src="target" style="opacity:0">` | Invisible target frame overlay |
| `<div class="decoy">` | Visible decoy content beneath frame |
| `sandbox` attribute | Bypass JS frame-busting on iframe |

## JavaScript Frame-Busting Patterns

| Pattern | Description |
|---------|-------------|
| `top.location !== self.location` | Check if page is framed |
| `window.top !== window.self` | Alternative frame detection |
| `parent.frames.length > 0` | Check for parent frames |

## Key Libraries

- **requests** (`pip install requests`): HTTP client for header analysis
- **selenium** (optional): Browser-based testing for JS frame-busting validation
- **beautifulsoup4** (optional): Parse HTML for embedded frame-busting scripts

## Configuration

| Variable | Description |
|----------|-------------|
| Target URL | Authorized target application URL |
| Endpoint paths | Application paths to test (login, settings, admin) |

## OWASP Testing Guide

| Test ID | Description |
|---------|-------------|
| WSTG-CLNT-09 | Testing for Clickjacking |

## References

- [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
- [MDN X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)
- [MDN CSP frame-ancestors](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors)
- [PortSwigger Clickjacking](https://portswigger.net/web-security/clickjacking)
