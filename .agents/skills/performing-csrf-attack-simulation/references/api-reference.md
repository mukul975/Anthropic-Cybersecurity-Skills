# API Reference: Performing CSRF Attack Simulation

## HTTP Headers for CSRF Protection

| Header | Description |
|--------|-------------|
| `Set-Cookie: SameSite=Strict` | Prevents cookie from being sent in cross-site requests |
| `Set-Cookie: SameSite=Lax` | Allows cookies on top-level GET navigations only |
| `X-CSRF-Token` | Custom header carrying CSRF token |
| `Origin` | Sent by browsers on cross-origin POST requests |
| `Referer` | Indicates the source page of the request |

## CSRF Token Patterns (HTML)

| Pattern | Framework |
|---------|-----------|
| `<input name="csrf_token" value="...">` | Generic |
| `<input name="csrfmiddlewaretoken">` | Django |
| `<input name="authenticity_token">` | Ruby on Rails |
| `<input name="__RequestVerificationToken">` | ASP.NET |
| `<meta name="csrf-token" content="...">` | Rails/Laravel meta tag |

## requests Library

| Method | Description |
|--------|-------------|
| `session.get(url)` | Fetch page to extract CSRF tokens |
| `session.post(url, data)` | Submit form with/without CSRF token |
| `session.cookies` | Access session cookies for SameSite analysis |

## Key Libraries

- **requests** (`pip install requests`): HTTP client with session cookie management
- **beautifulsoup4** (`pip install beautifulsoup4`): Parse HTML forms and extract tokens
- **selenium** (optional): Browser-based CSRF testing with full JS execution

## PoC Generation

| Element | Purpose |
|---------|---------|
| `<form action="target" method="POST">` | Cross-origin form submission |
| `<input type="hidden">` | Pre-filled form parameters |
| `document.getElementById().submit()` | Auto-submit on page load |
| `<img src="target?action=delete">` | GET-based CSRF via image tag |

## OWASP Testing Guide

| Test ID | Description |
|---------|-------------|
| WSTG-SESS-05 | Testing for Cross-Site Request Forgery |

## References

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger CSRF](https://portswigger.net/web-security/csrf)
- [MDN SameSite Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)
- [Burp Suite CSRF PoC Generator](https://portswigger.net/burp/documentation/desktop/tools/engagement-tools/generate-csrf-poc)
