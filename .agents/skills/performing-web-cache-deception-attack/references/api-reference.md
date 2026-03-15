# API Reference: Web Cache Deception Attack

## Attack Technique

| Step | Action | Description |
|------|--------|-------------|
| 1 | Identify authenticated endpoint | Find URL returning personalized content |
| 2 | Append static extension | `/account/nonexistent.css` |
| 3 | CDN caches response | Proxy treats as static file |
| 4 | Access cached URL unauthenticated | Receive victim's personalized data |

## Static Extensions to Test

| Extension | Type | Cache Likelihood |
|-----------|------|-----------------|
| `.css` | Stylesheet | Very High |
| `.js` | JavaScript | Very High |
| `.png`, `.jpg`, `.gif` | Image | High |
| `.woff`, `.woff2` | Font | High |
| `.pdf` | Document | Medium |
| `.ico` | Icon | Medium |

## Cache Detection Headers

| Header | Cached Indicators |
|--------|------------------|
| `X-Cache` | HIT |
| `CF-Cache-Status` | HIT (Cloudflare) |
| `X-Cache-Status` | HIT (Nginx proxy_cache) |
| `Age` | Non-zero value |
| `X-Varnish` | Two IDs = cache hit |

## Path Delimiter Confusion

| Delimiter | URL Example |
|-----------|-------------|
| `;` | `/account;test.css` |
| `%23` | `/account%23test.css` |
| `%3f` | `/account%3ftest.css` |

## Mitigation

| Control | Description |
|---------|-------------|
| `Cache-Control: no-store` | Prevent caching of authenticated pages |
| Validate file extension | Only cache actual static files |
| `Vary: Cookie` | Separate cache by session |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | HTTP requests with/without auth |

## References

- PortSwigger Web Cache Deception: https://portswigger.net/web-security/web-cache-deception
- Original Research (Omer Gil): https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html
