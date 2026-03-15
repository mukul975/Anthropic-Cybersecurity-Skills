# API Reference: Broken Link Hijacking

## Concept
Broken Link Hijacking (BLH) occurs when a website links to external resources
that no longer exist. An attacker can register the expired resource (domain,
GitHub repo, npm package) to serve malicious content via the trusted site.

## Hijackable Platforms

| Platform | Hijack Vector |
|----------|---------------|
| GitHub | Register abandoned username/repo |
| npm | Publish unclaimed package name |
| PyPI | Register unclaimed package |
| Twitter/X | Claim abandoned handle |
| BitBucket | Register abandoned team/repo |
| Custom domain | Register expired domain |

## Python requests — Link Checking

### HEAD Request
```python
import requests
resp = requests.head(url, timeout=10, allow_redirects=True, verify=False)
# 404 = broken link, potential hijack
```

### Connection Error = Domain Takeover
```python
try:
    requests.head(url, timeout=5)
except requests.ConnectionError:
    print("Domain may be unregistered - takeover possible")
```

## HTML Link Extraction

### Regex Patterns
```python
import re
# href links
re.finditer(r'href=["\']([^"\']+)', html)
# src links
re.finditer(r'src=["\']([^"\']+)', html)
```

## Domain Availability Check

### WHOIS Lookup
```bash
whois expired-domain.com
# "No match for" = available for registration
```

### DNS Check
```bash
dig expired-domain.com +short
# Empty = no DNS records (likely available)
```

## GitHub API — Check Username Availability

### Check user exists
```http
GET https://api.github.com/users/username
```
- 200 = exists
- 404 = available for registration

### Check repo exists
```http
GET https://api.github.com/repos/owner/repo
```

## npm Registry — Check Package

```http
GET https://registry.npmjs.org/package-name
```
- 200 = exists
- 404 = available for registration

## Subdomain Takeover Indicators

### CNAME to Unclaimed Service
```bash
dig CNAME old-service.example.com
# old-service.example.com. CNAME  unregistered.herokuapp.com.
```

### Common Vulnerable Services
| Service | Indicator |
|---------|-----------|
| GitHub Pages | 404 "There isn't a GitHub Pages site here" |
| Heroku | "No such app" |
| AWS S3 | "NoSuchBucket" |
| Azure | "404 Web Site not found" |
| Shopify | "Sorry, this shop is currently unavailable" |
