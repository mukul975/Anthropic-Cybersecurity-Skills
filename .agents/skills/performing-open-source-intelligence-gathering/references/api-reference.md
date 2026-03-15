# API Reference — Performing Open Source Intelligence Gathering

## Libraries Used
- **requests**: HTTP requests for tech fingerprinting and social media checks
- **dns.resolver** (dnspython): DNS record enumeration and subdomain discovery
- **python-whois**: Domain WHOIS registration data
- **re**: Email pattern extraction
- **socket**: Network connectivity

## CLI Interface
```
python agent.py whois --domain example.com
python agent.py dns --domain example.com
python agent.py email --domain example.com
python agent.py tech --url https://example.com
python agent.py social --name "John Doe"
```

## Core Functions

### `whois_lookup(domain)` — Domain registration data
Returns registrar, creation/expiration dates, name servers, registrant info.

### `dns_enumeration(domain)` — DNS record and subdomain discovery
Queries 7 record types. Tests 15 common subdomain prefixes.

### `email_harvest(domain)` — Email address discovery
Uses Hunter.io API and regex pattern matching.

### `technology_fingerprint(url)` — Web technology identification
Detects: web server, framework, CMS. Audits 6 security headers.

### `social_media_search(target_name)` — Profile enumeration
Checks: LinkedIn, Twitter/X, GitHub, Facebook, Instagram.

## Security Headers Checked
Strict-Transport-Security, Content-Security-Policy, X-Frame-Options,
X-Content-Type-Options, X-XSS-Protection, Referrer-Policy

## Dependencies
```
pip install requests dnspython python-whois
```
