---
name: testing-for-sensitive-data-exposure
description: Identifying sensitive data exposure vulnerabilities including API key leakage, PII in responses, insecure storage, and unprotected data transmission during security assessments.
domain: cybersecurity
subdomain: web-application-security
tags: [penetration-testing, data-exposure, pii, owasp, web-security, api-keys, secrets]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Testing for Sensitive Data Exposure

## When to Use

- During authorized penetration tests when assessing data protection controls
- When evaluating applications for GDPR, PCI DSS, HIPAA, or other data protection compliance
- For identifying leaked API keys, credentials, tokens, and secrets in application responses
- When testing whether sensitive data is properly encrypted in transit and at rest
- During security assessments of APIs that handle PII, financial data, or health records

## Prerequisites

- **Authorization**: Written penetration testing agreement with data handling scope
- **Burp Suite Professional**: For intercepting and analyzing responses for sensitive data
- **trufflehog**: Secret scanning tool (`pip install trufflehog`)
- **gitleaks**: Git repository secret scanner (`go install github.com/gitleaks/gitleaks/v8@latest`)
- **curl/httpie**: For manual endpoint testing
- **Browser DevTools**: For examining local storage, session storage, and cached data
- **testssl.sh**: TLS configuration testing tool

## Workflow

### Step 1: Scan for Secrets in Client-Side Code

Search JavaScript files, HTML source, and other client-side resources for exposed secrets.

```bash
# Download and search JavaScript files for secrets
curl -s "https://target.example.com/" | \
  grep -oP 'src="[^"]*\.js[^"]*"' | \
  grep -oP '"[^"]*"' | tr -d '"' | while read js; do
    echo "=== Scanning: $js ==="
    # Handle relative URLs
    if [[ "$js" == /* ]]; then
      curl -s "https://target.example.com$js"
    else
      curl -s "$js"
    fi | grep -inE \
      "(api[_-]?key|apikey|api[_-]?secret|aws[_-]?access|aws[_-]?secret|private[_-]?key|password|secret|token|auth|credential|AKIA[0-9A-Z]{16})" \
      | head -20
done

# Search for common secret patterns
curl -s "https://target.example.com/static/app.js" | grep -nP \
  "(AIza[0-9A-Za-z-_]{35}|AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{48}|ghp_[a-zA-Z0-9]{36}|xox[bpsa]-[0-9a-zA-Z-]{10,})"

# Check source maps for exposed source code
curl -s "https://target.example.com/static/app.js.map" | head -c 500
# Source maps may contain original source code with embedded secrets

# Search HTML source for exposed data
curl -s "https://target.example.com/" | grep -inE \
  "(api_key|secret|password|token|private_key|database_url|smtp_password)" | head -20

# Check for exposed .env or configuration files
for file in .env .env.local .env.production config.json settings.json \
  .aws/credentials .docker/config.json; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.example.com/$file")
  if [ "$status" == "200" ]; then
    echo "FOUND: $file ($status)"
  fi
done
```

### Step 2: Analyze API Responses for Data Over-Exposure

Check if API endpoints return more data than necessary.

```bash
# Fetch user profile and examine response fields
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/users/me" | jq .

# Look for sensitive fields that should not be exposed:
# - password, password_hash, password_salt
# - ssn, social_security_number, national_id
# - credit_card_number, card_cvv, card_expiry
# - api_key, secret_key, access_token, refresh_token
# - internal_id, database_id
# - ip_address, session_id
# - date_of_birth, drivers_license

# Check list endpoints for excessive data
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/users" | jq '.[0] | keys'

# Compare public vs authenticated responses
echo "=== Public ==="
curl -s "https://target.example.com/api/users/1" | jq 'keys'
echo "=== Authenticated ==="
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/users/1" | jq 'keys'

# Check error responses for information leakage
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"invalid": "data"}' \
  "https://target.example.com/api/users" | jq .
# Look for: stack traces, database queries, internal paths, version info

# Test for PII in search/autocomplete responses
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/search?q=john" | jq .
# May return full user records instead of just names
```

### Step 3: Test Data Transmission Security

Verify that sensitive data is encrypted during transmission.

```bash
# Check TLS configuration
# Using testssl.sh
./testssl.sh "https://target.example.com"

# Quick TLS checks with curl
curl -s -v "https://target.example.com/" 2>&1 | grep -E "(SSL|TLS|cipher|subject)"

# Check for HTTP (non-HTTPS) endpoints
curl -s -I "http://target.example.com/" | head -5
# Should redirect to HTTPS

# Check for mixed content (HTTP resources on HTTPS pages)
curl -s "https://target.example.com/" | grep -oP "http://[^\"'> ]+" | head -20

# Check if sensitive forms submit over HTTPS
curl -s "https://target.example.com/login" | grep -oP 'action="[^"]*"'
# Form action should use HTTPS

# Check for sensitive data in URL parameters (query string)
# URLs are logged in browser history, server logs, proxy logs, Referer headers
# Look for: /login?username=admin&password=secret
# /api/data?ssn=123-45-6789
# /search?credit_card=4111111111111111

# Check WebSocket encryption
curl -s "https://target.example.com/" | grep -oP "(ws|wss)://[^\"'> ]+"
# ws:// is unencrypted; should only use wss://
```

### Step 4: Examine Browser Storage for Sensitive Data

Check local storage, session storage, cookies, and cached responses.

```bash
# Check what cookies are set and their security attributes
curl -s -I "https://target.example.com/login" | grep -i "set-cookie"

# In browser DevTools (Application tab):
# 1. Local Storage: Check for stored tokens, PII, credentials
# 2. Session Storage: Check for temporary sensitive data
# 3. IndexedDB: Check for cached application data
# 4. Cache Storage: Check for cached API responses containing PII
# 5. Cookies: Check for sensitive data in cookie values

# Common insecure storage patterns:
# localStorage.setItem('access_token', 'eyJ...');  // XSS can steal
# localStorage.setItem('user', JSON.stringify({email: '...', ssn: '...'}));
# sessionStorage.setItem('credit_card', '4111...');

# Check for autocomplete on sensitive forms
curl -s "https://target.example.com/login" | \
  grep -oP '<input[^>]*(password|credit|ssn|card)[^>]*>' | \
  grep -v 'autocomplete="off"'
# Password and credit card fields should have autocomplete="off"

# Check Cache-Control headers on sensitive pages
for page in /account/profile /api/users/me /transactions /billing; do
  echo -n "$page: "
  curl -s -I "https://target.example.com$page" \
    -H "Authorization: Bearer $TOKEN" | \
    grep -i "cache-control" | tr -d '\r'
  echo
done
# Sensitive pages should have: Cache-Control: no-store
```

### Step 5: Scan Git Repositories and Source Code for Secrets

Search for accidentally committed secrets in version control.

```bash
# Check for exposed .git directory
curl -s "https://target.example.com/.git/config"
curl -s "https://target.example.com/.git/HEAD"

# If .git is exposed, use git-dumper to download
# pip install git-dumper
git-dumper https://target.example.com/.git /tmp/target-repo

# Scan downloaded repository with trufflehog
trufflehog filesystem /tmp/target-repo

# Scan with gitleaks
gitleaks detect --source /tmp/target-repo -v

# If GitHub/GitLab repository is available (authorized scope)
trufflehog github --org target-organization --token $GITHUB_TOKEN
gitleaks detect --source https://github.com/org/repo -v

# Common secrets found in repositories:
# - AWS access keys (AKIA...)
# - Database connection strings
# - API keys (Google, Stripe, Twilio, SendGrid)
# - Private SSH keys
# - JWT signing secrets
# - OAuth client secrets
# - SMTP credentials

# Search for secrets in Docker images
# docker save target-image:latest | tar x -C /tmp/docker-layers
# Search each layer for credentials
```

### Step 6: Test Data Masking and Redaction

Verify that sensitive data is properly masked in the application.

```bash
# Check if credit card numbers are fully displayed
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/payment-methods" | jq .
# Should show: **** **** **** 4242, not full number

# Check if SSN/national ID is masked
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/users/me" | jq '.ssn'
# Should show: ***-**-6789, not full SSN

# Check API responses for password hashes
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/users" | jq '.[].password // empty'
# Should return nothing; password hashes should never be in API responses

# Check export/download features for unmasked data
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/users/export?format=csv" | head -5
# CSV exports often contain unmasked PII

# Check logging endpoints for sensitive data
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/admin/logs" | \
  grep -iE "(password|token|secret|credit_card|ssn)" | head -10
# Logs should not contain sensitive data in plaintext

# Test for sensitive data in error messages
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"duplicate@test.com"}' \
  "https://target.example.com/api/register"
# Should not reveal: "User with email duplicate@test.com already exists"
# Should show: "Registration failed" (generic)
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Sensitive Data Exposure** | Unintended disclosure of PII, credentials, financial data, or health records |
| **Data Over-Exposure** | API returning more data fields than the client needs |
| **Secret Leakage** | API keys, tokens, or credentials exposed in client-side code or logs |
| **Data at Rest** | Sensitive data stored in databases, files, or backups without encryption |
| **Data in Transit** | Sensitive data transmitted over network without TLS encryption |
| **Data Masking** | Replacing sensitive data with redacted values (e.g., showing last 4 digits of credit card) |
| **PII** | Personally Identifiable Information - data that can identify an individual |
| **Information Leakage** | Excessive error messages, stack traces, or debug information in responses |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite Professional** | Response analysis and regex-based sensitive data scanning |
| **trufflehog** | Secret detection across git repos, filesystems, and cloud storage |
| **gitleaks** | Git repository scanning for hardcoded secrets |
| **testssl.sh** | TLS/SSL configuration assessment |
| **git-dumper** | Downloading exposed .git directories from web servers |
| **SecretFinder** | JavaScript file analysis for exposed API keys and tokens |
| **Retire.js** | Detecting JavaScript libraries with known vulnerabilities |

## Common Scenarios

### Scenario 1: API Key in JavaScript Bundle
The application's JavaScript bundle contains a hardcoded Google Maps API key and a Stripe publishable key. The Stripe key has overly broad permissions, allowing the attacker to create charges.

### Scenario 2: User API Returns Password Hashes
The `/api/users` endpoint returns complete user objects including bcrypt password hashes. Attackers can extract hashes and attempt offline cracking.

### Scenario 3: PII in Cached API Responses
The user profile API endpoint returns full SSN and credit card numbers without masking. The endpoint does not set `Cache-Control: no-store`, so responses are cached in the browser and proxy caches.

### Scenario 4: Git Repository with Database Credentials
The `.git` directory is accessible on the production server. Using git-dumper, the attacker downloads the repository history, finding database credentials committed in an early commit that were later "removed" but remain in git history.

## Output Format

```
## Sensitive Data Exposure Assessment Report

**Target**: target.example.com
**Assessment Date**: 2024-01-15
**OWASP Category**: A02:2021 - Cryptographic Failures

### Findings Summary
| Finding | Severity | Data Type |
|---------|----------|-----------|
| API keys in JavaScript source | High | Credentials |
| Password hashes in API response | Critical | Authentication |
| Unmasked SSN in user profile | Critical | PII |
| Credit card number in export | High | Financial |
| .git directory exposed | Critical | Source code + secrets |
| Missing TLS on API endpoint | High | All data in transit |
| Sensitive data in error messages | Medium | Technical info |

### Critical: Exposed Secrets
| Secret Type | Location | Risk |
|-------------|----------|------|
| AWS Access Key (AKIA...) | /static/app.js line 342 | AWS resource access |
| Stripe Secret Key (sk_live_...) | .env (via .git exposure) | Payment processing |
| Database URL with credentials | .git history commit abc123 | Database access |
| JWT Signing Secret | config.json (via .git) | Token forgery |

### Data Over-Exposure in APIs
| Endpoint | Unnecessary Fields Returned |
|----------|-----------------------------|
| GET /api/users | password_hash, internal_id, created_ip |
| GET /api/users/{id} | ssn, credit_card_full, date_of_birth |
| GET /api/orders | customer_phone, customer_address |

### Recommendation
1. Remove all hardcoded secrets from client-side code; use backend proxies
2. Rotate all exposed credentials immediately
3. Remove .git directory from production web root
4. Implement response field filtering; return only required fields
5. Mask sensitive data (SSN, credit card) in all API responses
6. Add Cache-Control: no-store to all sensitive endpoints
7. Enable TLS 1.2+ on all endpoints; redirect HTTP to HTTPS
8. Implement secret scanning in CI/CD pipeline (trufflehog/gitleaks)
```
