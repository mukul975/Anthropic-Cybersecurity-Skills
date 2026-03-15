# API Reference: Web Application Penetration Test Agent

## Overview

Performs automated web application security testing: technology fingerprinting, security header checks, HTTP method testing, CORS misconfiguration detection, basic SQL injection, and reflected XSS testing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| requests | >= 2.28 | HTTP client for all web tests |

## External Tools (Optional)

| Tool | Purpose |
|------|---------|
| ffuf | Directory and file brute-forcing |

## Core Functions

### `fingerprint_technology(target_url)`
Identifies server, framework, and language from headers and cookie names.
- **Returns**: `dict` with `server` and `technologies` list

### `check_security_headers(target_url)`
Checks HSTS, CSP, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy.
- **Returns**: `dict[str, dict]` - header to presence/value mapping

### `test_http_methods(target_url)`
Tests for dangerous HTTP methods (PUT, DELETE, TRACE, CONNECT).
- **Returns**: `list[dict]` - allowed dangerous methods with risk levels

### `test_cors_config(target_url)`
Tests CORS with evil origins, null origin, and subdomain spoofing.
- **Returns**: `list[dict]` - reflected origins with credential risks

### `run_directory_bruteforce(target_url, wordlist)`
Subprocess wrapper for ffuf directory enumeration.
- **Default wordlist**: `/usr/share/seclists/Discovery/Web-Content/common.txt`

### `test_sql_injection_basic(target_url, params)`
Tests URL parameters with SQL injection payloads and checks for database error strings.
- **Risk**: CRITICAL when SQL error patterns detected

### `test_xss_basic(target_url, params)`
Tests for reflected XSS by checking if payloads appear unescaped in response body.
- **Risk**: HIGH when payload is reflected

### `run_assessment(target_url, test_params)`
Full assessment pipeline with summary statistics.

## OWASP Test Coverage

| OWASP Category | Tests Performed |
|----------------|----------------|
| A01 Broken Access Control | CORS, HTTP methods |
| A03 Injection | SQL injection, XSS |
| A05 Security Misconfiguration | Security headers, HTTP methods |

## Usage

```bash
python agent.py https://target-app.example.com
```
