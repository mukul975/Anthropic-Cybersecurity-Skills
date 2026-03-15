# API Reference: Forced Browsing Authentication Bypass Agent

## Overview

Tests web applications for unprotected endpoints, authentication bypass via HTTP methods and path normalization, and exposed sensitive files. For authorized penetration testing only.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP requests to target endpoints |

## CLI Usage

```bash
# Test common admin paths
python agent.py --target https://target.example.com --admin-paths --session-cookie <token>

# Test with custom wordlist
python agent.py --target https://target.example.com --wordlist /path/to/wordlist.txt
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--target` | Yes | Target base URL |
| `--wordlist` | No | Path to directory/file wordlist |
| `--session-cookie` | No | Valid session cookie for authenticated comparison |
| `--admin-paths` | No | Use built-in common admin path list |
| `--output` | No | Output file (default: `forced_browsing_report.json`) |

## Key Functions

### `test_endpoint(base_url, path, session_cookie)`
Tests an endpoint with and without authentication, comparing response status and size to detect auth bypass.

### `enumerate_directories(base_url, wordlist, session_cookie)`
Iterates through wordlist paths, recording responses with status 200, 301, 302, or 403.

### `test_http_method_bypass(base_url, path)`
Tests GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD on protected endpoints to find method-based bypasses.

### `test_path_traversal_bypass(base_url, path)`
Tests URL normalization variants (case changes, path traversal, encoding, semicolons) against protected paths.

### `check_sensitive_files(base_url)`
Checks for exposed `.env`, `.git`, backup files, and configuration files.

### `generate_report(findings, method_results, sensitive_files)`
Compiles all findings into a structured JSON pentest report.

## Output Schema

```json
{
  "total_endpoints_found": 15,
  "auth_bypass_candidates": [{"path": "/admin", "unauth_status": 200}],
  "accessible_without_auth": [...],
  "http_method_bypass": {"/admin": {"GET": 403, "PUT": 200}},
  "sensitive_files_exposed": [{"path": ".env", "size": 1024}]
}
```
