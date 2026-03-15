# API Reference: SSL Stripping Assessment Agent

## Overview

Automates SSL stripping vulnerability assessment by checking HSTS headers, preload list status, redirect chains, mixed content, and security headers using curl subprocess calls.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| subprocess | stdlib | Runs curl for HTTP header inspection |
| re | stdlib | Regex parsing of HSTS header values |
| json | stdlib | Parses hstspreload.org API responses |

## External Tools Required

| Tool | Purpose |
|------|---------|
| curl | HTTP/HTTPS header and content fetching |

## Core Functions

### `check_hsts_header(target_url)`
Fetches response headers and parses Strict-Transport-Security values.
- **Returns**: `dict` with `hsts_present`, `max_age`, `include_subdomains`, `preload`

### `check_hsts_preload(domain)`
Queries the hstspreload.org API to check browser preload list inclusion.
- **Returns**: `dict` with `status` and `preloaded` boolean

### `check_redirect_chain(url)`
Follows HTTP redirects to verify HTTPS upgrade behavior.
- **Returns**: `dict` with `initial_url`, `final_url`, `upgrades_to_https`

### `check_mixed_content(url)`
Scans page HTML for HTTP resource references on HTTPS pages.
- **Returns**: `dict` with `mixed_content_found` and `http_reference_count`

### `check_security_headers(url)`
Checks for CSP, X-Content-Type-Options, X-Frame-Options, and Upgrade-Insecure-Requests.
- **Returns**: `dict[str, bool]` - header name to presence mapping

### `run_assessment(targets)`
Full assessment pipeline for a list of target domains.
- **Parameters**: `targets` (list[str]) - domain names
- **Returns**: `list[dict]` - per-target assessment results with `ssl_strip_risk`

## Risk Levels

| Level | Criteria |
|-------|----------|
| HIGH | No HSTS header present |
| MEDIUM | HSTS present but not in preload list |
| LOW | HSTS with preload list inclusion |

## Usage

```bash
python agent.py example.com banking.example.com api.example.com
```
