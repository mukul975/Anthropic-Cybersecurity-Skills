# API Reference: Web Cache Poisoning Attack Agent

## Overview

Tests web applications for cache poisoning vulnerabilities by identifying CDN infrastructure, testing unkeyed headers for reflection and caching, and checking for cache deception paths.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| requests | >= 2.28 | HTTP requests with custom headers |

## Core Functions

### `identify_cache_layer(target_url)`
Detects caching infrastructure (Cloudflare, Varnish, Akamai, Fastly, CloudFront) from response headers.
- **Returns**: `dict` with `cdn_detected`, cache headers

### `test_cache_hit_miss(target_url)`
Sends 3 sequential requests with cache buster to observe HIT/MISS progression.
- **Returns**: `dict` with per-request cache status

### `test_unkeyed_headers(target_url)`
Tests 10 common unkeyed headers (X-Forwarded-Host, X-Original-URL, etc.) for reflection and cache poisoning.
- **Process**: Send header -> check reflection -> re-request without header -> verify cached poison
- **Returns**: `list[dict]` with `reflected`, `cached_poison`, `risk`

### `test_cache_key_normalization(target_url)`
Tests cache key handling for extra parameters, fragments, and trailing slashes.
- **Returns**: `list[dict]` - variation test results

### `test_cache_deception(target_url)`
Tests web cache deception by requesting authenticated pages with static file extensions (.css, .js, .png).
- **Returns**: `list[dict]` - cached sensitive endpoints

### `run_assessment(target_url)`
Full assessment pipeline with summary statistics.

## Unkeyed Headers Tested

| Header | Attack Vector |
|--------|--------------|
| X-Forwarded-Host | Host override for poisoning links/redirects |
| X-Forwarded-Scheme | HTTPS downgrade to HTTP |
| X-Original-URL | Path override (Nginx/IIS) |
| X-Rewrite-URL | Path override |
| X-Host | Alternative host injection |
| X-Forwarded-Port | Port injection |

## Risk Levels

| Level | Criteria |
|-------|----------|
| CRITICAL | Header reflected AND cached (full cache poison) |
| HIGH | Header reflected but not confirmed cached |

## Usage

```bash
python agent.py https://target.example.com
```
