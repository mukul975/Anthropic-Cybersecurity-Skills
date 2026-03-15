# API Reference — Performing Paste Site Monitoring for Credentials

## Libraries Used
- **requests**: HIBP API v3 for breach and paste lookup
- **re**: Credential pattern matching (email:pass, API keys, AWS keys, JWTs)
- **time**: Rate limiting for HIBP API (1.6s between requests)

## CLI Interface
```
python agent.py [--api-key <hibp_key>] check --email user@example.com
python agent.py [--api-key <hibp_key>] pastes --email user@example.com
python agent.py [--api-key <hibp_key>] bulk --domain example.com --emails employee_list.txt
python agent.py scan --file paste_dump.txt
python agent.py [--api-key <hibp_key>] report --domain example.com --emails employees.txt
```

## Core Functions

### `check_haveibeenpwned(email, api_key)` — Breach database lookup
**Endpoint:** `GET /api/v3/breachedaccount/{email}`

### `check_paste_dumps(email, api_key)` — Paste site exposure check
**Endpoint:** `GET /api/v3/pasteaccount/{email}`

### `bulk_check_domain(domain, email_list_file, api_key)` — Organization-wide scan
Rate-limited to 1.6s between requests. Max 50 emails per run.

### `scan_text_for_credentials(text_file)` — Pattern-based credential detection
Patterns: email:password, username:password, API keys, AWS keys (AKIA*), private keys, JWTs.

### `generate_exposure_report(...)` — Executive exposure summary

## Rate Limiting
HIBP free tier: ~1 request/1.6 seconds. Agent auto-sleeps between requests.

## Dependencies
```
pip install requests
```
