# API Reference: Phishing Simulation Campaign Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP client for GoPhish REST API |

## CLI Usage

```bash
# List campaigns
python scripts/agent.py --gophish-url https://gophish.lab:3333 --api-key KEY --action list

# Get campaign results
python scripts/agent.py --gophish-url https://gophish.lab:3333 --api-key KEY \
  --action results --campaign-id 1 --output report.json
```

## GoPhishClient Class

### `__init__(base_url, api_key, verify_ssl=False)`
Initializes the session with Bearer token auth for the GoPhish API.

### `create_sending_profile(name, smtp_from, host, username, password) -> dict`
Creates an SMTP sending profile. GoPhish API: `POST /api/smtp/`.

### `create_email_template(name, subject, html_body, text_body) -> dict`
Creates a phishing email template with credential capture enabled. API: `POST /api/templates/`.

### `create_landing_page(name, html, capture_creds, redirect_url) -> dict`
Creates a credential harvesting page. API: `POST /api/pages/`.

### `import_targets(group_name, targets) -> dict`
Imports a target list as a GoPhish group. Each target: `{email, first_name, last_name, position}`.

### `launch_campaign(name, template_id, page_id, smtp_id, group_ids, url) -> dict`
Launches a phishing campaign. API: `POST /api/campaigns/`.

### `get_campaign_results(campaign_id) -> dict`
Fetches campaign timeline and per-target results. API: `GET /api/campaigns/{id}/results`.

## `compute_metrics(results) -> dict`
Calculates click rate, submission rate, and report rate from campaign timeline events.

## GoPhish API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/campaigns/` | GET/POST | List or create campaigns |
| `/api/campaigns/{id}/results` | GET | Campaign results with timeline |
| `/api/templates/` | POST | Create email templates |
| `/api/pages/` | POST | Create landing pages |
| `/api/smtp/` | POST | Create SMTP profiles |
| `/api/groups/` | POST | Create target groups |
