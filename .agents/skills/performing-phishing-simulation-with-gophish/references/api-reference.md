# API Reference — Performing Phishing Simulation with GoPhish

## Libraries Used
- **requests**: HTTP client for GoPhish REST API

## CLI Interface
```
python agent.py --url https://gophish.local:3333 --api-key <key> campaigns
python agent.py --url <url> --api-key <key> metrics --id 1
python agent.py --url <url> --api-key <key> resources
python agent.py --url <url> --api-key <key> report --id 1
python agent.py --url <url> --api-key <key> launch --name "Q1 Test" --template-id 1 --page-id 1 --smtp-id 1 --group-ids 1 2 --phish-url https://phish.local
```

## GoPhishClient API Endpoints

### `GET /api/campaigns/` — List all campaigns
### `GET /api/campaigns/{id}` — Campaign details with results
### `POST /api/campaigns/` — Create and launch campaign
### `GET /api/groups/` — List target groups
### `GET /api/templates/` — List email templates
### `GET /api/smtp/` — List sending profiles

## Core Functions

### `get_campaign_metrics(...)` — Campaign performance analysis
Tracks: sent, opened, clicked, submitted, reported. Calculates percentage rates.

### `generate_report(...)` — Risk assessment with recommendations
Risk levels: CRITICAL (>10% credential submission), HIGH (>20% click rate), MEDIUM.

### `list_resources(...)` — Enumerate available GoPhish configurations

## Campaign Status Tracking
| Status | Description |
|--------|-------------|
| Email Sent | Email delivered to target |
| Email Opened | Tracking pixel loaded |
| Clicked Link | Target clicked phishing URL |
| Submitted Data | Target entered credentials |
| Reported | Target reported phishing email |

## Dependencies
```
pip install requests
```
