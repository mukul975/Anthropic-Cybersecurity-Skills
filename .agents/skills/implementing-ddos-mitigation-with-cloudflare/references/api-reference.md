# API Reference: Cloudflare DDoS Mitigation Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP client for Cloudflare API v4 |

## CLI Usage

```bash
python scripts/agent.py \
  --api-token CF_API_TOKEN \
  --output-dir /reports/
```

## Functions

### `CloudflareClient(api_token)`
Authenticated client using Bearer token for Cloudflare API v4.

### `list_zones() -> list`
GET `/zones` - List all managed zones.

### `get_zone_analytics(zone_id, since) -> dict`
GET `/zones/{id}/analytics/dashboard` - Traffic analytics for time period.

### `get_firewall_events(zone_id, limit) -> list`
GET `/zones/{id}/security/events` - Recent firewall/WAF events.

### `get_ddos_settings(zone_id) -> dict`
GET `/zones/{id}/firewall/ddos_protection` - DDoS protection configuration.

### `create_rate_limit_rule(zone_id, url_pattern, threshold, period) -> dict`
POST `/zones/{id}/rate_limits` - Create rate limiting rule.

### `set_security_level(zone_id, level) -> dict`
PATCH `/zones/{id}/settings/security_level` - Set security level (low/medium/high/under_attack).

## Cloudflare API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/zones` | GET | Zone listing |
| `/zones/{id}/analytics/dashboard` | GET | Traffic data |
| `/zones/{id}/security/events` | GET | Security events |
| `/zones/{id}/rate_limits` | POST | Rate limiting |

## Output Schema

```json
{
  "summary": {"zones_assessed": 3, "total_threats": 15420},
  "zones": [{"name": "example.com", "traffic": {"threats_blocked": 5140}}]
}
```
