# API Reference: BGP Hijacking Assessment Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP client for RIPEstat API queries |

## CLI Usage

```bash
# Full ASN assessment
python scripts/agent.py --asn 12345 --output bgp_report.json

# Check a specific prefix
python scripts/agent.py --asn 12345 --prefix 203.0.113.0/24
```

## Functions

### `check_rpki_status(prefix, asn) -> dict`
Queries RIPEstat RPKI validation endpoint. Returns `{status, validating_roas}`.

### `get_announced_prefixes(asn) -> list`
Lists all prefixes currently announced by the given ASN.

### `get_routing_status(prefix) -> dict`
Returns first/last seen timestamps, visibility across RIS peers, and origin ASN list.

### `check_roas(prefix) -> list`
Retrieves Route Origin Authorization records for the prefix.

### `get_bgp_looking_glass(prefix) -> dict`
Queries RIPEstat looking glass for current route advertisements across RRCs.

### `assess_hijack_resilience(asn) -> dict`
Runs full assessment: enumerates prefixes, checks RPKI, detects multi-origin conflicts.

## RIPEstat API Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/rpki-validation/data.json` | RPKI validity for prefix-origin pair |
| `/announced-prefixes/data.json` | Prefixes announced by an ASN |
| `/routing-status/data.json` | Current routing state of a prefix |
| `/looking-glass/data.json` | BGP routes from RIS collectors |

## Output Schema

```json
{
  "asn": 12345,
  "total_prefixes": 5,
  "rpki_valid": 3,
  "rpki_unprotected": 2,
  "multi_origin_conflicts": 0,
  "prefix_details": [{"prefix": "203.0.113.0/24", "rpki_status": "valid"}]
}
```
