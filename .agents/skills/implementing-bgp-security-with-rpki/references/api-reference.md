# API Reference: BGP RPKI Validation Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP client for RIPEstat and Cloudflare RPKI APIs |

## CLI Usage

```bash
python scripts/agent.py \
  --asn AS13335 \
  --prefixes 1.1.1.0/24 104.16.0.0/12 \
  --output-dir /reports/ \
  --output rpki_report.json
```

## Functions

### `validate_prefix_rpki(prefix) -> dict`
Queries RIPEstat `/rpki-validation/data.json` for RPKI status (valid/invalid/unknown).

### `get_roas_for_asn(asn) -> list`
Queries Cloudflare RPKI `/api/v1/roas` for Route Origin Authorizations.

### `get_prefix_overview(prefix) -> dict`
Queries RIPEstat `/prefix-overview/data.json` for routing overview.

### `check_rpki_adoption(asn) -> dict`
Compares announced prefixes against ROA coverage to calculate adoption percentage.

### `validate_multiple_prefixes(prefixes) -> list`
Batch validates prefixes against RPKI.

### `generate_report(asn, prefixes) -> dict`
Full report with adoption metrics, per-prefix validation, and recommendations.

## APIs Used

| API | Endpoint |
|-----|----------|
| RIPEstat | `stat.ripe.net/data/rpki-validation/data.json` |
| RIPEstat | `stat.ripe.net/data/announced-prefixes/data.json` |
| Cloudflare RPKI | `rpki.cloudflare.com/api/v1/roas` |

## Output Schema

```json
{
  "asn": "AS13335",
  "adoption": {"announced_prefixes": 500, "roa_covered": 498, "coverage_pct": 99.6},
  "prefix_validation": [{"prefix": "1.1.1.0/24", "status": "valid"}],
  "recommendations": ["Create ROAs for 2 uncovered prefixes"]
}
```
