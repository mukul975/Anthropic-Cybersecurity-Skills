# API Reference — Implementing EPSS Score for Vulnerability Prioritization

## Libraries Used
- **requests**: HTTP client for FIRST.org EPSS API
- **csv**: Parse and enrich vulnerability scan CSV files

## CLI Interface

```
python agent.py score --cves CVE-2024-1234 CVE-2024-5678
python agent.py enrich --scan-file scan.csv [--output enriched.csv]
```

## Core Functions

### `get_epss_scores(cve_list)`
Fetches EPSS scores from the FIRST.org API (batches of 100).

**API Endpoint:** `GET https://api.first.org/data/v1/epss?cve=CVE-1,CVE-2`

**Returns:** dict with `scores` list, each containing `cve`, `epss` (0.0-1.0), `percentile` (0.0-1.0).

### `prioritize_vulnerabilities(cve_scores, epss_threshold=0.1, percentile_threshold=0.9)`
Classifies CVEs into priority buckets based on EPSS probability.

**Priority Buckets:**
| Priority | Criteria |
|----------|---------|
| CRITICAL | EPSS >= 0.1 or percentile >= 90th |
| HIGH | EPSS >= 0.05 |
| MEDIUM | EPSS >= 0.01 |
| LOW | EPSS < 0.01 |

### `enrich_from_scan(scan_file, output_file=None)`
Reads a CSV vulnerability scan, fetches EPSS for all CVEs, and writes enriched output.

**Auto-detects columns:** CVE, cve, CVE-ID, cve_id, vulnerability_id.

## FIRST.org EPSS API

| Parameter | Description |
|-----------|-------------|
| `cve` | Comma-separated CVE IDs (max 100 per request) |
| `envelope` | Wrap response in metadata envelope |
| `date` | Get scores for a specific date (YYYY-MM-DD) |

**Response Fields:**
- `epss`: Probability of exploitation in next 30 days (0.0–1.0)
- `percentile`: Percentile rank relative to all scored CVEs

## Dependencies
```
pip install requests>=2.31
```
