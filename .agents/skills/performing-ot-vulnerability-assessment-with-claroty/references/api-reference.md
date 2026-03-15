# API Reference — Performing OT Vulnerability Assessment with Claroty

## Libraries Used
- **requests**: HTTP client for Claroty xDome REST API

## CLI Interface
```
python agent.py --url <claroty_url> --token <api_token> vulns [--severity critical] [--limit 100]
python agent.py --url <claroty_url> --token <api_token> prioritize
python agent.py --url <claroty_url> --token <api_token> risk
```

## ClarotyVulnClient API

### `get_vulnerabilities(severity, asset_type, limit)`
**Endpoint:** `GET /api/v1/vulnerabilities`

### `get_affected_assets(cve_id)`
**Endpoint:** `GET /api/v1/vulnerabilities/cve/{cve_id}/assets`

### `get_risk_score()`
**Endpoint:** `GET /api/v1/risk/score`

## Core Functions

### `assess_vulnerabilities(...)` — Analyze OT vulnerability landscape
Groups by severity and asset type. Extracts critical vulnerabilities with CVSS scores.

### `prioritize_remediation(...)` — Risk-based prioritization
Risk formula: `CVSS * asset_criticality * exploitability / 10`
Priority: CRITICAL (>=4), HIGH (>=2.5), MEDIUM (>=1.5), LOW (<1.5).

### `get_risk_overview(...)` — Overall OT risk posture

## Dependencies
```
pip install requests
```
