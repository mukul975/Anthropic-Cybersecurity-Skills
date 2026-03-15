# API Reference: XM Cyber Attack Path Analysis Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP client for XM Cyber REST API |

## CLI Usage

```bash
python scripts/agent.py \
  --url https://xmcyber.example.com \
  --api-key YOUR_API_KEY \
  --output-dir /reports/ \
  --output attack_path_report.json
```

## Functions

### `XMCyberClient(base_url, api_key)`
Client class with Bearer token auth for the XM Cyber API.

### `get_scenarios() -> list`
GET `/api/v1/scenarios` - Lists all attack simulation scenarios.

### `get_attack_paths(scenario_id) -> list`
GET `/api/v1/scenarios/{id}/attack-paths` - Returns attack paths for a scenario.

### `get_choke_points(scenario_id) -> list`
GET `/api/v1/scenarios/{id}/choke-points` - Returns points where attack paths converge.

### `get_critical_assets() -> list`
GET `/api/v1/critical-assets` - Lists defined critical business assets.

### `get_entities_at_risk(scenario_id) -> list`
GET `/api/v1/scenarios/{id}/entities-at-risk` - Entities reachable via attack paths.

### `get_remediation_actions(scenario_id) -> list`
GET `/api/v1/scenarios/{id}/remediations` - Prioritized fix recommendations.

### `analyze_choke_points(choke_points) -> dict`
Ranks choke points by paths_through count, returns top 10.

### `compute_risk_score(attack_paths, critical_assets) -> dict`
Calculates critical asset exposure percentage from reachable targets.

## Output Schema

```json
{
  "scenarios": [{
    "name": "Full Environment",
    "attack_paths": 1234,
    "choke_point_analysis": {"total_choke_points": 45, "top_choke_points": []},
    "risk_score": {"critical_asset_exposure_pct": 67.5}
  }]
}
```
