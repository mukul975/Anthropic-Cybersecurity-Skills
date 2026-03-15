# API Reference: Azure AD Conditional Access Audit Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP client for Microsoft Graph API |

## CLI Usage

```bash
python scripts/agent.py \
  --tenant-id TENANT_ID --client-id CLIENT_ID --client-secret SECRET \
  --output-dir /reports/
```

## Functions

### `ConditionalAccessClient(tenant_id, client_id, client_secret)`
Authenticates via OAuth2 client credentials to Microsoft Graph.

### `list_policies() -> list`
GET `/identity/conditionalAccess/policies` - All conditional access policies.

### `list_named_locations() -> list`
GET `/identity/conditionalAccess/namedLocations` - Named locations for geo-fencing.

### `audit_policy(policy) -> dict`
Checks for: MFA requirement, enabled state, app coverage, grant controls.

### `check_baseline_policies(policies) -> list`
Verifies essential baselines: MFA for admins, block legacy auth, require compliant devices.

### `generate_report(client) -> dict`
Full audit with per-policy findings and baseline gap analysis.

## Microsoft Graph Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /identity/conditionalAccess/policies` | List CA policies |
| `GET /identity/conditionalAccess/namedLocations` | Named locations |

## Output Schema

```json
{
  "total_policies": 15, "enabled_policies": 12,
  "summary": {"high_risk": 3, "missing_baselines": 1},
  "baseline_checks": [{"baseline": "Require MFA for admins", "implemented": true}]
}
```
