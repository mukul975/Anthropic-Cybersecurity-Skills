# API Reference: Azure AD PIM Audit Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP client for Microsoft Graph API |

## CLI Usage

```bash
python scripts/agent.py \
  --tenant-id YOUR_TENANT_ID \
  --client-id YOUR_CLIENT_ID \
  --client-secret YOUR_SECRET \
  --output-dir /reports/ \
  --output pim_report.json
```

## Functions

### `PIMClient(tenant_id, client_id, client_secret)`
Authenticates via OAuth2 client credentials flow to Microsoft Graph API.

### `list_role_definitions() -> list`
GET `/roleManagement/directory/roleDefinitions` - Available directory roles.

### `list_eligible_assignments() -> list`
GET `/roleManagement/directory/roleEligibilityScheduleInstances` - PIM eligible roles.

### `list_active_assignments() -> list`
GET `/roleManagement/directory/roleAssignmentScheduleInstances` - Active assignments.

### `list_role_settings() -> list`
GET `/policies/roleManagementPolicyAssignments` - PIM policy configurations.

### `audit_permanent_assignments(active, eligible) -> list`
Identifies permanent role assignments not managed via PIM eligible workflow.

### `compute_pim_coverage(active, eligible) -> dict`
Calculates percentage of assignments managed through PIM.

## Microsoft Graph Endpoints

| Endpoint | Purpose |
|----------|---------|
| `POST /oauth2/v2.0/token` | Client credentials auth |
| `GET /roleManagement/directory/roleDefinitions` | Role catalog |
| `GET /roleManagement/directory/roleEligibilityScheduleInstances` | Eligible assignments |
| `GET /roleManagement/directory/roleAssignmentScheduleInstances` | Active assignments |

## Output Schema

```json
{
  "coverage": {"active_assignments": 15, "eligible_assignments": 42, "pim_coverage_pct": 73.7},
  "permanent_assignments": [{"role": "Global Administrator", "recommendation": "Convert to eligible"}],
  "recommendations": ["Convert 5 permanent assignments to PIM-eligible"]
}
```
