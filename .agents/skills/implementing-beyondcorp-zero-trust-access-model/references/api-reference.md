# API Reference: BeyondCorp Zero Trust Assessment Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP client for Google Cloud IAP and Access Context Manager APIs |

## CLI Usage

```bash
python scripts/agent.py \
  --project my-gcp-project \
  --output-dir /reports/ \
  --output beyondcorp_report.json
```

## Functions

### `get_gcloud_token() -> str`
Runs `gcloud auth print-access-token` to obtain Bearer token.

### `list_iap_resources(project_id, token) -> list`
GET IAP tunnel destination groups for the project.

### `get_iap_settings(project_id, resource, token) -> dict`
GET IAP settings for a specific compute service resource.

### `list_access_levels(org_id, policy_name, token) -> list`
GET `/accessPolicies/{name}/accessLevels` from Access Context Manager.

### `audit_iap_bindings(project_id, token) -> list`
POST `getIamPolicy` and filters for IAP-related role bindings.

### `assess_zero_trust_posture(project_id, token) -> dict`
Evaluates IAP coverage, binding security, checks for allUsers exposure.

### `generate_report(project_id, token) -> dict`
Computes zero trust score (0-100) based on findings.

## Google Cloud APIs Used

| API | Endpoint |
|-----|----------|
| IAP | `iap.googleapis.com/v1/projects/{id}/iap_tunnel/...` |
| Access Context Manager | `accesscontextmanager.googleapis.com/v1/accessPolicies/...` |
| Resource Manager | `cloudresourcemanager.googleapis.com/v1/projects/{id}:getIamPolicy` |

## Output Schema

```json
{
  "project": "my-project",
  "posture": {"iap_resources": 5, "findings": []},
  "zero_trust_score": 85
}
```
