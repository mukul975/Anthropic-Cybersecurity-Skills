# API Reference: Securing Container Registry with Harbor

## Harbor REST API v2.0

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v2.0/projects` | List all projects |
| PUT | `/api/v2.0/projects/{name}` | Update project settings |
| GET | `/api/v2.0/configurations` | Get system config |
| PUT | `/api/v2.0/configurations` | Update system config |
| GET | `/api/v2.0/projects/{name}/members` | List project members |
| POST | `/api/v2.0/projects/{name}/members` | Add member |
| GET | `/api/v2.0/projects/{name}/immutabletagrules` | List tag rules |
| GET | `/api/v2.0/audit-logs` | Get audit logs |
| GET | `/api/v2.0/projects/{name}/repositories/{repo}/artifacts/{ref}/additions/vulnerabilities` | Get scan results |

## Harbor Roles

| Role ID | Name | Permissions |
|---------|------|------------|
| 1 | ProjectAdmin | Full project control |
| 2 | Maintainer | Push/pull/scan/sign |
| 3 | Developer | Push and pull images |
| 4 | Guest | Pull images only |
| 5 | LimitedGuest | Pull specific repos |

## Security Metadata Fields

| Field | Values | Description |
|-------|--------|-------------|
| `auto_scan` | true/false | Scan images on push |
| `prevent_vul` | true/false | Block vulnerable images |
| `severity` | critical/high/medium | Block threshold |
| `enable_content_trust` | true/false | Notary signing |
| `enable_content_trust_cosign` | true/false | Cosign verification |
| `public` | true/false | Public project access |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | Harbor REST API calls |
| `json` | stdlib | Parse API responses |

## References

- Harbor Documentation: https://goharbor.io/docs/
- Harbor API Spec: https://editor.swagger.io/?url=https://raw.githubusercontent.com/goharbor/harbor/main/api/v2.0/swagger.yaml
- Harbor GitHub: https://github.com/goharbor/harbor
