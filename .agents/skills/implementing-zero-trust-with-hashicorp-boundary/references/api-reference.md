# API Reference: HashiCorp Boundary

## Boundary CLI (JSON output)

### Core Commands
```bash
boundary scopes list -scope-id=global -format=json
boundary targets list -scope-id=<id> -format=json
boundary host-catalogs list -scope-id=<id> -format=json
boundary credential-stores list -scope-id=<id> -format=json
boundary sessions list -scope-id=<id> -format=json
boundary auth-methods list -scope-id=global -format=json
```

### Environment Variables
| Variable | Description |
|----------|-------------|
| `BOUNDARY_ADDR` | Controller address (e.g., `http://127.0.0.1:9200`) |
| `BOUNDARY_TOKEN` | Authentication token |

### Target Fields
| Field | Description |
|-------|-------------|
| `name` | Target display name |
| `type` | `tcp` or `ssh` |
| `session_max_seconds` | Maximum session duration |
| `session_connection_limit` | Max concurrent connections (-1 = unlimited) |

### Credential Store Types
| Type | Description |
|------|-------------|
| `vault` | Vault-brokered dynamic credentials (recommended) |
| `static` | Static credentials stored in Boundary |

### Auth Method Types
| Type | Zero Trust Suitability |
|------|----------------------|
| `oidc` | Recommended (SSO, MFA support) |
| `ldap` | Acceptable with MFA |
| `password` | Not recommended for zero trust |

### Session Recording
```bash
boundary targets update tcp -id=<id> -enable-session-recording=true \
  -storage-bucket-id=<bucket-id>
```

## References
- Boundary docs: https://developer.hashicorp.com/boundary/docs
- Boundary CLI: https://developer.hashicorp.com/boundary/docs/commands
- Boundary API: https://developer.hashicorp.com/boundary/api-docs
