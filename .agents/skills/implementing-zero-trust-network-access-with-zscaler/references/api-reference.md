# API Reference: Zscaler Private Access (ZPA)

## ZPA Management API

### Authentication
```
POST https://config.private.zscaler.com/signin
Body: client_id=X&client_secret=Y
Returns: {"access_token": "...", "token_type": "Bearer"}
```

### Application Segments
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/mgmtconfig/v1/admin/customers/{id}/application` | List app segments |
| POST | `/mgmtconfig/v1/admin/customers/{id}/application` | Create app segment |

### Server Groups
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/mgmtconfig/v1/admin/customers/{id}/serverGroup` | List server groups |

### Access Policies
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/mgmtconfig/v1/admin/customers/{id}/policySet/rules` | List policy rules |

### Connectors
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/mgmtconfig/v1/admin/customers/{id}/connector` | List connectors |

### App Segment Fields
| Field | Description |
|-------|-------------|
| `name` | Application segment name |
| `enabled` | Whether segment is active |
| `bypassType` | `NEVER`, `ALWAYS`, or `ON_NET` |
| `domainNames` | FQDN list for the segment |
| `tcpPortRanges` | Allowed TCP port ranges |

### Bypass Types
| Value | Security Implication |
|-------|---------------------|
| `NEVER` | Always enforce ZPA (recommended) |
| `ALWAYS` | Bypass ZPA entirely (high risk) |
| `ON_NET` | Bypass when on corporate network |

## References
- ZPA API: https://help.zscaler.com/zpa/about-zpa-api
- ZPA Admin Guide: https://help.zscaler.com/zpa
