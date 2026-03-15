# API Reference: Saviynt Access Recertification

## Saviynt EIC REST API v5

### Authentication
```python
POST /ECM/api/login
Body: {"username": "admin", "password": "pass"}
Returns: {"access_token": "...", "token_type": "Bearer"}
```

### Certification Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/ECM/api/v5/listCertification` | List campaigns |
| POST | `/ECM/api/v5/getCertificationDetails` | Campaign statistics |
| POST | `/ECM/api/v5/getCertificationItems` | Get review items |
| POST | `/ECM/api/v5/certifyItems` | Certify/revoke items |

### listCertification Payload
| Field | Description |
|-------|-------------|
| `certificationstatus` | `active`, `completed`, `expired` |
| `max` | Maximum results per page |
| `offset` | Pagination offset |

### Certification Item Fields
| Field | Description |
|-------|-------------|
| `username` | Identity under review |
| `entitlement_value` | Access being reviewed |
| `risk_score` | Computed risk (0-10) |
| `last_used_date` | Last access usage date |
| `peer_group_match` | Whether peers have same access |

### certifyItems Actions
| Action | Description |
|--------|-------------|
| `certify` | Approve continued access |
| `revoke` | Remove access |
| `consult` | Request additional reviewer input |

### Campaign Types
| Type | Trigger |
|------|---------|
| User Manager | Manager reviews direct reports |
| Application Owner | App owner reviews all users |
| Entitlement Owner | Entitlement owner reviews holders |
| Event-Based | Triggered by role/department change |

## References
- Saviynt REST API: https://docs.saviyntcloud.com/
- Saviynt Certification: https://docs.saviyntcloud.com/bundle/EIC-Admin-v24x/
