# API Reference: CyberArk Zero Standing Privilege

## CyberArk PVWA REST API v2

### Authentication
```python
POST /api/auth/CyberArk/Logon
Body: {"username": "admin", "password": "pass"}
Returns: Session token string
```

### Key Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/Safes` | List all safes |
| GET | `/api/Safes/{name}/Members` | List safe members and permissions |
| GET | `/api/Platforms` | List configured platforms |
| GET | `/api/Accounts` | List privileged accounts |
| GET | `/api/LiveSessions` | List active privileged sessions |
| POST | `/api/Accounts/{id}/CheckIn` | Release exclusive account access |

### Safe Member Permissions
| Permission | ZSP Implication |
|------------|----------------|
| `useAccounts` | Can initiate privileged sessions |
| `retrieveAccounts` | Can retrieve passwords |
| `listAccounts` | Can see account inventory |
| `requestsAuthorizationLevel1` | Dual-control approval required |

### Session Properties
| Field | Description |
|-------|-------------|
| `User` | Session initiator |
| `AccountName` | Target privileged account |
| `Duration` | Session length in seconds |
| `RemoteMachine` | Target host |

## TEA Framework
| Component | API Field | Purpose |
|-----------|-----------|---------|
| Time | `MaxSessionDuration` | Auto-revoke after timeout |
| Entitlements | `AllowedPermissions` | Scoped access per session |
| Approvals | `requestsAuthorizationLevel` | Require approval workflow |

## References
- CyberArk REST API: https://docs.cyberark.com/pam-self-hosted/latest/en/Content/SDK/CyberArk%20REST%20API.htm
- CyberArk Secure Cloud Access: https://docs.cyberark.com/secure-cloud-access/
