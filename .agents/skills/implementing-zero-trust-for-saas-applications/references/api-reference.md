# API Reference: Zero Trust for SaaS Applications

## Microsoft Graph API v1.0

### Authentication
```python
POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
Body: grant_type=client_credentials&client_id=X&client_secret=Y&scope=https://graph.microsoft.com/.default
```

### Conditional Access
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/identity/conditionalAccess/policies` | List CA policies |
| GET | `/identity/conditionalAccess/policies/{id}` | Get policy details |

### Enterprise Applications
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/servicePrincipals` | List service principals |
| GET | `/oauth2PermissionGrants` | List OAuth consent grants |
| GET | `/appRoleAssignments` | List app role assignments |

### Identity Protection
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/identityProtection/riskyUsers` | List at-risk users |
| GET | `/identityProtection/riskDetections` | Risk detection events |

### CA Policy Grant Controls
| Control | Description |
|---------|-------------|
| `mfa` | Require multi-factor authentication |
| `compliantDevice` | Require Intune-compliant device |
| `domainJoinedDevice` | Require hybrid Azure AD join |
| `passwordChange` | Force password change |

### Risky OAuth Scopes
| Scope | Risk |
|-------|------|
| `Mail.ReadWrite` | Full mailbox access |
| `Files.ReadWrite.All` | All OneDrive/SharePoint files |
| `Directory.ReadWrite.All` | Full directory modification |

## References
- Graph API: https://learn.microsoft.com/en-us/graph/api/overview
- Conditional Access: https://learn.microsoft.com/en-us/entra/identity/conditional-access/
