# Palo Alto Prisma Access Zero Trust — API Reference

## Authentication

| Parameter | Value |
|-----------|-------|
| Token URL | `https://auth.apps.paloaltonetworks.com/oauth2/access_token` |
| Grant Type | `client_credentials` |
| Scope | `tsg_id:<tenant_service_group_id>` |

## SASE Configuration API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/sse/config/v1/remote-networks` | List remote network connections |
| GET | `/sse/config/v1/service-connections` | List service connections |
| GET | `/sse/config/v1/ike-gateways` | List IKE gateway configurations |
| GET | `/sse/config/v1/security-rules` | List security policy rules |
| GET | `/sse/config/v1/hip-profiles` | List Host Information Profiles |
| GET | `/sse/config/v1/mobile-agent/global-settings` | GlobalProtect mobile user config |
| POST | `/sse/config/v1/security-rules` | Create security rule |
| PUT | `/sse/config/v1/security-rules/{id}` | Update security rule |

## Base URL

```
https://api.sase.paloaltonetworks.com
```

## Security Rule Actions

| Action | Description |
|--------|-------------|
| `allow` | Permit traffic matching rule |
| `deny` | Block traffic matching rule |
| `drop` | Silently drop traffic |
| `reset-client` | Send TCP RST to client |

## HIP Match Criteria

| Field | Description |
|-------|-------------|
| `disk-encryption` | Require disk encryption enabled |
| `firewall` | Require host firewall active |
| `patch-management` | Require OS patches current |
| `anti-malware` | Require AV/EDR running |

## External References

- [Prisma Access SASE API](https://pan.dev/sase/api/)
- [Prisma Access Configuration Guide](https://docs.paloaltonetworks.com/prisma-access)
- [SASE Authentication](https://pan.dev/sase/docs/getstarted/)
