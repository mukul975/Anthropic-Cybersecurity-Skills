# Tailscale Zero Trust VPN — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| requests | `pip install requests` | Tailscale API v2 client |

## Tailscale API v2 Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v2/tailnet/{tailnet}/devices` | List all devices in tailnet |
| GET | `/api/v2/tailnet/{tailnet}/acl` | Get ACL policy |
| PUT | `/api/v2/tailnet/{tailnet}/acl` | Update ACL policy |
| GET | `/api/v2/tailnet/{tailnet}/dns/nameservers` | Get DNS nameservers |
| GET | `/api/v2/tailnet/{tailnet}/keys` | List auth keys |
| GET | `/api/v2/device/{deviceid}` | Get device details |
| DELETE | `/api/v2/device/{deviceid}` | Remove device from tailnet |
| GET | `/api/v2/tailnet/{tailnet}/webhooks` | List webhooks |

## Base URL & Authentication

```
Base: https://api.tailscale.com
Header: Authorization: Bearer <api-key>
```

## ACL Policy Structure

| Field | Description |
|-------|-------------|
| `acls` | Access control rules (src, dst, action) |
| `groups` | Named groups of users |
| `tagOwners` | Tag-based device ownership |
| `ssh` | Tailscale SSH access rules |
| `autoApprovers` | Auto-approve routes and exit nodes |
| `tests` | ACL policy unit tests |

## Device Fields

| Field | Description |
|-------|-------------|
| `hostname` | Device hostname |
| `os` | Operating system |
| `clientVersion` | Tailscale client version |
| `keyExpiryDisabled` | Whether key expiry is disabled |
| `online` | Current online status |
| `lastSeen` | Last seen timestamp |
| `addresses` | Tailscale IP addresses |

## External References

- [Tailscale API Docs](https://tailscale.com/api)
- [Tailscale ACL Policy](https://tailscale.com/kb/1018/acls)
- [Tailscale SSH](https://tailscale.com/kb/1193/tailscale-ssh)
