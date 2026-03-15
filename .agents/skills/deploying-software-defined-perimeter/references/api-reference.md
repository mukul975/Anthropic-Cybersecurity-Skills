# Software-Defined Perimeter — API Reference

## Core SDP Concepts

| Component | Description |
|-----------|-------------|
| SDP Controller | Central policy engine managing authentication and authorization |
| SDP Gateway | Enforces access policies, terminates encrypted tunnels |
| SDP Client | End-user agent performing Single Packet Authorization (SPA) |
| SPA (Single Packet Authorization) | Cryptographic knock before TCP connection allowed |

## Appgate SDP Admin API

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/admin/login` | Authenticate and get Bearer token |
| GET | `/admin/sites` | List configured sites |
| GET | `/admin/policies` | List access policies |
| GET | `/admin/entitlements` | List entitlements (resource access rules) |
| GET | `/admin/appliances` | List SDP gateways and controllers |
| GET | `/admin/identity-providers` | List identity providers |
| POST | `/admin/entitlements` | Create new entitlement |

## Dark Port Scanning

```python
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5)
result = sock.connect_ex((host, port))  # Non-zero = port dark (SDP enforced)
```

## Mutual TLS Verification

```python
import ssl
ctx = ssl.create_default_context()
ctx.load_cert_chain("client.crt", "client.key")
with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
    s.connect((host, 443))
```

## SPA Packet Structure

| Field | Description |
|-------|-------------|
| Random Data | 16 bytes of random padding |
| Username | SDP client identity |
| Timestamp | Prevents replay attacks |
| HMAC | SHA-256 authentication code |

## External References

- [Appgate SDP API Docs](https://sdphelp.appgate.com/adminguide/rest-api-guide.html)
- [CSA SDP Specification](https://cloudsecurityalliance.org/research/sdp/)
- [fwknop SPA Tool](https://www.cipherdyne.org/fwknop/)
