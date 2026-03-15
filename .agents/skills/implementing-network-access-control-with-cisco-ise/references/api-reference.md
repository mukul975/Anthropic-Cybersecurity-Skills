# API Reference: Implementing Network Access Control with Cisco ISE

## Cisco ISE ERS API

```python
import requests
resp = requests.get("https://ISE:9060/ers/config/authorizationprofile",
                    auth=("admin", "password"),
                    headers={"Accept": "application/json"}, verify=False)
```

## Key ERS Endpoints

| Endpoint | Description |
|----------|-------------|
| `/ers/config/authorizationprofile` | Authorization profiles |
| `/ers/config/networkdevice` | Network devices |
| `/ers/config/endpointgroup` | Endpoint groups |
| `/ers/config/identitygroup` | Identity groups |
| `/ers/config/internaluser` | Internal users |

## ISE Policy Components

| Component | Description |
|-----------|-------------|
| Authentication Policy | Protocol selection (EAP-TLS, PEAP) |
| Authorization Policy | Access decisions (permit, deny, quarantine) |
| Profiling Policy | Endpoint classification |
| Posture Policy | Compliance checks (AV, patch level) |

## 802.1X Authentication Methods

| Method | Security Level | Use Case |
|--------|---------------|----------|
| EAP-TLS | Highest | Certificate-based corporate |
| PEAP-MSCHAPv2 | High | Username/password |
| MAB | Low | Non-supplicant devices |

## RADIUS Attributes

| Attribute | Description |
|-----------|-------------|
| Calling-Station-Id | Client MAC address |
| NAS-IP-Address | Switch/AP IP |
| Tunnel-Type | VLAN assignment |
| Filter-Id | ACL name |

### References

- Cisco ISE API: https://developer.cisco.com/docs/identity-services-engine/
- ISE Admin Guide: https://www.cisco.com/c/en/us/td/docs/security/ise/
