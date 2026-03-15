# API Reference: Implementing Microsegmentation with Guardicore

## Akamai Guardicore API

```python
import requests
headers = {"Authorization": "Bearer <token>"}
base = "https://guardicore.example.com/api/v3.0"
# Get assets
assets = requests.get(f"{base}/assets", headers=headers).json()
# Get policies
policies = requests.get(f"{base}/policies", headers=headers).json()
# Get traffic map
traffic = requests.get(f"{base}/connections", headers=headers,
                       params={"from_time": "2024-01-01"}).json()
```

## Policy Modes

| Mode | Description |
|------|-------------|
| Reveal | Monitor only, log violations |
| Enforce | Block unauthorized traffic |
| Override | Temporary exception |

## Ringfencing Pattern

| Rule | Source | Destination | Action |
|------|--------|-------------|--------|
| 1 | Frontend | Backend:8443 | Allow |
| 2 | Backend | Database:5432 | Allow |
| 3 | Any | Backend:* | Deny |
| 4 | Backend | Any | Deny |

## Segmentation Metrics

| Metric | Target |
|--------|--------|
| Coverage rate | > 80% of flows |
| Enforced policies | > 90% |
| Cross-zone flows controlled | 100% |
| Default deny coverage | All zones |

## Traffic Analysis Fields

| Field | Description |
|-------|-------------|
| `src_ip` | Source IP address |
| `dst_ip` | Destination IP |
| `dst_port` | Destination port |
| `src_label` | Source workload label |
| `dst_label` | Destination workload label |
| `count` | Flow count |

### References

- Akamai Guardicore: https://www.akamai.com/products/akamai-segmentation
- Zero Trust Microsegmentation: https://www.nist.gov/publications/zero-trust-architecture
- NIST SP 800-207: https://csrc.nist.gov/pubs/sp/800/207/final
