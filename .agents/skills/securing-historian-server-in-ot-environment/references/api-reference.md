# API Reference: Securing Historian Server in OT Environment

## Common Historian Ports

| Port | Service | Risk if Exposed |
|------|---------|----------------|
| 5450 | PI Data Archive | SDK/API data access |
| 5457 | PI AF Server | Asset Framework access |
| 443 | HTTPS | Web API (acceptable if TLS) |
| 80 | HTTP | Cleartext credentials/data |
| 1433 | MS SQL | Direct database queries |
| 3389 | RDP | Remote admin access |
| 135/445 | RPC/SMB | Lateral movement target |
| 502 | Modbus | Industrial protocol |

## Purdue Model Placement

| Level | Systems | Historian Role |
|-------|---------|---------------|
| 0-1 | Field devices, PLCs | Data source |
| 2 | HMI, SCADA | Data source |
| 3 | Site Operations | OT Historian location |
| 3.5 | DMZ | Replica historian |
| 4-5 | Enterprise | Consumer of DMZ data |

## Authentication Methods

| Method | Security Level | Recommendation |
|--------|---------------|----------------|
| PI Trust (IP-based) | Insecure | Migrate immediately |
| piadmin default | Insecure | Disable account |
| Windows Integrated | Recommended | Use AD groups/PI Mappings |
| Certificate-based | Strong | For inter-server comms |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `socket` | stdlib | Port scanning |
| `json` | stdlib | Report generation |
| `pathlib` | stdlib | File handling |

## References

- OSIsoft PI Security Guide: https://docs.aveva.com/
- IEC 62443: Industrial Automation Security
- NIST SP 800-82: Guide to ICS Security
