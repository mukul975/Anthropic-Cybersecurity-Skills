# API Reference: Implementing NERC CIP Compliance Controls

## NERC CIP Standards Summary

| Standard | Title | Focus |
|----------|-------|-------|
| CIP-002 | BES Cyber System Categorization | Asset identification |
| CIP-003 | Security Management Controls | Policies, delegation |
| CIP-004 | Personnel and Training | Background checks, training |
| CIP-005 | Electronic Security Perimeters | Network boundaries, remote access |
| CIP-006 | Physical Security | Physical access controls |
| CIP-007 | Systems Security Management | Ports, patches, malware, logging |
| CIP-008 | Incident Reporting | Incident response plan |
| CIP-009 | Recovery Plans | Backup, recovery testing |
| CIP-010 | Configuration and Vulnerability | Baselines, vulnerability assessment |
| CIP-011 | Information Protection | BES Cyber System Information |
| CIP-013 | Supply Chain Risk Management | Vendor risk assessment |

## CIP-005 ESP Requirements

| Requirement | Description |
|-------------|-------------|
| R1 | Define and document ESP boundaries |
| R1.3 | Deny-by-default firewall rules |
| R2 | MFA for interactive remote access |
| R2.3 | Encrypt remote sessions |

## CIP-007 Patching Timeline

| Impact Level | Patch Cycle |
|-------------|-------------|
| High | 35 days from availability |
| Medium | 35 days from availability |
| Low | Documented mitigation plan |

### References

- NERC CIP Standards: https://www.nerc.com/pa/Stand/Pages/CIPStandards.aspx
- NERC CIP v5/v7: https://www.nerc.com/pa/CI/tpv5impmntnstdy/Pages/default.aspx
