# API Reference: Securing Remote Access to OT Environment

## Session States

| State | Description |
|-------|-------------|
| pending_approval | Awaiting manager approval (vendor sessions) |
| approved | Approved, awaiting MFA |
| active | MFA verified, session in progress |
| terminated | Ended by user, admin, or policy |
| expired | Max duration exceeded |
| denied | Access denied by policy |

## User Roles and Policies

| Role | Approval | Co-Attendance | MFA | Max Duration |
|------|----------|--------------|-----|--------------|
| OT Operator | No | No | Yes | 8 hours |
| OT Engineer | No | No | Yes | 4 hours |
| Vendor | Yes | Yes | Yes | 2 hours |
| Security Analyst | No | No | Yes | 4 hours |

## CIP-005-7 R2 Requirements

| Requirement | Control |
|-------------|---------|
| R2.1 | Intermediate system (jump server) in DMZ |
| R2.2 | Encryption for all remote sessions |
| R2.3 | Multi-factor authentication |
| R2.4 | Session recording and logging |
| R2.5 | Disable remote access when not needed |

## PAM Solutions

| Tool | Capability |
|------|-----------|
| CyberArk PAS | Credential vaulting, session recording |
| BeyondTrust PRA | OT remote access, session control |
| Claroty SRA | OT-specific protocol-aware access |
| Wallix Bastion | Jump server, session recording |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `hashlib` | stdlib | Session ID generation |
| `json` | stdlib | Report output |
| `datetime` | stdlib | Session timing/expiration |

## References

- NERC CIP-005-7: https://www.nerc.com/pa/Stand/Reliability%20Standards/CIP-005-7.pdf
- IEC 62443-3-3: System Security Requirements
- CISA OT Remote Access: https://www.cisa.gov/news-events/alerts/
