# Standards and Frameworks Reference

## CSA Software-Defined Perimeter Specification v2.0

### Core Architecture
- **SDP Controller**: Central policy and authentication authority
- **Initiating Host (IH)**: Client device requesting access
- **Accepting Host (AH)**: Gateway protecting backend resources
- **Single Packet Authorization (SPA)**: Pre-authentication mechanism making services invisible

### SDP Workflow
1. IH authenticates to SDP Controller
2. Controller validates identity, device posture, and policy
3. Controller instructs AH to accept connection from specific IH
4. IH sends SPA packet to AH
5. AH validates SPA and opens temporary port
6. mTLS tunnel established between IH and AH
7. Application traffic flows through encrypted tunnel

### Deployment Models
| Model | Use Case | Architecture |
|---|---|---|
| Client-to-Gateway | Remote user access | IH → AH Gateway → Backend servers |
| Client-to-Server | Direct application access | IH → AH (application server) |
| Server-to-Server | Workload communication | IH (server) → AH (server) |
| Gateway-to-Gateway | Site-to-site connectivity | AH₁ → Controller → AH₂ |

## NIST SP 800-207: SDP as Zero Trust Deployment

### SDP Mapping to NIST ZTA Components
| NIST Component | SDP Equivalent |
|---|---|
| Policy Engine (PE) | SDP Controller policy evaluation |
| Policy Administrator (PA) | SDP Controller session management |
| Policy Enforcement Point (PEP) | SDP Gateway (Accepting Host) |

### NIST ZTA Tenets Addressed by SDP
- All communication secured regardless of network location (mTLS tunnels)
- Per-session access grants (dynamic SDP connections)
- Dynamic policy evaluation (controller real-time decisions)
- Asset integrity monitoring (device posture checks)

## CISA Zero Trust Maturity Model v2.0

### Network Pillar - SDP Alignment
| Maturity | SDP Capability |
|---|---|
| Traditional | No SDP, perimeter-based VPN |
| Initial | SDP for remote access, basic SPA |
| Advanced | Full SDP with device posture, context-aware |
| Optimal | Dynamic SDP with continuous verification, ML-driven |

## Single Packet Authorization (SPA) Technical Details

### SPA Packet Structure
- Encrypted with shared key or asymmetric cryptography
- Contains: source IP, timestamp, HMAC, requested service
- Single UDP packet (no TCP handshake visible)
- Anti-replay protection via timestamp and sequence number

### fwknop Implementation
- Open-source SPA implementation
- Supports AES-256 and GnuPG encryption
- Integrates with iptables/nftables for firewall rule insertion
- Temporary rule created for authenticated session only

## mTLS Configuration Standards

### Certificate Requirements
- Minimum RSA 2048-bit or ECDSA P-256 keys
- Short-lived certificates (24-72 hours) preferred
- OCSP stapling for real-time revocation checking
- Certificate pinning for additional security
