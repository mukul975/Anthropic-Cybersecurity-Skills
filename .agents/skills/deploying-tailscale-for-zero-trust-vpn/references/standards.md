# Standards Reference: Tailscale Zero Trust VPN

## Protocol Standards

### WireGuard Protocol
- **Encryption**: ChaCha20 for symmetric encryption
- **Key Exchange**: Curve25519 for Diffie-Hellman
- **MAC**: Poly1305 for message authentication
- **Hashing**: BLAKE2s for hashing
- **Framework**: Noise Protocol Framework for key negotiation

### NIST SP 800-207: Zero Trust Architecture
- Tailscale implements identity-aware proxying (Section 3.2.2)
- End-to-end encryption satisfies data-in-transit requirements
- ACL-based access control implements least privilege access
- Device identity via WireGuard keys maps to device trust

### NIST SP 800-77: Guide to IPsec VPNs
- WireGuard provides alternative to IPsec with reduced complexity
- Tailscale automates key distribution and NAT traversal
- Mesh topology eliminates single point of failure

## Tailscale Security Model

### Identity Layer
- Authentication via OIDC-compatible identity providers
- SSO integration with Okta, Azure AD, Google Workspace, GitHub
- MFA enforcement through identity provider policies
- Key expiry forces periodic re-authentication

### Network Layer
- Default deny ACL policy (zero trust)
- Per-connection authorization based on identity and tags
- No implicit trust based on network location
- All traffic encrypted with WireGuard (256-bit keys)

### Device Layer
- Unique WireGuard key pair per device
- Device authorization required before network access
- Network Lock prevents unauthorized node addition
- Ephemeral nodes for temporary workloads

## Compliance Considerations

### SOC 2
- End-to-end encryption for data in transit
- ACL-based access control for authorization
- Audit logging for all connection events
- Key management through coordination server

### GDPR
- Data minimization: Tailscale only routes traffic, does not inspect
- Encryption: All traffic encrypted end-to-end
- Self-hosted option (Headscale) for data sovereignty
- Log retention configurable per organization policy
