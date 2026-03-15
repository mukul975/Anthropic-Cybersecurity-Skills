# Standards Reference: HashiCorp Boundary Zero Trust

## Core Standards

### NIST SP 800-207: Zero Trust Architecture
- Boundary implements identity-aware proxy architecture (Section 3.2.2)
- Default-deny access model aligns with ZTA core principle
- Dynamic credential brokering eliminates standing privileges
- Session-level authorization satisfies continuous verification

### NIST SP 800-53: Security Controls
- AC-2: Account Management (identity lifecycle via OIDC)
- AC-3: Access Enforcement (role-based grants)
- AC-6: Least Privilege (fine-grained permissions)
- AU-2: Audit Events (session recording and logging)
- AU-3: Content of Audit Records (session playback)
- IA-2: Identification and Authentication (OIDC/LDAP)
- SC-7: Boundary Protection (identity-aware proxy)

### SOC 2 Compliance
- CC6.1: Logical and Physical Access Controls
- CC6.2: Prior to Access, Identity is Established
- CC6.3: Role-Based Access Controls
- CC7.2: Monitoring of System Components
- CC8.1: Change Management

## Boundary Security Model

### Identity-Aware Access
- Authentication via OIDC, LDAP, or password auth methods
- Managed groups for automatic role assignment from IdP claims
- Session tokens with configurable expiry
- No direct network access to targets without Boundary session

### Credential Management
- Brokered credentials: Vault generates and returns credentials to user
- Injected credentials: Boundary injects credentials directly (user never sees them)
- SSH certificate signing: Vault CA issues short-lived SSH certificates
- Dynamic database credentials: just-in-time access with automatic revocation

### Session Controls
- Maximum session duration enforcement
- Connection limits per session
- Session recording for privileged access audit
- Automatic credential revocation on session end

## Integration Standards

### HashiCorp Vault Integration
- Transit KMS for Boundary encryption keys
- Database secrets engine for dynamic credentials
- SSH secrets engine for certificate-based access
- PKI secrets engine for TLS certificate management

### Terraform Infrastructure as Code
- Boundary Terraform provider for declarative configuration
- Version-controlled access policies
- Automated deployment and updates
- Drift detection for access control changes
