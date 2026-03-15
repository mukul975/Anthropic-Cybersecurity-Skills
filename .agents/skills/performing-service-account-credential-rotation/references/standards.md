# Service Account Credential Rotation - Standards Reference

## Compliance Requirements

### NIST SP 800-63B - Digital Identity Guidelines
- Authenticator lifecycle management
- Credential rotation for compromised or expired secrets
- Automated mechanisms for credential management preferred

### PCI DSS v4.0
- 8.3.9: Passwords/passphrases for application and system accounts changed periodically (at least every 90 days)
- 8.6.1: Interactive use of system and application accounts managed
- 8.6.3: Passwords for application and system accounts protected against misuse

### SOC 2 - CC6.1
- Logical access controls restrict access to information assets
- Credentials are managed throughout their lifecycle
- Service account credentials rotated per policy

### CIS Controls v8
- 5.2: Use unique passwords
- 5.4: Restrict admin privileges to dedicated accounts
- 5.5: Establish and maintain inventory of service accounts

## Rotation Frequency Standards

| Account Type | NIST Guideline | PCI DSS | CIS Benchmark | Recommended |
|-------------|----------------|---------|---------------|-------------|
| Domain Admin | 60 days | 90 days | 90 days | 30 days |
| Service Account (AD) | gMSA auto | 90 days | 90 days | gMSA (auto 30 days) |
| Cloud Access Keys | 90 days | 90 days | 90 days | 90 days or eliminate |
| Database Admin | 60 days | 90 days | 90 days | Dynamic secrets (per-session) |
| API Keys | 90 days | N/A | 90 days | 90 days or short-lived tokens |

## Technology Standards

### gMSA (Group Managed Service Accounts)
- Windows Server 2012+ domain functional level
- KDS Root Key required (one per forest)
- 240-byte cryptographically random passwords
- Automatic rotation every 30 days by default
- Multiple hosts can share same gMSA

### PKCS#12 / X.509 Certificate Rotation
- Certificate-based authentication preferred over passwords
- Auto-renewal via ACME protocol or internal CA
- Certificate pinning considerations for service-to-service auth
