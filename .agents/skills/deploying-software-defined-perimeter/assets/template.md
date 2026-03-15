# SDP Deployment Plan Template

## Project Information

| Field | Value |
|---|---|
| Project Name | |
| SDP Solution | [Appgate SDP / Zscaler / Open-source / Other] |
| Project Lead | |
| Start Date | |

## Application Inventory

| Application | FQDN/IP | Port | Protocol | Criticality | Gateway Assignment |
|---|---|---|---|---|---|
| | | | | | |

## SDP Controller Configuration

| Parameter | Value |
|---|---|
| HA Mode | [Active-Active / Active-Passive] |
| IdP Integration | [SAML / OIDC] |
| IdP Provider | [Azure AD / Okta / Ping] |
| PKI Backend | [Internal CA / HashiCorp Vault / EJBCA] |
| Client Cert Lifetime | [24h / 48h / 72h] |
| Audit Log Destination | [SIEM / Syslog / Cloud storage] |

## Gateway Deployment

| Gateway Name | Location | Protected Apps | SPA Enabled | mTLS Enabled | Default-Drop |
|---|---|---|---|---|---|
| | | | Yes | Yes | Yes |

## Access Policy Matrix

| User Group | Application | Conditions | Action |
|---|---|---|---|
| | | Device posture + MFA | Allow |
| Default | All | None | Deny |

## Security Validation

- [ ] Port scan confirms gateway invisibility
- [ ] SPA validation working correctly
- [ ] mTLS handshake succeeds with valid certs
- [ ] Invalid SPA packets dropped silently
- [ ] Revoked certificates denied access
- [ ] Lateral movement between apps blocked
- [ ] Logs captured in SIEM

## Sign-Off

| Stakeholder | Role | Approval | Date |
|---|---|---|---|
| | Security Architecture | | |
| | Network Engineering | | |
| | Application Owners | | |
