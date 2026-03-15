# Duo MFA Deployment Checklist

## Duo Admin Panel Configuration
- [ ] Admin account secured with hardware security key
- [ ] Admin API credentials generated and stored securely
- [ ] AD Sync configured for user provisioning
- [ ] User groups created (Standard, Privileged, Contractors)

## Authentication Policy Matrix
| Group | Push | Verified Push | WebAuthn | TOTP | SMS | Phone | Remember |
|-------|------|---------------|----------|------|-----|-------|----------|
| Standard | Yes | No | Optional | Yes | No | No | 7 days |
| Privileged | No | Yes | Yes | Backup | No | No | None |
| Contractors | Yes | No | No | Yes | No | No | None |

## Integration Points
| System | Integration Method | Status |
|--------|--------------------|--------|
| VPN (Cisco ASA) | RADIUS via Auth Proxy | [ ] |
| VPN (Palo Alto) | RADIUS via Auth Proxy | [ ] |
| Windows RDP | Duo for Windows Logon | [ ] |
| Linux SSH | Duo Unix (PAM) | [ ] |
| Web Apps (SAML) | Duo SSO | [ ] |
| Office 365 | Duo + Azure AD | [ ] |

## Device Health Policy
- [ ] Require disk encryption
- [ ] Minimum OS version: Windows 10 22H2 / macOS 13 / iOS 16 / Android 12
- [ ] Require firewall enabled
- [ ] Block jailbroken/rooted devices
- [ ] Require screen lock

## Emergency Procedures
- [ ] Bypass code generation procedure documented
- [ ] Failmode configuration documented per integration
- [ ] Emergency contact list for Duo outage
- [ ] Alternative authentication path tested
