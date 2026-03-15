# SAML SSO Implementation Checklist Template

## Project Information
| Field | Value |
|-------|-------|
| Service Provider | [Application Name] |
| Identity Provider | Okta |
| Implementation Lead | [Name] |
| Target Go-Live Date | [Date] |
| Environment | [ ] Development [ ] Staging [ ] Production |

## Pre-Implementation Checklist

### IdP (Okta) Configuration
- [ ] Okta organization provisioned and accessible
- [ ] Administrative access to Okta confirmed
- [ ] Okta MFA enabled for admin accounts
- [ ] Application created in Okta (SAML 2.0)
- [ ] SSO URL configured: `____________________________`
- [ ] Audience URI (SP Entity ID) set: `____________________________`
- [ ] Name ID Format selected: [ ] Email [ ] Persistent [ ] Transient
- [ ] Attribute statements configured:
  - [ ] email -> `user.email`
  - [ ] firstName -> `user.firstName`
  - [ ] lastName -> `user.lastName`
  - [ ] groups -> (group attribute filter)
- [ ] Signature algorithm set to SHA-256
- [ ] Response signed: [ ] Yes [ ] No
- [ ] Assertion signed: [ ] Yes [ ] No
- [ ] Assertion encryption enabled: [ ] Yes [ ] No
- [ ] Users/Groups assigned to application

### SP Configuration
- [ ] SP SAML library installed and configured
- [ ] ACS URL endpoint implemented: `____________________________`
- [ ] SP Entity ID configured: `____________________________`
- [ ] IdP metadata imported (certificate, SSO URL, Entity ID)
- [ ] Signature validation implemented (SHA-256)
- [ ] InResponseTo validation enabled
- [ ] Audience restriction validation enabled
- [ ] Time condition validation with clock skew tolerance
- [ ] Session creation after successful assertion
- [ ] Error handling for failed assertions

### Security Configuration
- [ ] All endpoints use HTTPS
- [ ] SHA-256 enforced (SHA-1 rejected)
- [ ] Assertion encryption with AES-256-CBC
- [ ] Certificate pinning or strong validation
- [ ] CSRF protection on ACS endpoint
- [ ] Rate limiting on authentication endpoints
- [ ] Session timeout configured: ____ minutes
- [ ] Idle timeout configured: ____ minutes
- [ ] Single Logout (SLO) endpoint configured

## Certificate Management

### Current Certificate
| Field | Value |
|-------|-------|
| Issuer | |
| Subject | |
| Serial Number | |
| Valid From | |
| Valid To | |
| SHA-256 Fingerprint | |
| Algorithm | |

### Certificate Rotation Schedule
| Date | Action | Status |
|------|--------|--------|
| | Generate new certificate in Okta | [ ] Done |
| | Distribute new certificate to SP team | [ ] Done |
| | Install new certificate on SP (dual-cert) | [ ] Done |
| | Activate new certificate on Okta | [ ] Done |
| | Monitor for authentication failures | [ ] Done |
| | Remove old certificate from SP | [ ] Done |

## Testing Checklist

### SP-Initiated SSO
- [ ] User redirected to Okta login page
- [ ] Successful authentication creates SP session
- [ ] User attributes correctly mapped
- [ ] Group memberships correctly populated
- [ ] Invalid credentials properly rejected
- [ ] MFA prompt appears when configured

### IdP-Initiated SSO
- [ ] Login from Okta dashboard tile works
- [ ] Session created correctly on SP
- [ ] Deep links preserved after authentication

### Single Logout
- [ ] SP-initiated logout terminates IdP session
- [ ] IdP-initiated logout terminates SP session
- [ ] All session cookies properly cleared

### Error Scenarios
- [ ] Expired assertion rejected
- [ ] Invalid signature rejected
- [ ] Wrong audience URI rejected
- [ ] Replay attack prevented (InResponseTo)
- [ ] Clock skew beyond tolerance rejected

## Post-Implementation

### Monitoring
- [ ] Authentication success/failure alerts configured
- [ ] Certificate expiration monitoring (30-day warning)
- [ ] Okta System Log integration with SIEM
- [ ] SP authentication logs forwarded to SIEM
- [ ] Dashboard for SSO health metrics

### Documentation
- [ ] Architecture diagram updated
- [ ] Runbook for SSO troubleshooting created
- [ ] Certificate rotation procedure documented
- [ ] Break-glass access procedure documented
- [ ] User communication sent

## Sign-Off
| Role | Name | Date | Signature |
|------|------|------|-----------|
| Security Lead | | | |
| Application Owner | | | |
| IAM Team Lead | | | |
| Change Manager | | | |
