# BeyondCorp Zero Trust Access - Migration Checklist

## Project Information
| Field | Value |
|-------|-------|
| Organization | Acme Corporation |
| Project ID | acme-prod-beyondcorp |
| Lead Engineer | J. Smith, Security Architecture |
| Start Date | 2026-01-15 |
| Target Completion | 2026-04-15 |

## Pre-Migration Checklist

### Identity Provider Configuration
- [x] Google Workspace or Cloud Identity configured as primary IdP
- [x] MFA enforced for all users (FIDO2 security keys for privileged accounts)
- [x] User groups defined and synchronized (engineering, finance, contractors, executives)
- [x] Service accounts inventoried and mapped to applications
- [ ] Break-glass accounts created with documented access procedures

### Google Cloud Infrastructure
- [x] IAP API enabled on all production projects
- [x] Access Context Manager API enabled at organization level
- [x] BeyondCorp Enterprise API enabled
- [x] Cloud Audit Logs enabled for IAP data access
- [x] OAuth consent screen configured
- [ ] IAP OAuth clients created per application tier

### Endpoint Verification
- [x] Endpoint Verification extension deployed to Chrome managed browsers
- [x] Device inventory populated (2,847 devices enrolled)
- [ ] Device compliance baseline established (target: 95%)
- [ ] Non-compliant device remediation plan documented
- [ ] BYOD enrollment policy defined

## Access Level Design

| Access Level | Device Policy | Encryption | Screen Lock | Geo Restriction | Applications |
|-------------|---------------|------------|-------------|-----------------|-------------|
| basic-access | Any enrolled | Not required | Not required | None | Public wiki, cafeteria menu |
| standard-access | Enrolled + managed | Required | Required | US, GB, DE | Email, calendar, chat |
| enhanced-access | Managed + EDR | Required | Required | US, GB | Internal tools, CI/CD |
| high-trust | Managed + EDR + patched | Required | Required | US only | Finance, HR, admin panels |

## Application Migration Tracker

| Application | Hosting | Protocol | Current Access | IAP Status | Access Level | Migration Date |
|-------------|---------|----------|---------------|------------|-------------|---------------|
| Internal Wiki | App Engine | HTTPS | VPN | Enabled | basic-access | 2026-02-01 |
| CI/CD Dashboard | GKE | HTTPS | VPN | Enabled | enhanced-access | 2026-02-08 |
| HR Portal | On-prem | HTTPS | VPN | Connector deployed | high-trust | 2026-02-15 |
| Finance System | Compute Engine | HTTPS | VPN | Enabled | high-trust | 2026-02-22 |
| Git Repository | GKE | SSH+HTTPS | VPN | Enabled | enhanced-access | 2026-02-08 |
| Monitoring | Cloud Run | HTTPS | VPN | Enabled | standard-access | 2026-02-01 |
| Admin Console | On-prem | HTTPS | VPN | Connector pending | high-trust | 2026-03-01 |

## Session Policy Configuration

| Application Tier | Session Duration | Re-auth Method | Re-auth Trigger |
|-----------------|-----------------|----------------|-----------------|
| General (Tier 1) | 8 hours | LOGIN | Session expiry |
| Sensitive (Tier 2) | 4 hours | LOGIN | Session expiry, device change |
| Critical (Tier 3) | 1 hour | SECURE_KEY (FIDO2) | Session expiry, IP change |
| Admin (Tier 4) | 30 minutes | SECURE_KEY (FIDO2) | Any context change |

## Post-Migration Validation

### Functional Testing
- [ ] All migrated applications accessible through IAP without VPN
- [ ] Access denied for users not in authorized groups
- [ ] Access denied for non-compliant devices
- [ ] Re-authentication triggers working per policy
- [ ] Break-glass access procedure tested successfully
- [ ] On-premises connector failover tested

### Security Testing
- [ ] Direct application access blocked (only through IAP)
- [ ] IAP bypass attempts detected and logged
- [ ] Session hijacking mitigations verified
- [ ] Cross-tenant access properly denied
- [ ] Audit logs capturing all access decisions

### Monitoring
- [ ] BigQuery audit pipeline operational
- [ ] Alert policies configured for repeated denials
- [ ] Dashboard showing real-time access metrics
- [ ] Monthly access review process documented

## VPN Decommission Timeline

| Phase | Date | Action | Status |
|-------|------|--------|--------|
| Parallel Start | 2026-03-01 | VPN and BeyondCorp running side by side | Pending |
| VPN Monitoring | 2026-03-01 to 2026-03-15 | Track remaining VPN usage | Pending |
| VPN Block New | 2026-03-15 | Block new VPN connections | Pending |
| VPN Shutdown | 2026-04-01 | Decommission VPN infrastructure | Pending |
| Post-Mortem | 2026-04-15 | Migration lessons learned review | Pending |

## Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| CISO | _________________ | __________ | __________ |
| Security Architect | _________________ | __________ | __________ |
| IT Operations Lead | _________________ | __________ | __________ |
| Application Owner | _________________ | __________ | __________ |
