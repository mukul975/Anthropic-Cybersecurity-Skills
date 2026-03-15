# ZPA ZTNA Deployment Checklist

## Project Information
| Field | Value |
|-------|-------|
| Organization | Acme Financial Corp |
| ZPA Customer ID | 12345678 |
| ZPA Cloud | zscaler.net (US) |
| Project Lead | Security Architecture Team |
| Start Date | 2026-01-20 |

## Pre-Deployment

### Identity Provider
- [x] IdP configured: Microsoft Entra ID (SAML 2.0)
- [x] SCIM provisioning enabled for user/group sync
- [x] MFA enforced for all users
- [x] User groups mapped: Engineering, HR, Finance, Contractors

### Network Requirements
- [x] Outbound HTTPS (443) to *.private.zscaler.com allowed
- [x] Outbound HTTPS (443) to *.zpath.net allowed
- [x] DNS resolution from App Connector VMs to all internal FQDNs verified
- [ ] Split-horizon DNS configured for hybrid access

## App Connector Deployment

| Connector Name | Group | Location | VM Specs | Status |
|---------------|-------|----------|----------|--------|
| ac-dc-east-01 | DC-East | AWS us-east-1 | t3.medium | Healthy |
| ac-dc-east-02 | DC-East | AWS us-east-1 | t3.medium | Healthy |
| ac-dc-west-01 | DC-West | AWS us-west-2 | t3.medium | Healthy |
| ac-dc-west-02 | DC-West | AWS us-west-2 | t3.medium | Healthy |

## Application Segments

| Segment Name | Applications | Ports | Server Group | Bypass |
|-------------|-------------|-------|-------------|--------|
| HR Applications | hr-portal.internal.corp | 443 | DC-East | Never |
| Finance Tools | finance.internal.corp, reports.internal.corp | 443 | DC-East | Never |
| Engineering | git.internal.corp, ci.internal.corp, wiki.internal.corp | 22, 443 | DC-East + DC-West | Never |
| Monitoring | grafana.internal.corp, prometheus.internal.corp | 443, 9090 | DC-West | Never |
| Contractor Portal | vendor.internal.corp | 443 | DC-East | Never |

## Access Policies

| Rule | Action | Users/Groups | Segments | Posture | Priority |
|------|--------|-------------|----------|---------|----------|
| HR Access | ALLOW | HR-Department | HR Applications | Corporate Managed | 1 |
| Finance Access | ALLOW | Finance-Team | Finance Tools | Corporate Managed | 2 |
| Engineering Access | ALLOW | Engineering, DevOps | Engineering | Developer Workstation | 3 |
| Monitoring Access | ALLOW | SRE-Team, Engineering | Monitoring | Corporate Managed | 4 |
| Contractor Access | ALLOW | Contractors | Contractor Portal | BYOD | 5 |
| Default Deny | DENY | All Users | All Segments | N/A | 99 |

## Device Posture Profiles

| Profile | CrowdStrike ZTA | OS Version | Encryption | Firewall |
|---------|----------------|------------|------------|----------|
| Corporate Managed | >= 60 | Win 10 21H2+ / macOS 13+ | Required | Required |
| Developer Workstation | >= 70 | Win 10 21H2+ / macOS 13+ | Required | Required |
| BYOD | N/A | Latest -1 | Recommended | N/A |

## Migration Tracker

| Phase | Users | Applications | Start | Status |
|-------|-------|-------------|-------|--------|
| Phase 1: IT/Security | 50 | All | 2026-02-01 | Complete |
| Phase 2: Engineering | 200 | Engineering, Monitoring | 2026-02-10 | Complete |
| Phase 3: Business | 250 | HR, Finance, Contractor | 2026-02-20 | In Progress |
| VPN Decommission | N/A | N/A | 2026-03-15 | Pending |

## Sign-Off

| Role | Name | Date | Approved |
|------|------|------|----------|
| CISO | _________________ | __________ | [ ] |
| Network Architect | _________________ | __________ | [ ] |
| IT Operations | _________________ | __________ | [ ] |
