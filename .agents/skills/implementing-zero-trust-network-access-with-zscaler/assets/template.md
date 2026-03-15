# ZTNA Deployment Plan Template

## Project Information

| Field | Value |
|---|---|
| Project Name | |
| Organization | |
| Project Lead | |
| Start Date | |
| Target Completion | |
| ZPA Tenant ID | |

## Current State Assessment

### Existing Remote Access
- **VPN Solution**: [e.g., Cisco AnyConnect, Palo Alto GlobalProtect]
- **Concurrent VPN Users**: [number]
- **VPN Concentrator Locations**: [list]
- **Known VPN Issues**: [latency, split-tunnel risks, capacity]

### Application Inventory

| App Name | FQDN/IP | Port | Protocol | User Groups | Criticality | Migration Wave |
|---|---|---|---|---|---|---|
| | | | | | | |
| | | | | | | |

### Identity Provider
- **Primary IdP**: [Azure AD / Okta / Ping Identity / Other]
- **MFA Enabled**: [Yes/No - Method]
- **SCIM Supported**: [Yes/No]
- **Federation Protocol**: [SAML 2.0 / OIDC]

## ZPA Architecture Design

### App Connector Placement

| Environment | Location | VM Count | Server Group |
|---|---|---|---|
| Primary DC | | 2 | |
| DR Site | | 2 | |
| AWS VPC | | 2 | |
| Azure VNet | | 2 | |

### Application Segments

| Segment Name | Domains/IPs | TCP Ports | UDP Ports | Server Group | Browser Access |
|---|---|---|---|---|---|
| | | | | | |
| | | | | | |

### Access Policy Matrix

| Policy Name | User Groups | App Segments | Posture Profile | Conditions | Action |
|---|---|---|---|---|---|
| | | | | | Allow |
| | | | | | Allow |
| Block Default | All | All | None | None | Deny |

### Device Posture Profiles

| Profile Name | OS | Min Version | Disk Encryption | AV/EDR Required | Domain Joined |
|---|---|---|---|---|---|
| Corporate Managed | Windows | 10 22H2+ | BitLocker | CrowdStrike | Yes |
| Corporate Managed | macOS | 14.0+ | FileVault | CrowdStrike | No |
| BYOD | Any | Current-1 | Any | Any | No |

## Migration Plan

### Wave 1: Low-Risk Web Applications (Weeks 1-2)
- [ ] Applications: [list]
- [ ] User groups: [list]
- [ ] Success criteria: [define]
- [ ] Rollback plan: [define]

### Wave 2: Business-Critical Web Apps (Weeks 3-5)
- [ ] Applications: [list]
- [ ] User groups: [list]
- [ ] Success criteria: [define]
- [ ] Rollback plan: [define]

### Wave 3: Non-Web TCP/UDP Applications (Weeks 6-8)
- [ ] Applications: [list]
- [ ] User groups: [list]
- [ ] Success criteria: [define]
- [ ] Rollback plan: [define]

### Wave 4: Legacy Applications (Weeks 9-12)
- [ ] Applications: [list]
- [ ] User groups: [list]
- [ ] Success criteria: [define]
- [ ] Rollback plan: [define]

## SIEM Integration

| Field | Value |
|---|---|
| SIEM Platform | [Splunk / Sentinel / QRadar / Other] |
| Log Streaming Method | [HTTPS / Syslog / Cloud NSS] |
| Log Types | [User Activity / App Connector Status / Policy Violations] |
| Retention Period | |
| Alert Rules | |

## Testing Plan

### Functional Tests
- [ ] User authentication via IdP
- [ ] Application access per policy
- [ ] Device posture enforcement
- [ ] Browser Access for web apps
- [ ] Failover between App Connectors
- [ ] Client Connector auto-update

### Security Tests
- [ ] Unauthorized user access denied
- [ ] Non-compliant device blocked or restricted
- [ ] No lateral movement between segments
- [ ] Log events captured in SIEM
- [ ] Incident response playbook tested

### Performance Tests
- [ ] Application latency within SLA
- [ ] Throughput meets requirements
- [ ] Service Edge selection optimal for user locations

## Sign-Off

| Stakeholder | Role | Approval | Date |
|---|---|---|---|
| | Network Security | | |
| | Identity Team | | |
| | Application Owners | | |
| | CISO / Security Lead | | |
| | IT Operations | | |
