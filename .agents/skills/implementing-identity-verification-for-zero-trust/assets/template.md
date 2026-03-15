# Identity Verification Implementation Plan Template

## Project Information

| Field | Value |
|---|---|
| Project Name | |
| Organization | |
| Identity Provider | [Azure AD / Okta / Ping Identity] |
| User Population | |
| Target Completion | |

## Current State Assessment

### Identity Infrastructure
- **Primary IdP**: |
- **Secondary IdPs**: |
- **Local Accounts**: [Count and locations] |
- **Shared Accounts**: [Count - target for elimination] |

### Current MFA State
| Method | Enabled | Users Enrolled | Phishing-Resistant |
|---|---|---|---|
| SMS OTP | | | No |
| Voice Call | | | No |
| TOTP App | | | No |
| Push Notification | | | No |
| FIDO2 Security Key | | | Yes |
| Windows Hello | | | Yes |
| Certificate/PIV | | | Yes |

### MFA Enrollment Target
- Current enrollment rate: ___%
- Target enrollment rate: 100%
- Phishing-resistant target: 100%

## Phishing-Resistant MFA Rollout Plan

### Hardware Key Distribution

| User Group | Key Type | Quantity | Distribution Method | Timeline |
|---|---|---|---|---|
| Executive Leadership | YubiKey 5 NFC | | In-person | Week 1 |
| IT Administrators | YubiKey 5C | | IT distribution | Week 2 |
| All Employees | YubiKey Security Key | | Self-service + mail | Weeks 3-8 |

### Enrollment Campaign
- [ ] Communication sent to all users
- [ ] Self-service portal configured
- [ ] Help desk trained on enrollment support
- [ ] Enrollment deadline set: ____
- [ ] Escalation path for non-compliant users

## Conditional Access Policies

| Policy Name | Users | Apps | Conditions | Grant Controls | Session Controls |
|---|---|---|---|---|---|
| Block Legacy Auth | All | All | Legacy clients | Block | N/A |
| Require MFA | All | All | Any | Require MFA | Sign-in freq: 8hr |
| Require Compliant Device | All | Sensitive Apps | Any | Compliant device | App enforced |
| Block Risky Sign-In | All | All | High sign-in risk | Block | N/A |
| Require FIDO2 for Admins | Admin roles | Admin portals | Any | FIDO2 only | 1hr frequency |

## Risk-Based Policies

| Risk Level | User Risk Response | Sign-In Risk Response |
|---|---|---|
| Low | Allow | Allow |
| Medium | Require MFA step-up | Require MFA step-up |
| High | Block + alert SOC | Block + alert SOC |

## Identity Governance

### Lifecycle Automation
- [ ] HR system integrated for joiner/mover/leaver
- [ ] Automatic provisioning on hire
- [ ] Role change triggers access review
- [ ] Automatic deprovisioning on termination
- [ ] Contractor access expiration configured

### Access Reviews
- Frequency: Quarterly
- Scope: All application assignments
- Reviewers: Direct managers
- Auto-action on non-response: Revoke access

## Monitoring and Detection

| Capability | Tool | Status |
|---|---|---|
| Sign-in log analysis | SIEM (Splunk/Sentinel) | |
| Identity threat detection | Entra ID Protection / ThreatInsight | |
| Impossible travel detection | IdP + UEBA | |
| Continuous Access Evaluation | CAE/CAEP | |
| Behavioral analytics | UEBA platform | |

## Sign-Off

| Stakeholder | Role | Approval | Date |
|---|---|---|---|
| | CISO | | |
| | Identity Team Lead | | |
| | Help Desk Manager | | |
| | HR Systems | | |
