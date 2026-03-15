# AiTM Phishing Detection Template

## Phishing-Resistant MFA Deployment
| User Group | MFA Method | AiTM Resistant | Status |
|---|---|---|---|
| Global Admins | FIDO2 Security Key | Yes | |
| Privileged Admins | Windows Hello for Business | Yes | |
| Finance/HR | FIDO2 Security Key | Yes | |
| All Users | Microsoft Authenticator (number match) | Partial | |

## Conditional Access Policies for AiTM Prevention
| Policy | Condition | Action | Status |
|---|---|---|---|
| Require managed device | All cloud apps | Block if unmanaged | |
| Block anonymous proxy | Sign-in risk | Block | |
| Require phishing-resistant MFA | Admin roles | Enforce FIDO2 | |
| Token binding | Sensitive apps | Bind to device | |
| Continuous access evaluation | Exchange/SharePoint | Enable CAE | |

## AiTM Detection Rules
| Rule | Data Source | Alert Priority |
|---|---|---|
| Session IP mismatch within 10min | Azure AD sign-in logs | Critical |
| Impossible travel | Azure AD sign-in logs | High |
| Inbox rule creation post-auth | Exchange audit logs | High |
| OAuth consent post-risky-sign-in | Azure AD audit logs | High |
| New MFA method from new IP | Azure AD audit logs | Medium |
| Connection to PhaaS infrastructure | Web proxy logs | Medium |

## Incident Response Contacts
| Role | Name | Contact |
|---|---|---|
| SOC Lead | | |
| Identity Team | | |
| Email Security | | |
