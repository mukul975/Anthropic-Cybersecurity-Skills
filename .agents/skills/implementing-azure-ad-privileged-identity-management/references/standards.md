# Azure AD PIM - Standards Reference

## Microsoft Entra ID Licensing

| Feature | Required License |
|---------|-----------------|
| PIM for Entra Roles | Entra ID P2 or Entra ID Governance |
| PIM for Azure Resources | Entra ID P2 or Entra ID Governance |
| PIM for Groups | Entra ID P2 or Entra ID Governance |
| Access Reviews | Entra ID P2 or Entra ID Governance |
| Conditional Access | Entra ID P1 (minimum) |

## Critical Entra Directory Roles

| Role | Risk Level | Recommended PIM Setting |
|------|-----------|------------------------|
| Global Administrator | Critical | Eligible, approval required, max 1hr activation |
| Privileged Role Administrator | Critical | Eligible, approval required |
| Security Administrator | High | Eligible, MFA required |
| Exchange Administrator | High | Eligible, MFA required |
| SharePoint Administrator | High | Eligible, MFA required |
| User Administrator | Medium | Eligible, MFA required |
| Application Administrator | High | Eligible, MFA required |
| Cloud Application Administrator | High | Eligible, MFA required |
| Intune Administrator | Medium | Eligible, justification required |
| Compliance Administrator | Medium | Eligible, justification required |

## Compliance Framework Mapping

### NIST SP 800-53 Rev 5
- AC-2(4): Automated Audit Actions (PIM audit logs)
- AC-2(5): Inactivity Logout (time-bound activations)
- AC-6(1): Authorize Access to Security Functions
- AC-6(2): Non-Privileged Access for Non-Security Functions
- AC-6(5): Privileged Accounts (eligible vs. active)

### CIS Microsoft 365 Foundations Benchmark
- 1.1.1: Ensure MFA is enabled for all users in admin roles
- 1.1.3: Ensure that between two and four Global Admins are designated
- 1.1.6: Ensure Administrative accounts are separate and cloud-only
- 1.3.1: Ensure PIM is used to manage roles

### SOC 2 Trust Service Criteria
- CC6.1: Logical and physical access controls
- CC6.2: Prior to issuing credentials, registration and authorization
- CC6.3: Authorize, modify, or remove access timely
