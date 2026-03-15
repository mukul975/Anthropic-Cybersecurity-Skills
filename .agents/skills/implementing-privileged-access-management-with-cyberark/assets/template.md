# CyberArk PAM Implementation Checklist

## Vault Architecture
- [ ] Primary vault server deployed in hardened network segment
- [ ] DR vault configured and tested
- [ ] Vault firewall rules (port 1858 only from authorized components)
- [ ] Vault OS hardened (CIS benchmark applied)
- [ ] Vault backup and recovery tested
- [ ] Break-glass procedure documented and sealed

## Safe Hierarchy
| Safe Name | Purpose | Dual Control | Retention |
|-----------|---------|--------------|-----------|
| DomainAdmins | Domain admin credentials | Yes | 365 days |
| LocalAdmins | Local admin credentials | No | 180 days |
| ServiceAccounts | Service account credentials | No | 365 days |
| DatabaseAdmins | DBA credentials | Yes | 365 days |
| NetworkDevices | Network device credentials | No | 180 days |
| CloudIAM | Cloud access keys | Yes | 365 days |

## Platform Rotation Policies
| Platform | Rotation | Verification | Reconciliation |
|----------|----------|--------------|----------------|
| Windows Domain Admin | 24 hours | 4 hours | On failure |
| Linux Root (SSH Key) | 72 hours | 12 hours | On failure |
| SQL Server SA | 24 hours | 4 hours | On failure |
| Oracle DBA | 24 hours | 4 hours | On failure |
| Cisco IOS | 7 days | 24 hours | On failure |
| Service Accounts | 30 days | 7 days | On failure |
| AWS IAM Keys | 90 days | 30 days | On failure |

## PSM Configuration
- [ ] PSM servers deployed behind load balancer
- [ ] RDP connection component configured
- [ ] SSH connection component configured
- [ ] Database connection components (SSMS, SQL*Plus)
- [ ] Web application connectors configured
- [ ] Session recording storage provisioned
- [ ] Recording retention policy: _____ days
- [ ] Live monitoring enabled

## Integration Checklist
- [ ] SIEM integration (Syslog/CEF)
- [ ] Ticketing system integration (ServiceNow/Jira)
- [ ] PTA deployed and configured
- [ ] LDAP/AD integration for vault authentication
- [ ] MFA integration (RADIUS/Duo)

## Compliance Mapping
| Requirement | CyberArk Control | Status |
|-------------|------------------|--------|
| NIST AC-2 Account Management | Vault account lifecycle | [ ] |
| NIST AC-5 Separation of Duties | Dual control, safe roles | [ ] |
| NIST AC-6 Least Privilege | Platform-based access | [ ] |
| NIST IA-5 Authenticator Management | CPM rotation | [ ] |
| NIST AU-14 Session Audit | PSM recording | [ ] |
| PCI DSS 7.1 Restrict Access | Safe-based access control | [ ] |
| PCI DSS 8.3.6 Password Complexity | Platform policies | [ ] |
