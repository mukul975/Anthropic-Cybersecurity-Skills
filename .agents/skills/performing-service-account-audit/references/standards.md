# Standards - Service Account Audit

## NIST Standards
- **NIST SP 800-53 Rev 5**: AC-2, AC-2(3), AC-6, IA-5, AU-6
- **NIST SP 800-171**: 3.1.1, 3.1.2, 3.5.1, 3.5.2

## Industry Frameworks
- **CIS Controls v8**: Control 5.3 - Disable Dormant Accounts, Control 5.4 - Restrict Administrator Privileges
- **MITRE ATT&CK**: T1078 (Valid Accounts), T1136 (Create Account)
- **PCI DSS 4.0**: 7.2.5 - Review user access, 8.6 - Application/system account management
- **SOX Section 404**: Service account access controls for financial systems

## Tools
- **Microsoft AD**: Get-ADServiceAccount, Get-ADUser with SPN filter
- **AWS IAM**: Access Analyzer, Credential Report, IAM Access Advisor
- **Azure Entra ID**: Service principal reports, App registration audit
- **CyberArk DNA**: Automated privileged account discovery
- **Stealthbits (Netwrix)**: Service account discovery and monitoring
