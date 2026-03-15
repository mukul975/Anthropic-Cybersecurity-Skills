# Standards and References: BloodHound AD Analysis

## MITRE ATT&CK Techniques

### Discovery (TA0007)
- **T1087.002** - Account Discovery: Domain Account
- **T1069.001** - Permission Groups Discovery: Local Groups
- **T1069.002** - Permission Groups Discovery: Domain Groups
- **T1018** - Remote System Discovery
- **T1482** - Domain Trust Discovery
- **T1615** - Group Policy Discovery
- **T1016** - System Network Configuration Discovery
- **T1049** - System Network Connections Discovery
- **T1033** - System Owner/User Discovery

### Lateral Movement (TA0008) - Paths Identified by BloodHound
- **T1550.002** - Use Alternate Authentication Material: Pass the Hash
- **T1550.003** - Use Alternate Authentication Material: Pass the Ticket
- **T1021.002** - Remote Services: SMB/Windows Admin Shares
- **T1021.001** - Remote Services: Remote Desktop Protocol
- **T1021.006** - Remote Services: Windows Remote Management

### Credential Access (TA0006) - Attacks Enabled by BloodHound
- **T1558.003** - Steal or Forge Kerberos Tickets: Kerberoasting
- **T1558.004** - Steal or Forge Kerberos Tickets: AS-REP Roasting
- **T1003.006** - OS Credential Dumping: DCSync
- **T1558.001** - Steal or Forge Kerberos Tickets: Golden Ticket

### Privilege Escalation (TA0004)
- **T1484.001** - Domain Policy Modification: Group Policy Modification
- **T1078.002** - Valid Accounts: Domain Accounts
- **T1134** - Access Token Manipulation

## BloodHound Software Entry
- **MITRE ATT&CK ID**: S0521
- **Type**: Tool
- **Platforms**: Windows, Azure AD
- **Associated Groups**: FIN7, APT29, Wizard Spider

## NIST References
- **NIST SP 800-53 Rev. 5** - AC-6: Least Privilege
- **NIST SP 800-53 Rev. 5** - AC-2: Account Management
- **NIST SP 800-53 Rev. 5** - IA-5: Authenticator Management
- **NIST SP 800-171** - 3.1.5: Least Privilege

## CIS Benchmarks
- **CIS Microsoft Windows Server 2022** - Section 2.3.10: Network access
- **CIS Active Directory Benchmark** - Section 1: Account Policies
- **CIS Controls v8** - Control 6: Access Control Management
- **CIS Controls v8** - Control 5: Account Management

## Active Directory Security Hardening Standards
- Microsoft Tier Model for Active Directory Administration
- Microsoft Privileged Access Workstation (PAW) Architecture
- ANSSI Active Directory Security Hardening Guide
- ASD Essential Eight: Restrict Administrative Privileges
