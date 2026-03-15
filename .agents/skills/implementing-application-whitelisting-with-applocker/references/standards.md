# Standards & References - Implementing Application Whitelisting with AppLocker

## Primary Standards

### NIST SP 800-167 - Guide to Application Whitelisting
- **Publisher**: NIST
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-167/final
- **Scope**: Comprehensive guidance on planning, implementing, and maintaining application whitelisting
- **Key sections**: Technology overview, planning process, policy creation, maintenance operations

### ACSC Essential Eight - Application Control
- **Publisher**: Australian Cyber Security Centre
- **URL**: https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight
- **Scope**: Application control is Mitigation Strategy #1 in the Essential Eight
- **Maturity levels**: L1 (block executables in user profiles), L2 (block from all user-writable paths), L3 (Microsoft recommended block rules + WDAC)

### CIS Control 2 - Software Inventory and Control
- **Publisher**: Center for Internet Security
- **Relevance**: CIS Controls v8 Control 2 requires software allowlisting for authorized applications

## Compliance Mappings

| Framework | Requirement | AppLocker Coverage |
|-----------|------------|-------------------|
| PCI DSS 4.0 | 6.4.3 - Restrict active content | AppLocker script rules block unauthorized scripts |
| NIST 800-53 | CM-7 - Least Functionality | AppLocker enforces minimum required software |
| NIST 800-53 | CM-11 - User-Installed Software | AppLocker prevents unauthorized software installation |
| NIST 800-171 | 3.4.8 - Application whitelisting | Direct requirement for application control |
| ISO 27001 | A.12.5.1 - Installation of software on operational systems | AppLocker restricts installation capability |
| HIPAA | 164.312(a)(1) - Access Control | Restricts executable access to authorized applications |

## Microsoft Documentation

- **AppLocker Overview**: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-overview
- **AppLocker Policies Design Guide**: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-policies-design-guide
- **WDAC and AppLocker Feature Availability**: Comparison of capabilities between AppLocker and WDAC
- **Microsoft Recommended Block Rules**: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol

## Supporting References

- **LOLBAS Project**: https://lolbas-project.github.io/ - Living Off The Land Binaries reference for deny rule creation
- **AaronLocker (GitHub)**: Open-source toolkit for generating robust AppLocker policies
- **UltimateAppLockerByPassList**: Security research on AppLocker bypass techniques for defense awareness
