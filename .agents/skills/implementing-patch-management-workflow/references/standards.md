# Standards and References - Patch Management Workflow

## Industry Standards
- **NIST SP 800-40 Rev 4**: Guide to Enterprise Patch Management Planning
- **NIST SP 800-53 SI-2**: Flaw Remediation control
- **CIS Controls v8 Control 7.3**: Perform automated patch management
- **PCI DSS v4.0 Req 6.3**: Identify and address security vulnerabilities
- **ISO 27001:2022 A.8.8**: Management of technical vulnerabilities

## Patch Management Tools
| Tool | Platform | Type | License |
|------|----------|------|---------|
| WSUS | Windows | Microsoft native | Free with Windows Server |
| SCCM/MECM | Windows/Linux | Enterprise endpoint management | Microsoft licensing |
| Ansible | Linux/Windows | Agentless automation | Open source / Red Hat |
| Intune | Windows/macOS/iOS/Android | Cloud MDM/MAM | Microsoft 365 |
| Jamf Pro | macOS/iOS | Apple device management | Commercial |
| Ivanti Patch | Multi-platform | Enterprise patching | Commercial |
| ManageEngine | Multi-platform | IT management suite | Commercial |

## Vendor Patch Schedules
| Vendor | Schedule | Source |
|--------|----------|--------|
| Microsoft | Second Tuesday monthly | https://msrc.microsoft.com/update-guide |
| Adobe | Second Tuesday monthly | https://helpx.adobe.com/security/products.html |
| Oracle | Quarterly (Jan, Apr, Jul, Oct) | https://www.oracle.com/security-alerts/ |
| Cisco | As needed | https://sec.cloudapps.cisco.com/security/center |
| Linux distributions | Continuous | Distribution-specific advisories |
