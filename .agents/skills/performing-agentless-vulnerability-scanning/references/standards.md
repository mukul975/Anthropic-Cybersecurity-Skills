# Standards and References - Agentless Vulnerability Scanning

## Tools and Platforms
- Vuls (Open Source): https://vuls.io/
- Microsoft Defender for Cloud Agentless: https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-agentless-data-collection
- Tenable Agentless Discovery: https://www.tenable.com/cloud-security/capabilities/agentless-asset-vulnerability-discovery
- Wiz Agentless VM: https://www.wiz.io/solutions/vulnerability-management
- Datadog Agentless Scanning: https://www.datadoghq.com/blog/agentless-scanning/

## Industry Standards
- **NIST SP 800-115**: Technical Guide to Information Security Testing and Assessment
- **CIS Controls v8.1 Control 7.5**: Perform Automated Vulnerability Scans of Internal Assets
- **PCI DSS v4.0 Req 11.3**: External and internal vulnerability scanning
- **ISO 27001:2022 A.8.8**: Management of technical vulnerabilities

## Protocol Requirements
| Protocol | Port | Auth Method | Use Case |
|----------|------|-------------|----------|
| SSH | 22 | Key-based or password | Linux/Unix scanning |
| WinRM | 5985/5986 | NTLM/Kerberos | Windows scanning |
| WMI | 135 + dynamic | NTLM | Windows legacy |
| SNMP v3 | 161 | AuthPriv | Network devices |
| Cloud APIs | 443 | IAM roles/keys | Cloud VMs |
