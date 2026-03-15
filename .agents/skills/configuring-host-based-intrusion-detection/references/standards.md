# Standards & References - Configuring Host-Based Intrusion Detection

## Primary Standards

### NIST SP 800-94 Rev 1 - Guide to Intrusion Detection and Prevention Systems
- **Publisher**: NIST
- **Scope**: Architecture, deployment, and management of IDPS including host-based systems

### PCI DSS 4.0 Requirement 11.5 - File Integrity Monitoring
- **Publisher**: PCI SSC
- **Requirement**: Deploy FIM to alert on unauthorized modification of critical files
- **Scope**: System files, configuration files, content files on in-scope systems

### CIS Control 3 - Data Protection (v8)
- **Publisher**: CIS
- **Relevance**: Sub-control 3.14 requires monitoring for unauthorized changes to sensitive data

## Compliance Mappings

| Framework | Requirement | HIDS Coverage |
|-----------|------------|--------------|
| PCI DSS 4.0 | 11.5.2 - FIM mechanism deployed | Wazuh syscheck module |
| NIST 800-53 | SI-7 Software, Firmware, and Information Integrity | File integrity monitoring |
| NIST 800-53 | SI-4 System Monitoring | HIDS log analysis and alerting |
| HIPAA | 164.312(b) - Audit controls | File access and change monitoring |
| ISO 27001 | A.12.4.1 - Event logging | HIDS event collection and analysis |

## Supporting References

- **Wazuh Documentation**: https://documentation.wazuh.com/
- **OSSEC Documentation**: https://www.ossec.net/docs/
- **Wazuh FIM Reference**: https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/
- **Wazuh Ruleset**: https://github.com/wazuh/wazuh-ruleset
