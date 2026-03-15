# Standards & References - Detecting Evasion Techniques in Endpoint Logs

## Primary Standards

### MITRE ATT&CK TA0005 - Defense Evasion
- **URL**: https://attack.mitre.org/tactics/TA0005/
- **Scope**: 43 techniques and 80+ sub-techniques for defense evasion
- **Key techniques**: T1055 (Process Injection), T1070 (Indicator Removal), T1036 (Masquerading), T1218 (System Binary Proxy Execution), T1562 (Impair Defenses)

### Sigma Detection Rules
- **URL**: https://github.com/SigmaHQ/sigma
- **Scope**: Community-maintained detection rules in vendor-agnostic format
- **Evasion rules**: rules/windows/process_creation/proc_creation_win_*, rules/windows/sysmon/

### LOLBAS Project
- **URL**: https://lolbas-project.github.io/
- **Scope**: Catalog of Windows binaries that can be used for defense evasion, with detection recommendations

## Compliance Mappings

| Framework | Requirement | Detection Coverage |
|-----------|------------|-------------------|
| NIST 800-53 | SI-4 System Monitoring | Evasion detection via endpoint logging |
| NIST 800-53 | AU-6 Audit Record Review | Log analysis for tampering indicators |
| PCI DSS 4.0 | 10.4.1 - Audit log review | Automated detection of log tampering |
| ISO 27001 | A.12.4.1 - Event logging | Integrity monitoring of security logs |

## Supporting References

- **Sysmon Configuration**: https://github.com/SwiftOnSecurity/sysmon-config
- **Olaf Hartong Sysmon Modular**: https://github.com/olafhartong/sysmon-modular
- **SANS Hunt Evil Poster**: Comprehensive guide to suspicious Windows process behavior
- **Elastic Detection Rules**: https://github.com/elastic/detection-rules
