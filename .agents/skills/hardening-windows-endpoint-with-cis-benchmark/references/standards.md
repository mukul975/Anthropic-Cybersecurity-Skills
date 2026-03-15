# Standards & References - Hardening Windows Endpoint with CIS Benchmark

## Primary Standards

### CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0
- **Publisher**: Center for Internet Security (CIS)
- **URL**: https://www.cisecurity.org/benchmark/microsoft_windows_desktop
- **Scope**: 400+ security configuration recommendations organized into 19 sections
- **Profiles**: Level 1 (Corporate), Level 2 (High Security), BitLocker (BL), Next Generation Windows Security (NG)

### CIS Microsoft Windows Server 2022 Benchmark v3.0.0
- **Publisher**: CIS
- **URL**: https://www.cisecurity.org/benchmark/microsoft_windows_server
- **Scope**: Server-specific recommendations for Member Server and Domain Controller roles
- **Profiles**: Level 1 (MS/DC), Level 2 (MS/DC)

### NIST SP 800-123 - Guide to General Server Security
- **Publisher**: NIST
- **Relevance**: Foundational server hardening guidance that CIS benchmarks operationalize
- **Key sections**: OS hardening, user account management, resource access controls

## Compliance Mappings

### PCI DSS v4.0 Mapping
| PCI DSS Requirement | CIS Benchmark Section |
|---------------------|----------------------|
| 2.2 - Develop configuration standards | CIS Benchmark entire scope |
| 5.2 - Anti-malware mechanisms | Section 18.10 (Windows Defender) |
| 8.3 - Strong authentication | Section 1.1 (Password Policy) |
| 10.2 - Audit trail implementation | Section 17 (Advanced Audit Policy) |

### NIST 800-53 Rev 5 Mapping
| NIST Control | CIS Benchmark Section |
|-------------|----------------------|
| CM-6 Configuration Settings | Entire CIS Benchmark |
| AC-2 Account Management | Section 1 (Account Policies) |
| AU-2 Audit Events | Section 17 (Advanced Audit Policy) |
| SC-7 Boundary Protection | Section 9 (Windows Firewall) |

### HIPAA Security Rule Mapping
| HIPAA Requirement | CIS Benchmark Section |
|------------------|----------------------|
| 164.312(a)(1) Access Control | Section 2.3 (Security Options) |
| 164.312(b) Audit Controls | Section 17 (Advanced Audit Policy) |
| 164.312(a)(2)(iv) Encryption | BitLocker Profile |
| 164.312(c)(1) Integrity | Section 18.9 (Windows Defender) |

## Supporting References

- **Microsoft Security Baselines**: https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines
- **CIS Controls v8**: Maps to Implementation Group (IG) 1, 2, and 3 for prioritized implementation
- **STIGs (DoD)**: DISA Security Technical Implementation Guides provide overlapping but more restrictive benchmarks for government systems
- **ACSC Essential Eight**: Australian Cyber Security Centre hardening framework with overlap to CIS benchmark categories
