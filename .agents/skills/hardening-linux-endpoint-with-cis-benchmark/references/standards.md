# Standards & References

## Primary Standards
- **CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0**: https://www.cisecurity.org/benchmark/ubuntu_linux
- **CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0**: https://www.cisecurity.org/benchmark/red_hat_linux
- **NIST SP 800-123**: Guide to General Server Security
- **DISA STIG**: Security Technical Implementation Guide for RHEL/Ubuntu

## Compliance Mappings
| Framework | Requirement | Linux Hardening Coverage |
|-----------|------------|------------------------|
| PCI DSS 4.0 | 2.2 - Configuration standards | CIS benchmark application |
| NIST 800-53 | CM-6 Configuration Settings | Kernel, service, and auth hardening |
| NIST 800-53 | AU-2 Audit Events | auditd configuration |
| HIPAA | 164.312(a)(1) Access Control | SSH hardening, PAM configuration |

## Supporting References
- **Ansible Lockdown**: https://github.com/ansible-lockdown
- **OpenSCAP**: https://www.open-scap.org/
- **Lynis**: https://cisofy.com/lynis/
- **SCAP Security Guide**: https://github.com/ComplianceAsCode/content
