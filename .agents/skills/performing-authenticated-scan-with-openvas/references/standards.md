# Standards and References - Authenticated Scanning with OpenVAS

## Primary Standards

### NIST SP 800-115
- **Title**: Technical Guide to Information Security Testing and Assessment
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-115/final
- **Relevance**: Defines vulnerability scanning methodologies including credentialed vs non-credentialed approaches

### NIST SP 800-53 Rev 5 - RA-5
- **Title**: Vulnerability Monitoring and Scanning
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- **Requirement**: Organizations must scan for vulnerabilities in information systems and hosted applications with both authenticated and unauthenticated methods

### CIS Controls v8 - Control 7
- **Title**: Continuous Vulnerability Management
- **URL**: https://www.cisecurity.org/controls/continuous-vulnerability-management
- **Sub-controls**:
  - 7.1: Establish and maintain a vulnerability management process
  - 7.4: Perform authenticated vulnerability scanning with agents or credentialed scans
  - 7.5: Perform automated vulnerability scans of internal enterprise assets on a quarterly basis

### PCI DSS v4.0 - Requirement 11.3
- **Title**: External and Internal Vulnerabilities Are Regularly Identified, Prioritized, and Addressed
- **Requirement**: Internal vulnerability scans must be performed at least quarterly and after any significant change; authenticated scanning is required for comprehensive assessment

## OpenVAS/GVM Technical References

### Greenbone Community Edition
- **URL**: https://greenbone.github.io/docs/latest/
- **Components**: gvmd (manager), openvas-scanner, gsad (web UI), ospd-openvas
- **Feed**: Greenbone Community Feed with 180,000+ NVT checks

### GVM Architecture
- **Scanner**: openvas-scanner performs the actual vulnerability tests
- **Manager**: gvmd manages scan tasks, credentials, targets, and results
- **Web Interface**: Greenbone Security Assistant (GSA) provides browser-based management
- **Database**: PostgreSQL stores configurations and results
- **Cache**: Redis provides high-speed NVT metadata caching

### python-gvm Library
- **URL**: https://github.com/greenbone/python-gvm
- **PyPI**: https://pypi.org/project/python-gvm/
- **Documentation**: https://python-gvm.readthedocs.io/

### GMP Protocol
- **Title**: Greenbone Management Protocol
- **URL**: https://docs.greenbone.net/API/GMP/gmp-22.04.html
- **Purpose**: XML-based protocol for programmatic interaction with gvmd

## Compliance Mapping

| Framework | Control | Authenticated Scan Requirement |
|-----------|---------|-------------------------------|
| NIST 800-53 | RA-5 | Credentialed scanning for host-level assessment |
| PCI DSS 4.0 | 11.3.1 | Internal vulnerability scanning quarterly |
| CIS Controls v8 | 7.4 | Authenticated vulnerability scanning |
| ISO 27001 | A.8.8 | Technical vulnerability management |
| HIPAA | 164.312(a)(1) | Technical safeguards evaluation |
| SOC 2 | CC7.1 | Vulnerability identification and remediation |
