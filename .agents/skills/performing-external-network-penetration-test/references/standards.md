# Standards and Frameworks — External Network Penetration Testing

## Primary Standards

### PTES (Penetration Testing Execution Standard)
- Website: http://www.pentest-standard.org/
- Phases: Pre-engagement, Intelligence Gathering, Threat Modeling, Vulnerability Analysis, Exploitation, Post-Exploitation, Reporting
- Best for: Comprehensive network penetration testing engagements

### NIST SP 800-115
- Title: Technical Guide to Information Security Testing and Assessment
- URL: https://csrc.nist.gov/publications/detail/sp/800-115/final
- Covers: Review techniques, target identification, vulnerability analysis, planning, execution, post-testing

### OSSTMM v3 (Open Source Security Testing Methodology Manual)
- URL: https://www.isecom.org/OSSTMM.3.pdf
- Focus: Operational security testing across physical, wireless, telecommunications, data networks, and human channels

### OWASP Testing Guide v4.2
- URL: https://owasp.org/www-project-web-security-testing-guide/
- Focus: Web application security testing methodology
- Complement to network-level testing

## Compliance Frameworks

| Framework | Requirement | Pentest Frequency |
|-----------|------------|-------------------|
| PCI DSS v4.0 | Requirement 11.4 | Annual + after significant changes |
| SOC 2 Type II | CC7.1 | Annual |
| ISO 27001 | A.12.6, A.18.2 | Annual recommended |
| HIPAA | §164.308(a)(8) | Annual recommended |
| FedRAMP | CA-8 | Annual |

## CVSS v3.1 Scoring Reference

| Metric Group | Components |
|-------------|-----------|
| Base Score | Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, Confidentiality, Integrity, Availability |
| Temporal Score | Exploit Code Maturity, Remediation Level, Report Confidence |
| Environmental Score | Modified Base Metrics, Security Requirements |

Calculator: https://www.first.org/cvss/calculator/3.1

## CVE and Vulnerability Databases

- NVD (National Vulnerability Database): https://nvd.nist.gov/
- CVE: https://cve.mitre.org/
- Exploit-DB: https://www.exploit-db.com/
- VulnDB: https://vuldb.com/
