# Standards and References - CVSS Scoring

## Official CVSS Documentation
- CVSS v4.0 Specification: https://www.first.org/cvss/specification-document
- CVSS v4.0 User Guide: https://www.first.org/cvss/v4.0/user-guide
- CVSS v4.0 Calculator: https://www.first.org/cvss/calculator/4.0
- NVD CVSS v4 Calculator: https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator
- Red Hat CVSS v4 Calculator: https://github.com/RedHatProductSecurity/cvss-v4-calculator

## Complementary Scoring Systems
- EPSS (Exploit Prediction): https://www.first.org/epss/
- SSVC (Stakeholder-Specific): https://www.cisa.gov/ssvc
- CISA KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

## Industry Standards
- **NIST SP 800-40 Rev 4**: Guide to Enterprise Patch Management Planning
- **NIST NVD**: National Vulnerability Database uses CVSS for all CVEs
- **PCI DSS v4.0**: Requires CVSS scoring for vulnerability prioritization
- **ISO 27001:2022 A.8.8**: Technical vulnerability management

## CVSS v4.0 vs v3.1 Key Differences
| Feature | CVSS v3.1 | CVSS v4.0 |
|---------|-----------|-----------|
| Metric Groups | 3 (Base, Temporal, Environmental) | 4 (Base, Threat, Environmental, Supplemental) |
| Attack Requirements | N/A | New metric (AT) |
| User Interaction | None/Required | None/Passive/Active |
| Scope | Changed/Unchanged | Replaced by Subsequent System metrics |
| Temporal -> Threat | Report Confidence, RL, E | Only Exploit Maturity |
| Supplemental | N/A | Safety, Automatable, Recovery, etc. |

## Severity Thresholds
| Rating | CVSS v3.1 | CVSS v4.0 |
|--------|-----------|-----------|
| None | 0.0 | 0.0 |
| Low | 0.1 - 3.9 | 0.1 - 3.9 |
| Medium | 4.0 - 6.9 | 4.0 - 6.9 |
| High | 7.0 - 8.9 | 7.0 - 8.9 |
| Critical | 9.0 - 10.0 | 9.0 - 10.0 |
