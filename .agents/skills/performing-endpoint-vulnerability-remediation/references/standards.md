# Standards & References - Performing Endpoint Vulnerability Remediation

## Primary Standards

### NIST SP 800-40 Rev 4 - Guide to Enterprise Patch Management Planning
- **Publisher**: NIST
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-40/rev-4/final
- **Scope**: Enterprise patch management lifecycle, risk-based prioritization, and operational planning

### CISA Binding Operational Directive 22-01 - Known Exploited Vulnerabilities
- **Publisher**: CISA
- **URL**: https://www.cisa.gov/binding-operational-directive-22-01
- **Scope**: Federal mandate to remediate CVEs in the Known Exploited Vulnerabilities catalog within specified timelines
- **Timelines**: Typically 14 days for internet-facing, 28 days for internal systems

### FIRST CVSS v3.1 Specification
- **Publisher**: FIRST (Forum of Incident Response and Security Teams)
- **URL**: https://www.first.org/cvss/specification-document
- **Scope**: Scoring methodology for vulnerability severity

### FIRST EPSS Model
- **Publisher**: FIRST
- **URL**: https://www.first.org/epss/
- **Scope**: Machine learning model predicting probability of CVE exploitation within 30 days

## Compliance Mappings

| Framework | Requirement | Remediation Coverage |
|-----------|------------|---------------------|
| PCI DSS 4.0 | 6.3.3 - Patch within one month of release | Patch SLA tracking and compliance |
| PCI DSS 4.0 | 11.3.1 - Internal vulnerability scans quarterly | Scan-remediate-validate cycle |
| NIST 800-53 | SI-2 Flaw Remediation | Vulnerability identification and patching |
| NIST 800-53 | RA-5 Vulnerability Monitoring and Scanning | Ongoing scan-remediate process |
| HIPAA | 164.308(a)(1)(ii)(B) - Risk Management | Vulnerability remediation as risk reduction |
| ISO 27001 | A.12.6.1 - Management of technical vulnerabilities | Systematic vulnerability remediation |
| SOC 2 | CC7.1 - Detect and address vulnerabilities | Vulnerability management program |

## Remediation SLA Benchmarks

| Severity | CVSS Range | Industry Standard SLA | CISA KEV Timeline |
|----------|-----------|----------------------|-------------------|
| Critical | 9.0-10.0 | 14 days | Per directive (usually 14 days) |
| High | 7.0-8.9 | 30 days | Per directive |
| Medium | 4.0-6.9 | 60 days | N/A unless in KEV |
| Low | 0.1-3.9 | 90 days | N/A |

## Supporting References

- **CISA KEV Catalog**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **NVD (National Vulnerability Database)**: https://nvd.nist.gov/
- **EPSS Data**: https://api.first.org/data/v1/epss
- **Microsoft Security Update Guide**: https://msrc.microsoft.com/update-guide
