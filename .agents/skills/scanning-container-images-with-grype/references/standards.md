# Standards and References - Container Image Scanning with Grype

## Industry Standards

### NIST SP 800-190: Application Container Security Guide
- Section 4.1: Image vulnerabilities - Recommends scanning images for known vulnerabilities before deployment
- Section 4.2: Image configuration defects - Covers misconfigurations in container images
- Recommends integrating vulnerability scanning into CI/CD pipelines

### CIS Docker Benchmark v1.6
- Rule 4.1: Ensure a user for the container has been created
- Rule 4.6: Add HEALTHCHECK instruction to the container image
- Rule 4.9: Ensure that COPY is used instead of ADD
- Rule 4.10: Ensure secrets are not stored in Dockerfiles

### NIST SP 800-53 Rev 5
- RA-5: Vulnerability Monitoring and Scanning
- SI-2: Flaw Remediation
- CM-6: Configuration Settings
- SA-11: Developer Security Testing and Evaluation

### OWASP Container Security
- VS-001: Vulnerability Scanning - Scan container images for known vulnerabilities
- VS-002: SBOM Generation - Generate and maintain software bill of materials
- VS-003: Base Image Selection - Use minimal, trusted base images

## Vulnerability Databases

| Database | URL | Update Frequency |
|----------|-----|-----------------|
| NVD (National Vulnerability Database) | https://nvd.nist.gov/ | Continuous |
| GitHub Advisory Database | https://github.com/advisories | Continuous |
| OSV (Open Source Vulnerabilities) | https://osv.dev/ | Continuous |
| Alpine SecDB | https://secdb.alpinelinux.org/ | Daily |
| Debian Security Tracker | https://security-tracker.debian.org/ | Daily |

## CVSS Scoring Reference

| Severity | CVSS v3.1 Score | Recommended Action |
|----------|-----------------|-------------------|
| Critical | 9.0 - 10.0 | Block deployment, immediate remediation |
| High | 7.0 - 8.9 | Block deployment in production |
| Medium | 4.0 - 6.9 | Track and remediate within SLA |
| Low | 0.1 - 3.9 | Accept risk or remediate in next cycle |
| None | 0.0 | Informational |

## Compliance Mappings

### PCI DSS v4.0
- Requirement 6.3.1: Identify and manage security vulnerabilities
- Requirement 6.3.3: Update system components to address known vulnerabilities

### SOC 2
- CC7.1: To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in the introduction of new vulnerabilities

### FedRAMP
- RA-5(2): Update the vulnerabilities scanned within every 30 days prior to a new scan
- RA-5(5): Implement privileged access authorization for vulnerability scanning activities
