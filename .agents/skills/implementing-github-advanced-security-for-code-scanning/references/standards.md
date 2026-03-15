# Standards and Frameworks Reference

## OWASP Top 10 (2021) Coverage by CodeQL

| OWASP Category | CodeQL CWE Coverage | Query Suite |
|----------------|---------------------|-------------|
| A01 Broken Access Control | CWE-22, CWE-284, CWE-639 | security-extended |
| A02 Cryptographic Failures | CWE-259, CWE-327, CWE-328 | security-extended |
| A03 Injection | CWE-77, CWE-78, CWE-79, CWE-89 | default |
| A04 Insecure Design | CWE-209, CWE-256, CWE-501 | security-and-quality |
| A05 Security Misconfiguration | CWE-16, CWE-611 | security-extended |
| A06 Vulnerable Components | Dependency Review / Dependabot | N/A (separate feature) |
| A07 Auth Failures | CWE-287, CWE-798 | default |
| A08 Data Integrity Failures | CWE-502, CWE-829 | security-extended |
| A09 Logging Failures | CWE-117, CWE-778 | security-and-quality |
| A10 SSRF | CWE-918 | default |

## NIST SP 800-218 (SSDF) Alignment

- **PO.3**: Define security requirements --- CodeQL enforces security policies through query suites
- **PW.4**: Reuse existing, well-secured software --- Dependabot ensures dependencies are patched
- **PW.7**: Review and test code for vulnerabilities --- Automated code scanning on every PR
- **PW.8**: Test executable code --- SARIF integration enables combining SAST with DAST results
- **RV.1**: Identify and confirm vulnerabilities --- Security overview tracks alerts across the organization

## CIS Software Supply Chain Security Guide

- **SCS-1**: Source code management security --- Branch protection rules, required reviewers
- **SCS-2**: Build pipelines --- CodeQL runs in GitHub Actions with pinned action versions
- **SCS-5**: Artifact management --- Dependency review prevents vulnerable packages from merging

## ISO 27001 Control Mapping

| ISO 27001 Control | GHAS Feature |
|--------------------|--------------|
| A.8.25 Secure development lifecycle | CodeQL in CI/CD pipeline |
| A.8.26 Application security requirements | Custom query packs for org standards |
| A.8.28 Secure coding | Real-time scanning on pull requests |
| A.8.29 Security testing in dev and acceptance | Required status checks with severity gates |
| A.8.31 Separation of environments | Branch protection and deployment rules |
