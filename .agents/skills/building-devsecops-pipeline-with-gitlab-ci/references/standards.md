# Standards and Compliance Reference

## OWASP DevSecOps Pipeline Maturity Model

| Level | SAST | DAST | SCA | Container | Secrets | License |
|-------|------|------|-----|-----------|---------|---------|
| Level 1 (Basic) | Manual runs | None | Manual dependency check | None | Pre-commit hooks | None |
| Level 2 (Integrated) | CI-triggered on MR | Scheduled scans | CI-triggered | Image scan on build | CI scan on commits | CI-triggered |
| Level 3 (Enforced) | Required for merge | Gate before deploy | Block on critical CVE | Block vulnerable images | Push protection | Policy enforcement |
| Level 4 (Optimized) | Custom rules, tuned FP | Authenticated full scan | Auto-remediation PRs | Signed images only | Auto-rotation | SBOM generation |

## NIST SP 800-218 (SSDF) Mapping

| SSDF Practice | GitLab Feature | Pipeline Stage |
|---------------|----------------|----------------|
| PO.1 Define security requirements | Security policies | Policy configuration |
| PW.1 Design software securely | Threat modeling integration | Pre-build |
| PW.4 Reuse well-secured software | Dependency scanning | Security stage |
| PW.5 Create source code securely | SAST, secret detection | Security stage |
| PW.7 Review and test code | MR security widget | Merge request |
| PW.8 Test executable code | DAST | Post-deploy staging |
| PW.9 Configure software securely | Container scanning | Security stage |
| RV.1 Identify vulnerabilities | Vulnerability report | Dashboard |
| RV.2 Assess and prioritize | Severity classification | Triage workflow |
| RV.3 Remediate vulnerabilities | Issue tracking integration | Sprint planning |

## CIS Software Supply Chain Security

- **SCS-1**: Secure source code management with protected branches and signed commits
- **SCS-2**: Secure build pipelines with pinned template versions and runner isolation
- **SCS-3**: Verified dependencies through dependency scanning and license compliance
- **SCS-4**: Secure artifacts with container scanning and signed images
- **SCS-5**: Deployment security with manual gates and environment approvals

## GitLab Scanner Coverage Matrix

| Vulnerability Type | Primary Scanner | Secondary Scanner |
|--------------------|-----------------|-------------------|
| SQL Injection | SAST (Semgrep) | DAST |
| XSS | SAST | DAST |
| SSRF | SAST | DAST |
| Command Injection | SAST | DAST |
| Insecure Deserialization | SAST | N/A |
| Known CVE in dependency | Dependency Scanning | Container Scanning |
| Hardcoded credentials | Secret Detection | SAST |
| License violation | License Scanning | N/A |
| OS-level CVE in image | Container Scanning | N/A |
| Authentication flaws | DAST | SAST |
