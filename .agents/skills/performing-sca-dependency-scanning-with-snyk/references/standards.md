# Standards Reference: SCA Dependency Scanning with Snyk

## OWASP Top 10 - A06:2021 Vulnerable and Outdated Components

- Applications using components with known vulnerabilities may be exploitable
- SCA tools like Snyk identify vulnerable versions and provide upgrade paths
- Includes both direct and transitive dependency scanning

## NIST SSDF (SP 800-218)

### PW.4: Reuse Existing, Well-Secured Software
- PW.4.1: Verify that acquired software meets security requirements
- PW.4.2: Review, analyze, and test software to identify vulnerabilities
- SCA scanning of all third-party components before integration

### PW.4.4: Maintain Provenance Data
- Track the origin and version of all third-party software components
- Snyk monitor provides continuous tracking of dependency versions

## CIS Software Supply Chain Security

### Dependencies (DP) Controls
- DP-1: Pin dependencies to specific versions
- DP-2: Automate dependency vulnerability scanning in CI/CD
- DP-3: Review and approve new dependency additions
- DP-4: Monitor deployed dependencies for newly disclosed vulnerabilities

## OWASP SAMM - Software Security

### Security Testing - Maturity Level 1
- Automated dependency scanning using default configurations
- Visibility of vulnerable components to development teams

### Security Testing - Maturity Level 2
- Custom policies for severity thresholds and license compliance
- Automated fix PRs for upgradable vulnerabilities
- Tracking of exploit maturity to prioritize remediation

### Security Testing - Maturity Level 3
- Reachability analysis to identify actually exploitable vulnerabilities
- Integration with vulnerability management for SLA tracking
- Correlation with runtime monitoring for risk-based prioritization

## PCI DSS v4.0

- 6.2.4: Use automated methods to prevent common software attacks
- 6.3.2: Maintain an inventory of custom and third-party software components
- 6.3.3: Software components not needed for operation removed or identified

## Executive Order 14028 (US Federal)

- Section 4(e): Agencies shall employ automated tools for continuous monitoring of vulnerabilities in software
- SBOM requirement: All software suppliers must provide SBOMs listing all components including open-source
- Aligns with Snyk's SBOM generation and continuous monitoring capabilities

## License Compliance Framework

| License Type | Risk Level | Policy | Examples |
|--------------|------------|--------|----------|
| Permissive | Low | Auto-approve | MIT, BSD-2, BSD-3, ISC, Apache-2.0 |
| Weak Copyleft | Medium | Review | LGPL-2.1, LGPL-3.0, MPL-2.0 |
| Strong Copyleft | High | Restrict | GPL-2.0, GPL-3.0, AGPL-3.0 |
| Unknown/Custom | High | Manual Review | Proprietary, SSPL, BSL |
