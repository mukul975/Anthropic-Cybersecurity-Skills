# Standards Reference: SAST in GitHub Actions

## OWASP SAMM - Verification: Security Testing

### Maturity Level 1
- Perform automated SAST scanning with default rulesets on all application code
- Results are visible to development teams through IDE or CI/CD integration

### Maturity Level 2
- Customize SAST rules to reduce false positives below 20%
- Track and triage all findings with defined SLAs per severity
- Integrate SAST results into a centralized vulnerability management system

### Maturity Level 3
- Correlate SAST findings with DAST and SCA results for comprehensive coverage
- Measure and improve detection accuracy through benchmarking against known vulnerabilities
- Custom rules cover organization-specific vulnerability patterns and deprecated APIs

## NIST SSDF (SP 800-218) - Produce Well-Secured Software

### PW.7: Review and Analyze Code
- PW.7.1: Determine whether SAST tools should be used and select appropriate tools
- PW.7.2: Use SAST tools to analyze source code and identify vulnerabilities
- Configure tools to analyze code for compliance with secure coding standards

### PW.8: Test Executable Code
- Integration of SAST into CI/CD ensures code is tested before deployment
- Findings are tracked and remediated according to organizational policy

## CIS Software Supply Chain Security Guide

### Source Code (SC) Controls
- SC-2: Enforce branch protection requiring SAST checks to pass
- SC-3: Require code review in addition to automated scanning
- SC-4: Automate security testing in the build pipeline

### Build (BD) Controls
- BD-1: Define and enforce security requirements for build processes
- BD-2: Integrate multiple security testing tools for defense in depth

## OWASP Top 10 Coverage Matrix

| OWASP Category | CodeQL | Semgrep | Combined |
|----------------|--------|---------|----------|
| A01: Broken Access Control | Partial | Yes | Yes |
| A02: Cryptographic Failures | Yes | Yes | Yes |
| A03: Injection | Yes | Yes | Yes |
| A04: Insecure Design | No | Partial | Partial |
| A05: Security Misconfiguration | Partial | Yes | Yes |
| A06: Vulnerable Components | No | No | No (Use SCA) |
| A07: Auth Failures | Yes | Yes | Yes |
| A08: Software Integrity | No | Partial | Partial |
| A09: Logging Failures | Partial | Yes | Yes |
| A10: SSRF | Yes | Yes | Yes |

## PCI DSS v4.0 Mapping

- Requirement 6.2.4: Software engineering techniques or automated methods prevent or mitigate common software attacks
- Requirement 6.3.2: An inventory of bespoke and custom software and third-party software components is maintained
- Requirement 6.5.4: SAST tools are run as part of the software development lifecycle

## SOC 2 Trust Service Criteria

- CC7.1: Deploy detection and monitoring mechanisms for anomalies indicative of actual or attempted attacks
- CC8.1: Authorize, design, develop or acquire, configure, document, test, approve, and implement changes to infrastructure, data, software, and procedures
