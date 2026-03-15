# Standards Reference: Secret Scanning with Gitleaks

## OWASP Top 10 - A07:2021 Identification and Authentication Failures

- Hardcoded credentials in source code enable unauthorized access
- Gitleaks detects API keys, passwords, tokens, and private keys before they reach repositories
- CWE-798: Use of Hard-coded Credentials is a direct mapping

## NIST SSDF (SP 800-218)

### PW.1: Design Software to Meet Security Requirements
- PW.1.1: Identify security requirements including credential management
- Secrets should never be stored in source code; use environment variables or secrets managers

### PS.1: Protect All Forms of Code
- PS.1.1: Store code securely with access controls and secret scanning
- Implement pre-commit hooks to prevent secrets from entering version control

### PS.2: Provide a Mechanism for Verifying Software Release Integrity
- Code signing and secret scanning ensure software releases do not contain embedded credentials

## CIS Software Supply Chain Security Guide

### Source Code Controls
- SC-1: Automated secret scanning on all commits
- SC-5: No hardcoded credentials in source repositories
- SC-6: Secrets detection integrated into CI/CD pipeline

## OWASP SAMM - Secure Build

### Maturity Level 1
- Scan repositories for common secret patterns using default rulesets
- Alert developers when secrets are detected in pull requests

### Maturity Level 2
- Custom rules for organization-specific secret patterns
- Pre-commit hooks prevent secrets from entering history
- Baseline management for legacy codebases

### Maturity Level 3
- Automated secret rotation workflow triggered by detection
- Correlation with secrets management systems for validation
- Historical scanning with git-filter-repo remediation

## PCI DSS v4.0

- Requirement 6.3.1: Security vulnerabilities identified through a defined process including code analysis
- Requirement 8.6.1: Secrets stored in code or configuration files must be protected
- Requirement 8.6.3: Passwords/passphrases for application and system accounts are protected against misuse

## SOC 2 Trust Service Criteria

- CC6.1: Logical access security over protected information assets including credential management
- CC6.7: Restrict transmission of data to authorized external parties (prevent credential leakage)
