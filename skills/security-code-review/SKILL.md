---
name: security-code-review
description:
  Reviews code for security vulnerabilities and OWASP risks. Use when reviewing code changes, assessing security, or
  validating secure coding practices. Focuses on OWASP Top 10 and CWE.
domain: cybersecurity
subdomain: web-application-security
tags: [owasp, cwe, code-review, appsec, secure-coding]
version: "1.0"
author: HRD-Security
license: Apache-2.0
---

# Security Code Review Skill

## Overview

You are an expert application security engineer performing security-focused code reviews.
This skill covers identification and remediation of common application security vulnerabilities
aligned with OWASP Top 10, CWE/SANS Top 25, and language-specific secure coding best practices.

## Prerequisites

- Access to source code repositories
- Familiarity with OWASP Top 10 and CWE classification
- Understanding of the application's technology stack and language

## Key Concepts

### Core Expertise

- **OWASP Top 10**: Web application security risks
- **CWE/SANS Top 25**: Most dangerous software errors
- **Secure Coding**: Language-specific best practices
- **Gaming Security**: Payment processing, account security, fraud prevention

## Practical Steps

### Review Categories

#### 1. Injection Vulnerabilities

- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- LDAP Injection (CWE-90)
- XPath Injection (CWE-91)
- NoSQL Injection

**Look for**: String concatenation in queries, user input in commands

#### 2. Authentication & Session

- Broken Authentication (CWE-287)
- Session Fixation (CWE-384)
- Weak Password Requirements
- Missing MFA implementation

**Look for**: Session handling, credential storage, auth bypass

#### 3. Authorization

- Broken Access Control (CWE-862)
- IDOR (Insecure Direct Object Reference)
- Privilege Escalation
- Missing function-level access control

**Look for**: Authorization checks, object ownership validation

#### 4. Sensitive Data

- Sensitive Data Exposure (CWE-200)
- Hardcoded Secrets (CWE-798)
- Logging sensitive data
- PII/PCI data handling

**Look for**: API keys, passwords, tokens, PII in logs

#### 5. Input Validation

- Cross-Site Scripting (CWE-79)
- XML External Entities (CWE-611)
- Server-Side Request Forgery (CWE-918)
- Path Traversal (CWE-22)

**Look for**: Input sanitization, output encoding, URL validation

#### 6. Cryptography

- Weak Cryptography (CWE-327)
- Insufficient Key Size
- Insecure Random (CWE-330)
- Missing encryption

**Look for**: Crypto algorithms, key management, TLS configuration

#### 7. Error Handling

- Information Leakage (CWE-209)
- Improper Error Handling
- Stack traces in responses

**Look for**: Exception handling, error messages, debug info

### Gaming-Specific Checks

#### Payment Processing

- [ ] PCI DSS compliance
- [ ] Card data never logged
- [ ] Tokenization used
- [ ] Secure payment redirects

#### Account Security

- [ ] Account enumeration prevention
- [ ] Rate limiting on auth endpoints
- [ ] Password reset security
- [ ] Session invalidation

#### Fraud Prevention

- [ ] Velocity checks
- [ ] Duplicate transaction prevention
- [ ] Geolocation validation
- [ ] Bonus abuse prevention

#### Wagering Integrity

- [ ] Odds validation
- [ ] Bet slip integrity
- [ ] Transaction atomicity
- [ ] Audit trail completeness

## Verification

### Output Format

````markdown
## Security Code Review Finding

**Finding ID**: SEC-YYYY-NNN **Severity**: Critical/High/Medium/Low **CWE**: CWE-XXX **OWASP**: A01-A10

### Location

- File: `path/to/file.java`
- Line: XXX-XXX

### Description

[What the vulnerability is]

### Impact

[What could happen if exploited]

### Vulnerable Code

```language
[Code snippet]
```

### Recommended Fix

```language
[Fixed code snippet]
```

### References

- [OWASP link]
- [CWE link]
````
