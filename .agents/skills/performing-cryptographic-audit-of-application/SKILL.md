---
name: performing-cryptographic-audit-of-application
description: A cryptographic audit systematically reviews an application's use of cryptographic primitives, protocols, and key management to identify vulnerabilities such as weak algorithms, insecure modes, hardco
domain: cybersecurity
subdomain: cryptography
tags: [cryptography, audit, security-review, compliance, vulnerability-assessment]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing Cryptographic Audit of Application

## Overview

A cryptographic audit systematically reviews an application's use of cryptographic primitives, protocols, and key management to identify vulnerabilities such as weak algorithms, insecure modes, hardcoded keys, insufficient entropy, and protocol misconfigurations. This skill covers building an automated crypto audit tool that scans Python and configuration files for common cryptographic weaknesses.

## Objectives

- Detect usage of deprecated algorithms (MD5, SHA-1, DES, RC4)
- Identify insecure cipher modes (ECB) and padding schemes
- Find hardcoded keys, passwords, and secrets in source code
- Verify TLS/SSL configuration strength
- Check key derivation function parameters
- Validate random number generator usage
- Produce a structured audit report with findings and remediation

## Key Concepts

### Cryptographic Weakness Categories

| Category | Examples | Risk Level |
|----------|----------|------------|
| Weak Hashing | MD5, SHA-1 for integrity/signatures | High |
| Insecure Encryption | DES, 3DES, RC4, Blowfish | High |
| Bad Cipher Mode | ECB mode for any block cipher | High |
| Insufficient Key Size | RSA < 2048, AES-128 for long-term | Medium |
| Hardcoded Secrets | Keys/passwords in source code | Critical |
| Weak KDF | Low iteration PBKDF2, plain MD5 | High |
| Poor Entropy | time-based seeds, predictable IVs | High |
| Deprecated Protocols | SSLv3, TLS 1.0, TLS 1.1 | High |

## Security Considerations

- Review both application code and configuration files
- Check third-party dependencies for known crypto vulnerabilities
- Verify certificates and TLS configurations on deployed servers
- Ensure secrets are loaded from environment variables or vaults
- Review key storage and rotation practices

## Validation Criteria

- [ ] Scanner detects all injected test weaknesses
- [ ] MD5/SHA-1 usage for security purposes is flagged
- [ ] ECB mode usage is flagged
- [ ] Hardcoded keys/passwords are detected
- [ ] Weak KDF parameters are identified
- [ ] Report includes severity, location, and remediation
- [ ] False positive rate is below 10%
