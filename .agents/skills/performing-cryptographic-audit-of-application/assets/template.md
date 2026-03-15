# Cryptographic Audit Report Template

## Executive Summary

| Metric | Value |
|--------|-------|
| Target | [Application Name] |
| Scan Date | [Date] |
| Overall Risk | [CRITICAL/HIGH/MEDIUM/LOW] |
| Total Findings | [Count] |
| Critical | [Count] |
| High | [Count] |
| Medium | [Count] |
| Low | [Count] |

## Audit Scope

- [ ] Source code review (Python, JavaScript, Java, Go)
- [ ] Configuration file review (YAML, JSON, INI)
- [ ] TLS/SSL configuration assessment
- [ ] Key management practices review
- [ ] Dependency vulnerability check
- [ ] Deployed infrastructure scan

## Approved Algorithms

| Purpose | Approved | Deprecated |
|---------|----------|-----------|
| Hashing (integrity) | SHA-256, SHA-3 | MD5, SHA-1 |
| Password hashing | Argon2id, bcrypt, scrypt | MD5, SHA-1, plain SHA-256 |
| Symmetric encryption | AES-256-GCM, ChaCha20-Poly1305 | DES, 3DES, RC4, Blowfish |
| Asymmetric encryption | RSA-OAEP (3072+), ECIES | RSA-PKCS1v15 |
| Digital signatures | Ed25519, RSA-PSS (3072+), ECDSA (P-256+) | RSA-PKCS1v15 |
| Key exchange | X25519, ECDH (P-256+), DH (3072+) | DH (1024) |
| TLS | TLS 1.2 (approved ciphers), TLS 1.3 | SSLv3, TLS 1.0, TLS 1.1 |

## Finding Template

```
### Finding F-001: [Title]

**Severity**: CRITICAL / HIGH / MEDIUM / LOW
**Category**: [Category]
**CWE**: [CWE-XXX]
**File**: [file_path:line_number]

**Description**:
[Description of the vulnerability]

**Code**:
[Code snippet]

**Remediation**:
[Steps to fix]

**References**:
- [NIST/OWASP reference]
```

## Remediation Priority

1. CRITICAL: Hardcoded secrets, broken encryption (fix immediately)
2. HIGH: Weak algorithms, insecure modes (fix in current sprint)
3. MEDIUM: Suboptimal parameters, deprecated protocols (next release)
4. LOW: Informational, best practice improvements (backlog)
