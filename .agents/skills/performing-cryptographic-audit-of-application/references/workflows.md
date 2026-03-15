# Workflows - Cryptographic Audit

## Workflow 1: Automated Source Code Scan

```
[Target Application Source]
      |
[Scan for Crypto Patterns]:
  - Deprecated algorithms (MD5, SHA-1, DES, RC4)
  - Insecure modes (ECB)
  - Hardcoded secrets (keys, passwords, tokens)
  - Weak KDF parameters
  - Insecure random number generation
      |
[Scan Configuration Files]:
  - TLS/SSL settings
  - Cipher suite configurations
  - Certificate paths and validity
      |
[Generate Findings with Severity]
      |
[Produce Audit Report]
```

## Workflow 2: Manual Crypto Review

```
[Identify All Crypto Touchpoints]:
  - Encryption/decryption operations
  - Hashing operations
  - Key generation and storage
  - TLS/SSL connections
  - Token generation (JWT, API keys)
  - Password handling
      |
[For Each Touchpoint]:
  [Verify algorithm choice]
  [Verify mode/padding]
  [Verify key management]
  [Verify entropy sources]
  [Verify error handling]
      |
[Document Findings]
```

## Workflow 3: Remediation Prioritization

```
[All Findings]
      |
[Classify by Severity]:
  CRITICAL: Hardcoded keys, broken encryption
  HIGH: Weak algorithms, ECB mode, weak KDF
  MEDIUM: Short key sizes, deprecated protocols
  LOW: Missing best practices, informational
      |
[Prioritize by Risk]:
  1. CRITICAL findings (immediate fix)
  2. HIGH findings (fix in current sprint)
  3. MEDIUM findings (plan for next release)
  4. LOW findings (backlog)
```
