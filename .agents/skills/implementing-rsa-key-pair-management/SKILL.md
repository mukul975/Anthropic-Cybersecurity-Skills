---
name: implementing-rsa-key-pair-management
description: RSA (Rivest-Shamir-Adleman) is the most widely deployed asymmetric cryptographic algorithm, used for digital signatures, key exchange, and encryption. This skill covers generating, storing, rotating, 
domain: cybersecurity
subdomain: cryptography
tags: [cryptography, rsa, key-management, pki, asymmetric-encryption]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Implementing RSA Key Pair Management

## Overview

RSA (Rivest-Shamir-Adleman) is the most widely deployed asymmetric cryptographic algorithm, used for digital signatures, key exchange, and encryption. This skill covers generating, storing, rotating, and managing RSA key pairs following NIST SP 800-57 key management guidelines, including key serialization formats (PEM, DER, PKCS#8), passphrase protection, and key strength validation.

## Objectives

- Generate RSA key pairs with appropriate key sizes (2048, 3072, 4096 bits)
- Serialize keys in PEM and DER formats with PKCS#8
- Protect private keys with strong passphrase encryption
- Implement key rotation with versioning
- Extract public key components and fingerprints
- Validate key strength and detect weak keys
- Sign and verify data using RSA-PSS

## Key Concepts

### RSA Key Sizes and Security Strength

| Key Size (bits) | Security Strength (bits) | Recommended Until |
|-----------------|-------------------------|-------------------|
| 2048            | 112                     | 2030              |
| 3072            | 128                     | Beyond 2030       |
| 4096            | ~140                    | Beyond 2030       |

### RSA Padding Schemes

| Scheme | Use Case | Standard |
|--------|----------|----------|
| OAEP   | Encryption | PKCS#1 v2.2 (RFC 8017) |
| PSS    | Signatures | PKCS#1 v2.2 (RFC 8017) |
| PKCS#1 v1.5 | Legacy only | Deprecated for new systems |

### Key Storage Formats

- **PEM**: Base64-encoded with headers, human-readable
- **DER**: Binary ASN.1 encoding, compact
- **PKCS#8**: Standard for private key encapsulation
- **PKCS#12/PFX**: Bundled key + certificate, password-protected

## Security Considerations

- Minimum 3072-bit keys for new deployments (NIST recommendation)
- Always protect private keys with AES-256-CBC passphrase encryption
- Use RSA-PSS for signatures (not PKCS#1 v1.5)
- Use RSA-OAEP for encryption (not PKCS#1 v1.5)
- Store private keys with restrictive file permissions (0600)
- Implement key rotation at least annually

## Validation Criteria

- [ ] Key generation produces valid RSA key pair
- [ ] Public key can be extracted from private key
- [ ] Private key is protected with passphrase
- [ ] RSA-PSS signature verification succeeds
- [ ] Tampered signature verification fails
- [ ] Key fingerprint is computed correctly
- [ ] Key rotation maintains old key access for verification
