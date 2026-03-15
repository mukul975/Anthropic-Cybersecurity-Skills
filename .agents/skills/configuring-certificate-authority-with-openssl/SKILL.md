---
name: configuring-certificate-authority-with-openssl
description: A Certificate Authority (CA) is the trust anchor in a PKI hierarchy, responsible for issuing, signing, and revoking digital certificates. This skill covers building a two-tier CA hierarchy (Root CA + 
domain: cybersecurity
subdomain: cryptography
tags: [cryptography, pki, certificate-authority, openssl, x509]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Configuring Certificate Authority with OpenSSL

## Overview

A Certificate Authority (CA) is the trust anchor in a PKI hierarchy, responsible for issuing, signing, and revoking digital certificates. This skill covers building a two-tier CA hierarchy (Root CA + Intermediate CA) using OpenSSL and the Python cryptography library, including CRL distribution, OCSP responder configuration, and certificate policy management.

## Objectives

- Create a Root CA with self-signed certificate
- Create an Intermediate CA signed by the Root CA
- Issue server and client certificates from the Intermediate CA
- Configure Certificate Revocation Lists (CRLs)
- Implement certificate policies and constraints
- Build a complete PKI hierarchy programmatically

## Key Concepts

### CA Hierarchy

```
Root CA (offline, air-gapped)
  |
  +-- Intermediate CA (online, operational)
        |
        +-- Server Certificates
        +-- Client Certificates
        +-- Code Signing Certificates
```

### Certificate Extensions

| Extension | Purpose | Critical |
|-----------|---------|----------|
| basicConstraints | CA:TRUE/FALSE, pathLenConstraint | Yes |
| keyUsage | keyCertSign, cRLSign, digitalSignature | Yes |
| extendedKeyUsage | serverAuth, clientAuth, codeSigning | No |
| subjectKeyIdentifier | Hash of public key | No |
| authorityKeyIdentifier | Issuer's key identifier | No |
| crlDistributionPoints | URL to CRL | No |
| authorityInfoAccess | OCSP responder URL | No |

## Security Considerations

- Root CA private key must be stored offline (air-gapped HSM)
- Use minimum 4096-bit RSA or P-384 ECDSA for CA keys
- Set path length constraints on intermediate CAs
- Implement certificate policies (OIDs)
- Enable CRL and OCSP for revocation checking
- Audit all certificate issuance operations

## Validation Criteria

- [ ] Root CA self-signed certificate is valid
- [ ] Intermediate CA certificate chains to Root CA
- [ ] Issued certificates chain to Intermediate -> Root
- [ ] Path length constraints are enforced
- [ ] CRL is generated and accessible
- [ ] Revoked certificates appear in CRL
- [ ] Certificate policies are correctly embedded
