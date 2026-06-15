---
name: performing-post-quantum-cryptography-migration
description: 'Assesses organizational readiness for post-quantum cryptography migration
  per NIST FIPS 203/204/205 standards. Performs cryptographic inventory scanning to
  identify quantum-vulnerable algorithms (RSA, ECDH, ECDSA), evaluates hybrid TLS
  configurations with X25519MLKEM768, and validates CRYSTALS-Kyber (ML-KEM) and CRYSTALS-Dilithium
  (ML-DSA) readiness. Implements crypto-agility assessment using oqs-provider for
  OpenSSL. Use when planning or executing the transition from classical to post-quantum
  cryptographic algorithms across enterprise infrastructure.

  '
domain: cybersecurity
subdomain: cryptography
tags:
- post-quantum
- PQC
- CRYSTALS-Kyber
- ML-KEM
- ML-DSA
- FIPS-203
- FIPS-204
- hybrid-TLS
- crypto-agility
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
- PR.DS-01
- PR.DS-02
- PR.DS-10
mitre_attack:
- T1600
- T1573
- T1553
- T1040
---

# Performing Post-Quantum Cryptography Migration

## When to Use

- When assessing organizational readiness for the NIST post-quantum cryptography transition
- When building a cryptographic inventory to identify quantum-vulnerable algorithms across infrastructure
- When evaluating hybrid TLS 1.3 configurations using X25519MLKEM768 key exchange
- When testing CRYSTALS-Kyber (ML-KEM) and CRYSTALS-Dilithium (ML-DSA) algorithm support
- When implementing crypto-agility to support both classical and post-quantum algorithms
- When preparing migration roadmaps aligned with NIST IR 8547 deprecation timelines
- When configuring oqs-provider with OpenSSL 3.x for post-quantum algorithm support

## Prerequisites

- Python 3.8+ with `cryptography`, `requests`, `pyOpenSSL` libraries
- OpenSSL 3.0+ (3.5+ recommended for native ML-KEM/ML-DSA support)
- oqs-provider for OpenSSL (for hybrid TLS testing with older OpenSSL)
- Network access to target servers for TLS assessment
- Administrative access for infrastructure scanning
- Familiarity with PKI, TLS, and cryptographic protocols

## Core Concepts

### NIST Post-Quantum Cryptography Standards

NIST published three finalized PQC standards on August 13, 2024:

| Standard | Algorithm | Renamed To | Purpose | Based On |
|----------|-----------|------------|---------|----------|
| FIPS 203 | CRYSTALS-Kyber | ML-KEM | Key Encapsulation Mechanism | Module lattice |
| FIPS 204 | CRYSTALS-Dilithium | ML-DSA | Digital Signatures | Module lattice |
| FIPS 205 | SPHINCS+ | SLH-DSA | Digital Signatures (backup) | Stateless hash |

**ML-KEM (FIPS 203)** -- Primary standard for key exchange and encryption. Replaces
RSA and ECDH for key establishment. Three security levels: ML-KEM-512, ML-KEM-768,
ML-KEM-1024.

**ML-DSA (FIPS 204)** -- Primary standard for digital signatures. Replaces RSA and
ECDSA for signing. Three security levels: ML-DSA-44, ML-DSA-65, ML-DSA-87.

**SLH-DSA (FIPS 205)** -- Backup signature standard using hash-based approach. Intended
as fallback if lattice-based ML-DSA is found vulnerable. Larger signatures but
conservative security assumptions.

### Quantum-Vulnerable Algorithms

These classical algorithms are vulnerable to quantum attack via Shor's algorithm:

| Algorithm | Usage | Quantum Threat | Migration Priority |
|-----------|-------|---------------|-------------------|
| RSA-2048/4096 | Key exchange, signatures, encryption | Shor's algorithm breaks factoring | Critical |
| ECDH (P-256, P-384) | TLS key exchange | Shor's algorithm breaks ECDLP | Critical |
| ECDSA | Code signing, TLS certificates | Shor's algorithm breaks ECDLP | Critical |
| DSA | Legacy signatures | Shor's algorithm breaks DLP | Critical |
| DH (Diffie-Hellman) | Key exchange | Shor's algorithm breaks DLP | Critical |
| AES-128 | Symmetric encryption | Grover's halves key strength | Medium (upgrade to AES-256) |
| SHA-256 | Hashing | Grover's reduces to 128-bit | Low (still adequate) |

### NIST Migration Timeline (IR 8547)

- **2024**: Standards published, migration planning should begin
- **2030**: Deprecation of quantum-vulnerable algorithms for most federal systems
- **2035**: Complete removal of quantum-vulnerable algorithms from NIST standards
- **Now**: "Harvest now, decrypt later" attacks make early migration essential for
  long-lived secrets and data requiring long-term confidentiality

### Hybrid TLS Key Exchange

During the transition period, hybrid key exchange combines a classical algorithm with
a post-quantum algorithm. If either algorithm is secure, the connection remains protected.

```
Hybrid Key Exchange: X25519MLKEM768
  = X25519 (classical ECDH) + ML-KEM-768 (post-quantum)

Client Hello:
  supported_groups: X25519MLKEM768, X25519, secp256r1
  key_share: X25519MLKEM768

Server Hello:
  selected_group: X25519MLKEM768
  key_share: X25519MLKEM768

Shared Secret = KDF(X25519_shared || MLKEM768_shared)
```

## Instructions

### Phase 1: Cryptographic Inventory Scanning

The first step in PQC migration is discovering all cryptographic algorithm usage
across the enterprise. This includes TLS configurations, certificates, code libraries,
key stores, and protocol configurations.

```python
# Scan TLS endpoints for quantum-vulnerable algorithms
python scripts/agent.py --action scan_tls \
    --targets targets.txt \
    --output tls_inventory.json
```

The scanner identifies:
- TLS protocol versions in use
- Key exchange algorithms (RSA, ECDH, DH -- all quantum-vulnerable)
- Certificate signature algorithms (RSA, ECDSA)
- Cipher suite configurations
- Certificate key sizes and expiration dates

### Phase 2: Crypto-Agility Assessment

Evaluate the organization's ability to swap cryptographic algorithms without
major infrastructure changes:

```python
# Assess crypto-agility readiness
python scripts/agent.py --action assess_agility \
    --scan-results tls_inventory.json \
    --output agility_report.json
```

Key assessment areas:
1. **Protocol flexibility**: Can TLS configurations be updated without downtime?
2. **Library versions**: Do deployed crypto libraries support PQC algorithms?
3. **Certificate infrastructure**: Can CA issue PQC certificates?
4. **Key management**: Can KMS handle larger PQC key sizes?
5. **Hardware constraints**: Can HSMs support PQC operations?

### Phase 3: Hybrid TLS Readiness Testing

Test whether infrastructure supports hybrid key exchange with X25519MLKEM768:

```python
# Test hybrid TLS support on target servers
python scripts/agent.py --action test_hybrid_tls \
    --target server.example.com:443 \
    --output hybrid_tls_report.json
```

**OpenSSL 3.5+ (native ML-KEM support):**
```bash
# Test with native PQC support
openssl s_client -connect server.example.com:443 \
    -groups X25519MLKEM768
```

**OpenSSL 3.0-3.4 with oqs-provider:**
```bash
# Configure oqs-provider
# /etc/ssl/openssl-oqs.cnf
[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
module = /usr/lib/oqs-provider/oqsprovider.so

# Test hybrid TLS
OPENSSL_CONF=/etc/ssl/openssl-oqs.cnf \
openssl s_client -connect server.example.com:443 \
    -groups x25519_mlkem768
```

**Web Server Configuration for Hybrid TLS:**

Apache httpd:
```apache
SSLEngine on
SSLCertificateFile /etc/ssl/certs/server.crt
SSLCertificateKeyFile /etc/ssl/private/server.key
SSLOpenSSLConfCmd Curves X25519MLKEM768:X25519:prime256v1
SSLProtocol -all +TLSv1.2 +TLSv1.3
```

NGINX:
```nginx
ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
```

### Phase 4: ML-KEM Key Encapsulation Validation

Validate that ML-KEM (CRYSTALS-Kyber) key encapsulation works correctly in your
environment:

```python
# Test ML-KEM key encapsulation at all security levels
python scripts/agent.py --action test_mlkem \
    --output mlkem_validation.json
```

ML-KEM parameter comparison:

| Parameter | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|-----------|-----------|-----------|------------|
| Security Level | NIST Level 1 | NIST Level 3 | NIST Level 5 |
| Public Key Size | 800 bytes | 1,184 bytes | 1,568 bytes |
| Ciphertext Size | 768 bytes | 1,088 bytes | 1,568 bytes |
| Shared Secret | 32 bytes | 32 bytes | 32 bytes |
| Comparable To | AES-128 | AES-192 | AES-256 |

### Phase 5: ML-DSA Digital Signature Validation

Validate ML-DSA (CRYSTALS-Dilithium) signature operations:

```python
# Test ML-DSA digital signatures
python scripts/agent.py --action test_mldsa \
    --output mldsa_validation.json
```

ML-DSA parameter comparison:

| Parameter | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|-----------|----------|----------|----------|
| Security Level | NIST Level 2 | NIST Level 3 | NIST Level 5 |
| Public Key Size | 1,312 bytes | 1,952 bytes | 2,592 bytes |
| Signature Size | 2,420 bytes | 3,293 bytes | 4,595 bytes |
| Secret Key Size | 2,560 bytes | 4,032 bytes | 4,896 bytes |

### Phase 6: Migration Roadmap Generation

Generate a prioritized migration roadmap based on inventory and assessment results:

```python
# Generate complete migration roadmap
python scripts/agent.py --action roadmap \
    --scan-results tls_inventory.json \
    --agility-results agility_report.json \
    --output migration_roadmap.json
```

The roadmap prioritizes systems by:
1. **Data sensitivity**: Systems handling long-lived secrets migrate first
2. **Exposure level**: Internet-facing services before internal
3. **Crypto-agility**: Systems that can easily swap algorithms first
4. **Compliance requirements**: Federal/regulated systems per NIST IR 8547 timeline
5. **Dependency chains**: Libraries and frameworks before applications

## Examples

### Full Assessment Pipeline

```bash
# Step 1: Scan all TLS endpoints
python scripts/agent.py --action scan_tls --targets hosts.txt --output scan.json

# Step 2: Assess crypto-agility
python scripts/agent.py --action assess_agility --scan-results scan.json --output agility.json

# Step 3: Test hybrid TLS on critical servers
python scripts/agent.py --action test_hybrid_tls --target critical.example.com:443

# Step 4: Validate ML-KEM support
python scripts/agent.py --action test_mlkem --output mlkem.json

# Step 5: Validate ML-DSA support
python scripts/agent.py --action test_mldsa --output mldsa.json

# Step 6: Generate migration roadmap
python scripts/agent.py --action roadmap --scan-results scan.json --agility-results agility.json --output roadmap.json
```

### Quick Server Assessment

```bash
# Single server PQC readiness check
python scripts/agent.py --action scan_tls --target server.example.com:443
```

## Validation Checklist

- [ ] Cryptographic inventory covers all TLS endpoints, certificates, and key stores
- [ ] All quantum-vulnerable algorithms (RSA, ECDH, ECDSA, DH, DSA) are identified
- [ ] Crypto-agility assessment documents library versions and upgrade paths
- [ ] Hybrid TLS (X25519MLKEM768) tested on representative server configurations
- [ ] ML-KEM key encapsulation validated at target security level (768 recommended)
- [ ] ML-DSA signature verification validated for certificate chain use
- [ ] SLH-DSA (FIPS 205) evaluated as backup signature algorithm
- [ ] Migration roadmap prioritizes by data sensitivity and compliance timeline
- [ ] OpenSSL version and oqs-provider compatibility confirmed
- [ ] Key size increases accounted for in network and storage capacity planning
- [ ] HSM/KMS compatibility with PQC algorithms verified
- [ ] Performance impact of PQC algorithms benchmarked under production load
- [ ] "Harvest now, decrypt later" risk assessed for sensitive data channels
- [ ] Certificate Authority PQC readiness confirmed for certificate issuance

## References

- NIST PQC Standards: https://csrc.nist.gov/projects/post-quantum-cryptography
- FIPS 203 (ML-KEM): https://csrc.nist.gov/pubs/fips/203/final
- FIPS 204 (ML-DSA): https://csrc.nist.gov/pubs/fips/204/final
- FIPS 205 (SLH-DSA): https://csrc.nist.gov/pubs/fips/205/final
- NIST SP 1800-38 Migration Guide: https://www.nccoe.nist.gov/crypto-agility-considerations-migrating-post-quantum-cryptographic-algorithms
- NIST IR 8547 Transition Timeline: https://csrc.nist.gov/pubs/ir/8547/ipd
- Open Quantum Safe Project: https://openquantumsafe.org/
- oqs-provider for OpenSSL: https://github.com/open-quantum-safe/oqs-provider
- OQS TLS Integration: https://openquantumsafe.org/applications/tls.html
- CISA PQC Migration Strategy: https://www.cisa.gov/sites/default/files/2024-09/Strategy-for-Migrating-to-Automated-PQC-Discovery-and-Inventory-Tools.pdf
- IETF Hybrid Key Exchange Draft: https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/
- CycloneDX Crypto BOM: https://cyclonedx.org/use-cases/cryptographic-key/
