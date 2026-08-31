---
name: migrating-to-post-quantum-cryptography
description: Build a cryptographic inventory/CBOM with OpenSSL 3.5+, deploy hybrid post-quantum key exchange (X25519MLKEM768) on TLS/VPN/SSH endpoints, generate ML-KEM/ML-DSA keys and PQC/hybrid certificates, and prioritize migration by harvest-now-decrypt-later (HNDL) exposure per NIST SP 1800-38. Use when inventorying enterprise cryptography for quantum-readiness, enabling hybrid PQC key exchange, or issuing and verifying PQC/hybrid certificates. Do not use for assessing organizational readiness and scanning for quantum-vulnerable algorithms per FIPS 203/204/205 - use performing-post-quantum-cryptography-migration.
domain: cybersecurity
subdomain: cryptography
tags:
- post-quantum
- cryptography
- ml-kem
- ml-dsa
- crypto-agility
- cbom
- tls
- quantum-readiness
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.DS-02
mitre_attack:
- T1573
---
# Migrating to Post-Quantum Cryptography

> **Scope and Authorization:** This skill describes defensive cryptographic-migration engineering on systems you own or operate. Cryptographic discovery scanning can touch sensitive key material and production traffic — run inventory tooling only with authorization and in line with your organization's change-management and data-handling policies.

## Overview

A cryptographically relevant quantum computer (CRQC) running Shor's algorithm will break the public-key cryptography that secures almost all of today's communications and signatures: RSA, finite-field and elliptic-curve Diffie-Hellman (DH/ECDH), and ECDSA. Symmetric primitives (AES) and hashes (SHA-2/3) are only weakened (Grover gives a quadratic speedup, mitigated by larger key/output sizes), but asymmetric algorithms are catastrophically broken. The most urgent threat is **harvest-now, decrypt-later (HNDL)**: adversaries capturing encrypted traffic today to decrypt once a CRQC exists, which puts long-lived secrets (health records, state secrets, intellectual property, root-of-trust keys) at risk *now*.

On 13 August 2024 NIST finalized the first post-quantum standards: **FIPS 203 (ML-KEM**, Module-Lattice KEM, formerly CRYSTALS-Kyber) for key establishment, **FIPS 204 (ML-DSA**, Module-Lattice digital signatures, formerly CRYSTALS-Dilithium), and **FIPS 205 (SLH-DSA**, the stateless hash-based signature scheme SPHINCS+). The migration playbook (NIST SP 1800-38, *Migration to Post-Quantum Cryptography*) is: (1) build a **cryptographic inventory / CBOM**, (2) prioritize by HNDL exposure and crypto-agility, (3) deploy **hybrid** schemes (a classical algorithm AND a PQC algorithm combined, e.g. `X25519MLKEM768`) so a break in either leg does not compromise the session, and (4) re-key and rotate.

This skill maps to ATT&CK **T1573 – Encrypted Channel**: the same cryptographic channels adversaries abuse for stealthy C2 are the channels defenders must make quantum-resistant; understanding the algorithms in use is foundational to both attack detection and defensive migration. The NIST CSF outcome is **PR.DS-02 (data-in-transit protection)** — and by extension data-at-rest for HNDL-sensitive stores.

## When to Use

- When building an enterprise cryptographic inventory / Cryptography Bill of Materials (CBOM) for quantum-readiness.
- When prioritizing which systems must migrate first based on data lifetime and HNDL exposure.
- When enabling hybrid post-quantum key exchange (`X25519MLKEM768`) on TLS endpoints, VPNs, or SSH.
- When issuing PQC or hybrid certificates and testing PQC signature verification.
- When evaluating crypto-agility — the ability to swap algorithms without re-architecting applications.

## Prerequisites

- OpenSSL **3.5.0 or later**, which ships native ML-KEM, ML-DSA, and SLH-DSA support:
  ```bash
  openssl version            # expect 3.5.0+
  openssl list -kem-algorithms | grep -i mlkem
  openssl list -signature-algorithms | grep -i mldsa
  ```
- For OpenSSL 3.0–3.4, the Open Quantum Safe **oqs-provider** plus **liboqs**:
  ```bash
  git clone https://github.com/open-quantum-safe/liboqs && \
    cmake -S liboqs -B liboqs/build && cmake --build liboqs/build && \
    sudo cmake --install liboqs/build
  git clone https://github.com/open-quantum-safe/oqs-provider && \
    cmake -S oqs-provider -B oqs-provider/_build && \
    cmake --build oqs-provider/_build && \
    sudo cmake --install oqs-provider/_build
  ```
- Python 3.8+ for the inventory helper:
  ```bash
  python3 -m pip install cryptography
  ```
- (Optional) A CBOM generator: CycloneDX `cdxgen`, or `cbomkit-theia` for container/directory crypto discovery.

## Objectives

- Produce a cryptographic inventory (CBOM) of algorithms, key sizes, certificates, and protocols in use.
- Classify assets by quantum vulnerability and HNDL exposure and prioritize migration.
- Stand up and verify hybrid `X25519MLKEM768` key exchange on a TLS endpoint.
- Generate ML-KEM and ML-DSA keys and a PQC/hybrid certificate, and verify signatures.
- Establish a crypto-agility baseline and a re-keying / rotation plan.

## MITRE ATT&CK Mapping

| ID | Official Technique Name | Relevance |
|----|------------------------|-----------|
| T1573 | Encrypted Channel | Migration secures the encrypted channels (TLS/VPN/SSH) that protect data in transit; cryptographic inventory of these channels also underpins detection of adversary-controlled encrypted C2. |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | RSA/ECDH key exchange — the exact asymmetric primitives broken by a CRQC and replaced by ML-KEM hybrids. |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES and other symmetric ciphers; quantum-weakened by Grover, mitigated by 256-bit keys rather than replacement. |

## Workflow

### 1. Confirm PQC algorithm availability
```bash
openssl version
# List quantum-safe KEMs and signatures available in this OpenSSL build
openssl list -kem-algorithms | grep -Ei 'mlkem|kyber'
openssl list -signature-algorithms | grep -Ei 'mldsa|dilithium|slhdsa|sphincs'
openssl list -tls-groups 2>/dev/null | grep -Ei 'mlkem'
```
If using oqs-provider on OpenSSL 3.0–3.4, activate it in `openssl.cnf`:
```ini
[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect
[default_sect]
activate = 1
[oqsprovider_sect]
activate = 1
```

### 2. Build a cryptographic inventory (CBOM)
Generate a CycloneDX CBOM from a code repo or container with `cbomkit-theia` / `cdxgen`:
```bash
# Directory / container image crypto discovery
cbomkit-theia dir ./myapp --output cbom.json
# or with cdxgen (Java keystores, certs, source-level algorithms)
cdxgen -t java --include-crypto -o cbom.json ./myapp
```
Enumerate TLS algorithms and certificate signature schemes across live endpoints with the helper `agent.py scan` (below), and the public-key strength of any certificate:
```bash
openssl x509 -in server.crt -noout -text | grep -E 'Signature Algorithm|Public Key'
```

### 3. Classify and prioritize by HNDL exposure
For each inventoried asset, record: algorithm, key size, where the key lives, data sensitivity, and **data lifetime**. Prioritize migration where `data_lifetime_years + migration_time > years_until_CRQC` (Mosca's inequality). Long-lived confidential data over public networks ranks highest; ephemeral internal traffic ranks lower. Hash-based signature roots-of-trust (firmware signing) are also high priority because they protect long-lived trust anchors.

### 4. Generate ML-KEM and ML-DSA key material
```bash
# ML-KEM-768 (key establishment) keypair
openssl genpkey -algorithm ML-KEM-768 -out mlkem768.key
# OpenSSL 3.0-3.4 + oqs-provider uses lowercase 'mlkem768'
# openssl genpkey -algorithm mlkem768 -out mlkem768.key

# ML-DSA-65 (signature) keypair
openssl genpkey -algorithm ML-DSA-65 -out mldsa65.key
openssl pkey -in mldsa65.key -pubout -out mldsa65.pub
```

### 5. Issue a PQC (ML-DSA) certificate
```bash
# Self-signed ML-DSA-65 certificate for testing
openssl req -new -x509 -key mldsa65.key -out mldsa65.crt -days 365 \
  -subj "/CN=pqc-test.example.com"
openssl x509 -in mldsa65.crt -noout -text | grep -A1 'Signature Algorithm'
```

### 6. Sign and verify with ML-DSA
```bash
echo "firmware-image-v2.bin" > artifact.txt
openssl dgst -sign mldsa65.key -out artifact.sig artifact.txt
openssl dgst -verify mldsa65.pub -signature artifact.sig artifact.txt
# -> "Verified OK"
```

### 7. Deploy and test hybrid TLS key exchange
Run a TLS 1.3 server and force the hybrid group `X25519MLKEM768` (classical X25519 + ML-KEM-768):
```bash
# Server (use a classical or ML-DSA cert/key)
openssl s_server -accept 4433 -www -tls1_3 \
  -cert mldsa65.crt -key mldsa65.key -groups X25519MLKEM768

# Client — negotiate the hybrid group and confirm it was used
openssl s_client -connect localhost:4433 -tls1_3 -groups X25519MLKEM768 \
  </dev/null 2>/dev/null | grep -E 'Negotiated|Server Temp Key|Cipher'
```
For external endpoints, confirm support against a public PQC test server:
```bash
openssl s_client -groups X25519MLKEM768 -tls1_3 -connect pq.cloudflareresearch.com:443 </dev/null
```

### 8. Enable hybrid PQC on production TLS terminators
Configure the web server / load balancer to offer the hybrid group while keeping classical fallback for old clients. NGINX with OpenSSL 3.5+:
```nginx
server {
    listen 443 ssl;
    ssl_protocols TLSv1.3;
    ssl_ecdh_curve X25519MLKEM768:X25519:secp256r1;   # hybrid first, classical fallback
    ssl_certificate     /etc/nginx/certs/server.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;
}
```
Reload and verify with the s_client command from step 7 against the live host.

### 9. Establish crypto-agility and a rotation plan
Centralize algorithm selection (config, not code), record key/cert expiry, and schedule re-keying. Re-run the inventory (step 2) on a cadence to confirm no quantum-vulnerable-only algorithms remain on prioritized assets, and track residual RSA/ECDH usage to zero on high-HNDL paths.

## Tools and Resources

| Tool / Resource | Purpose | Link |
|-----------------|---------|------|
| FIPS 203 (ML-KEM) | KEM standard | https://csrc.nist.gov/pubs/fips/203/final |
| FIPS 204 (ML-DSA) | Signature standard | https://csrc.nist.gov/pubs/fips/204/final |
| FIPS 205 (SLH-DSA) | Hash-based signature standard | https://csrc.nist.gov/pubs/fips/205/final |
| NIST SP 1800-38 | Migration practice guide / crypto discovery | https://www.nccoe.nist.gov/crypto-agility-considerations-migrating-post-quantum-cryptographic-algorithms |
| OpenSSL 3.5 | Native ML-KEM/ML-DSA/SLH-DSA + hybrid groups | https://www.openssl.org |
| oqs-provider / liboqs | PQC for OpenSSL 3.0–3.4 | https://github.com/open-quantum-safe/oqs-provider |
| CycloneDX CBOM | Cryptography Bill of Materials spec | https://cyclonedx.org/capabilities/cbom/ |
| CBOMkit / cbomkit-theia | Crypto discovery & CBOM generation | https://github.com/cbomkit/cbomkit-theia |

## Algorithm Reference

| Classical (broken/weakened) | Quantum-safe replacement | Standard | Use |
|-----------------------------|--------------------------|----------|-----|
| RSA / ECDH / DH key exchange | ML-KEM-512/768/1024 (hybrid: X25519MLKEM768) | FIPS 203 | Key establishment |
| RSA / ECDSA / EdDSA signatures | ML-DSA-44/65/87 | FIPS 204 | General signatures |
| (backup signature) | SLH-DSA (SPHINCS+) | FIPS 205 | Conservative/firmware signing |
| AES-128 | AES-256 | FIPS 197 | Symmetric (Grover-hardened) |
| SHA-256 | SHA-384/512, SHA-3 | FIPS 180-4/202 | Hashing |

## Validation Criteria

- [ ] OpenSSL 3.5+ (or 3.x + oqs-provider) confirmed exposing ML-KEM and ML-DSA.
- [ ] Cryptographic inventory / CBOM produced covering algorithms, keys, certs, and protocols.
- [ ] Assets classified and prioritized by HNDL exposure (Mosca's inequality applied).
- [ ] ML-KEM-768 and ML-DSA-65 keypairs generated successfully.
- [ ] PQC (ML-DSA) certificate issued and its signature algorithm verified.
- [ ] Sign/verify round trip with ML-DSA returns "Verified OK".
- [ ] Hybrid `X25519MLKEM768` key exchange negotiated and confirmed on a test endpoint.
- [ ] Production TLS terminator offers the hybrid group with classical fallback.
- [ ] Crypto-agility/rotation plan documented and inventory re-run scheduled.
