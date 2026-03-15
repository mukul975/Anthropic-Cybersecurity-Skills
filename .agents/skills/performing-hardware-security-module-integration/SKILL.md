---
name: performing-hardware-security-module-integration
description: Integrate Hardware Security Modules (HSMs) using PKCS#11 interface for cryptographic key management, signing operations, and secure key storage with python-pkcs11, AWS CloudHSM, and YubiHSM2.
domain: cybersecurity
subdomain: cryptography
tags: [HSM, PKCS11, CloudHSM, YubiHSM2, key-management, cryptographic-operations, hardware-security]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Hardware Security Module Integration

## Overview

Hardware Security Modules (HSMs) provide tamper-resistant cryptographic key storage and operations. This skill covers integrating with HSMs via the PKCS#11 standard interface using python-pkcs11, performing key generation, signing, encryption, and verification operations, querying token and slot information, and validating HSM configuration for compliance with FIPS 140-2/3 requirements.

## Prerequisites

- HSM device or software HSM (SoftHSM2 for testing)
- PKCS#11 shared library (.so/.dll) for the HSM vendor
- Python 3.9+ with `python-pkcs11`
- Token initialized with SO PIN and user PIN
- For AWS CloudHSM: `cloudhsm-pkcs11` provider configured

## Steps

1. Load PKCS#11 library and enumerate available slots and tokens
2. Open session and authenticate with user PIN
3. Generate RSA 2048-bit or EC P-256 key pairs on the HSM
4. Perform signing and verification using on-device keys
5. List all objects (keys, certificates) stored on the token
6. Query mechanism list to verify supported algorithms
7. Generate compliance report with key inventory and algorithm audit

## Expected Output

- JSON report listing HSM slots, tokens, stored keys, supported mechanisms, and compliance status
- Signing test results with key metadata and algorithm details
