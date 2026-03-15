---
name: reverse-engineering-ransomware-encryption-routine
description: Reverse engineer ransomware encryption routines to identify cryptographic algorithms, key generation flaws, and potential decryption opportunities using static and dynamic analysis.
domain: cybersecurity
subdomain: malware-analysis
tags: [ransomware, encryption, reverse-engineering, cryptanalysis, aes, rsa, decryption, malware-analysis]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Reverse Engineering Ransomware Encryption Routine

## Overview

Modern ransomware uses hybrid encryption combining symmetric algorithms (AES-256-CBC/CTR, ChaCha20, Salsa20) for file encryption with asymmetric algorithms (RSA-2048/4096, Curve25519) for key protection. The encryption routine typically generates a random symmetric key per file, encrypts file contents, then encrypts the symmetric key with the attacker's embedded public key. Reverse engineering these routines identifies the specific algorithms, key derivation methods, initialization vectors, file targeting patterns, and potential implementation flaws that could enable decryption without paying the ransom. Notable examples include Rhysida (AES-256-CTR + RSA-4096), Qilin.B (AES-256-CTR with AES-NI or ChaCha20 fallback), and Medusa (AES-256 + RSA).

## Prerequisites

- IDA Pro or Ghidra for static disassembly
- x64dbg/WinDbg for dynamic debugging
- Python 3.9+ with `pycryptodome`, `pefile`
- Understanding of AES, RSA, ChaCha20, Curve25519 algorithms
- Knowledge of Windows CryptoAPI and CNG (BCrypt) functions
- Sandbox environment for safe execution

## Key Concepts

### Hybrid Encryption Model

Ransomware generates a unique AES key and IV for each file. The file content is encrypted with this symmetric key. The symmetric key is then encrypted with the attacker's RSA public key (embedded in the binary or fetched from C2). The encrypted key is appended or prepended to the encrypted file. Only the attacker holding the RSA private key can decrypt the per-file symmetric keys.

### Cryptographic API Identification

Windows ransomware typically uses CryptoAPI (`CryptAcquireContext`, `CryptGenKey`, `CryptEncrypt`) or CNG (`BCryptGenerateSymmetricKey`, `BCryptEncrypt`). Some use OpenSSL or custom implementations. Identifying these API calls provides immediate insight into the algorithm, key size, and mode of operation.

### Implementation Flaws

Decryption opportunities arise from: hardcoded encryption keys, weak PRNG for key generation (using `GetTickCount` or `time()` as seed), reuse of IVs across files, ECB mode usage, keys remaining in memory post-encryption, and race conditions where keys can be captured during encryption.

## Practical Steps

### Step 1: Identify Cryptographic Functions

```python
#!/usr/bin/env python3
"""Identify cryptographic functions in ransomware PE files."""
import pefile
import sys

CRYPTO_APIS = {
    # Windows CryptoAPI
    "CryptAcquireContextA": "CryptoAPI context acquisition",
    "CryptAcquireContextW": "CryptoAPI context acquisition",
    "CryptGenKey": "Key generation",
    "CryptDeriveKey": "Key derivation",
    "CryptEncrypt": "Encryption operation",
    "CryptDecrypt": "Decryption operation",
    "CryptImportKey": "Key import (public key?)",
    "CryptExportKey": "Key export",
    "CryptGenRandom": "Random number generation",
    "CryptCreateHash": "Hash creation",
    "CryptHashData": "Hashing operation",
    # Windows CNG (BCrypt)
    "BCryptOpenAlgorithmProvider": "CNG algorithm initialization",
    "BCryptGenerateSymmetricKey": "CNG symmetric key generation",
    "BCryptEncrypt": "CNG encryption",
    "BCryptDecrypt": "CNG decryption",
    "BCryptGenerateKeyPair": "CNG key pair generation",
    "BCryptImportKeyPair": "CNG key import",
    # OpenSSL
    "EVP_EncryptInit_ex": "OpenSSL encrypt init",
    "EVP_EncryptUpdate": "OpenSSL encrypt update",
    "EVP_EncryptFinal_ex": "OpenSSL encrypt final",
    "RSA_public_encrypt": "OpenSSL RSA encryption",
    "AES_set_encrypt_key": "OpenSSL AES key setup",
    # File operations
    "CreateFileW": "File open (target files)",
    "ReadFile": "File read (before encryption)",
    "WriteFile": "File write (after encryption)",
    "FindFirstFileW": "File enumeration (targeting)",
    "FindNextFileW": "File enumeration",
    "MoveFileW": "File rename (extension change)",
    "DeleteFileW": "File deletion (originals)",
}

AES_SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
])

CHACHA20_CONSTANT = b"expand 32-byte k"


def analyze_imports(filepath):
    """Analyze PE imports for cryptographic APIs."""
    try:
        pe = pefile.PE(filepath)
    except pefile.PEFormatError:
        print("[-] Not a valid PE file")
        return

    print("[+] Cryptographic API Analysis")
    print("=" * 60)

    crypto_imports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('utf-8', errors='replace')
            for imp in entry.imports:
                if imp.name:
                    name = imp.name.decode('utf-8', errors='replace')
                    if name in CRYPTO_APIS:
                        desc = CRYPTO_APIS[name]
                        crypto_imports.append((dll, name, desc))
                        print(f"  [{dll}] {name}: {desc}")

    if not crypto_imports:
        print("  No known crypto APIs found in imports")
        print("  Malware may use custom implementation or dynamic loading")

    return crypto_imports


def find_crypto_constants(filepath):
    """Search for embedded cryptographic constants."""
    with open(filepath, 'rb') as f:
        data = f.read()

    print("\n[+] Cryptographic Constants Search")
    print("=" * 60)

    # AES S-Box
    offset = data.find(AES_SBOX)
    if offset != -1:
        print(f"  AES S-Box found at offset 0x{offset:x}")

    # ChaCha20/Salsa20 constant
    offset = data.find(CHACHA20_CONSTANT)
    if offset != -1:
        print(f"  ChaCha20 constant at offset 0x{offset:x}")

    # RSA public key markers
    rsa_markers = [
        b'-----BEGIN PUBLIC KEY-----',
        b'-----BEGIN RSA PUBLIC KEY-----',
        b'\x30\x82',  # ASN.1 SEQUENCE
    ]
    for marker in rsa_markers:
        offset = data.find(marker)
        if offset != -1:
            print(f"  RSA key marker at offset 0x{offset:x}")

    # Common ransomware file extension patterns
    import re
    ext_pattern = re.compile(rb'\.\w{3,10}(?=\x00)', re.IGNORECASE)
    extensions = set()
    for match in ext_pattern.finditer(data):
        ext = match.group().decode('ascii', errors='replace').lower()
        target_exts = [
            '.doc', '.docx', '.xls', '.xlsx', '.pdf', '.ppt',
            '.jpg', '.png', '.sql', '.mdb', '.bak', '.zip',
        ]
        if ext in target_exts:
            extensions.add(ext)

    if extensions:
        print(f"\n  Target file extensions: {', '.join(sorted(extensions))}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ransomware_sample>")
        sys.exit(1)

    analyze_imports(sys.argv[1])
    find_crypto_constants(sys.argv[1])
```

### Step 2: Analyze Encryption Flow

```python
def analyze_encryption_pattern(filepath):
    """Analyze file encryption patterns from ransomware artifacts."""
    import os
    import struct

    with open(filepath, 'rb') as f:
        data = f.read()

    file_size = len(data)
    print(f"\n[+] Encrypted File Analysis: {filepath}")
    print(f"  Size: {file_size:,} bytes")

    # Check for appended key material (common pattern)
    # Many ransomware families append encrypted key at end of file
    tail_sizes = [256, 512, 1024, 2048]  # Common RSA ciphertext sizes
    for size in tail_sizes:
        if file_size > size + 16:
            tail = data[-size:]
            # High entropy suggests encrypted data
            entropy = calculate_entropy(tail)
            if entropy > 7.5:
                print(f"  Possible encrypted key ({size} bytes) "
                      f"at end of file (entropy: {entropy:.2f})")

    # Check for header modifications
    # Many ransomware prepend metadata
    header = data[:64]
    print(f"  First 16 bytes: {header[:16].hex()}")

    # Check if original file header is preserved
    known_headers = {
        b'PK': 'ZIP/Office',
        b'\x89PNG': 'PNG',
        b'\xff\xd8\xff': 'JPEG',
        b'%PDF': 'PDF',
        b'\xd0\xcf\x11\xe0': 'OLE (DOC/XLS)',
    }
    for magic, ftype in known_headers.items():
        if header.startswith(magic):
            print(f"  Original format preserved: {ftype}")
            break
    else:
        print("  Original header destroyed/encrypted")


def calculate_entropy(data):
    """Calculate Shannon entropy of data."""
    from collections import Counter
    import math

    if not data:
        return 0

    freq = Counter(data)
    length = len(data)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )
    return entropy
```

## Validation Criteria

- Cryptographic algorithms identified (AES, RSA, ChaCha20, etc.)
- Key size and mode of operation determined
- Key generation method analyzed for potential weaknesses
- Per-file key encryption scheme documented
- File targeting patterns and extension list extracted
- Embedded public keys extracted for infrastructure correlation
- Potential decryption opportunities assessed

## References

- [Morphisec - Breaking Down Ransomware Encryption](https://www.morphisec.com/blog/breaking-down-ransomware-encryption-key-strategies-algorithms-and-implementation-trends/)
- [Emsisoft - Ransomware Encryption Methods](https://www.emsisoft.com/en/blog/27649/ransomware-encryption-methods/)
- [Halcyon Ransomware Power Rankings Q4-2024](https://www.halcyon.ai/raas-mq/power-rankings-ransomware-malicious-quartile-q4-2024)
- [No More Ransom Project](https://www.nomoreransom.org/)
- [MITRE ATT&CK T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
