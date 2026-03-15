#!/usr/bin/env python3
"""
Ransomware Encryption Routine Analyzer

Analyzes ransomware samples to identify encryption algorithms,
key generation methods, and potential decryption opportunities.

Requirements:
    pip install pefile pycryptodome

Usage:
    python process.py --sample ransomware.exe
    python process.py --encrypted-file encrypted.docx.locked
"""

import argparse
import json
import math
import re
import struct
import sys
from collections import Counter
from pathlib import Path

try:
    import pefile
except ImportError:
    pefile = None


CRYPTO_APIS = {
    "CryptAcquireContextA": ("CryptoAPI", "context"),
    "CryptAcquireContextW": ("CryptoAPI", "context"),
    "CryptGenKey": ("CryptoAPI", "keygen"),
    "CryptEncrypt": ("CryptoAPI", "encrypt"),
    "CryptDecrypt": ("CryptoAPI", "decrypt"),
    "CryptImportKey": ("CryptoAPI", "import"),
    "CryptGenRandom": ("CryptoAPI", "random"),
    "BCryptOpenAlgorithmProvider": ("CNG", "init"),
    "BCryptGenerateSymmetricKey": ("CNG", "keygen"),
    "BCryptEncrypt": ("CNG", "encrypt"),
    "BCryptDecrypt": ("CNG", "decrypt"),
    "EVP_EncryptInit_ex": ("OpenSSL", "init"),
    "EVP_EncryptUpdate": ("OpenSSL", "encrypt"),
    "RSA_public_encrypt": ("OpenSSL", "rsa_encrypt"),
    "AES_set_encrypt_key": ("OpenSSL", "aes_init"),
}

AES_SBOX_PREFIX = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5])
CHACHA_CONST = b"expand 32-byte k"
SALSA_CONST = b"expand 32-byte k"


def entropy(data):
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum(
        (c / length) * math.log2(c / length) for c in freq.values()
    )


def analyze_sample(filepath):
    report = {"file": str(filepath), "crypto_apis": [], "constants": [],
              "embedded_keys": [], "target_extensions": []}

    with open(filepath, 'rb') as f:
        data = f.read()

    report["size"] = len(data)
    report["entropy"] = round(entropy(data), 3)

    # Import analysis
    if pefile:
        try:
            pe = pefile.PE(filepath)
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode('utf-8', errors='replace')
                    for imp in entry.imports:
                        if imp.name:
                            name = imp.name.decode('utf-8', errors='replace')
                            if name in CRYPTO_APIS:
                                framework, op = CRYPTO_APIS[name]
                                report["crypto_apis"].append({
                                    "dll": dll,
                                    "function": name,
                                    "framework": framework,
                                    "operation": op,
                                })
        except Exception:
            pass

    # Crypto constants
    if data.find(AES_SBOX_PREFIX) != -1:
        report["constants"].append("AES S-Box")
    if data.find(CHACHA_CONST) != -1:
        report["constants"].append("ChaCha20/Salsa20")

    # RSA keys
    pem_markers = [b'-----BEGIN PUBLIC KEY-----',
                   b'-----BEGIN RSA PUBLIC KEY-----']
    for marker in pem_markers:
        idx = data.find(marker)
        if idx != -1:
            end = data.find(b'-----END', idx)
            if end != -1:
                key_data = data[idx:end + 30].decode('ascii', errors='replace')
                report["embedded_keys"].append({
                    "type": "PEM RSA Public Key",
                    "offset": f"0x{idx:x}",
                    "preview": key_data[:100],
                })

    # Target extensions
    ext_pattern = re.compile(rb'\.(?:doc|docx|xls|xlsx|pdf|ppt|pptx|'
                              rb'jpg|png|sql|mdb|bak|zip|rar|7z|'
                              rb'psd|dwg|vmdk|raw|db)\b', re.I)
    for m in ext_pattern.finditer(data):
        ext = m.group().decode('ascii', errors='replace').lower()
        if ext not in report["target_extensions"]:
            report["target_extensions"].append(ext)

    return report


def analyze_encrypted_file(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()

    report = {
        "file": str(filepath),
        "size": len(data),
        "entropy": round(entropy(data), 3),
        "high_entropy": entropy(data) > 7.9,
        "possible_appended_key": [],
    }

    # Check tail for appended encrypted key
    for key_size in [128, 256, 512, 1024, 2048]:
        if len(data) > key_size + 16:
            tail = data[-key_size:]
            tail_entropy = entropy(tail)
            if tail_entropy > 7.5:
                report["possible_appended_key"].append({
                    "size": key_size,
                    "entropy": round(tail_entropy, 3),
                })

    return report


def main():
    parser = argparse.ArgumentParser(
        description="Ransomware Encryption Analyzer"
    )
    parser.add_argument("--sample", help="Ransomware binary")
    parser.add_argument("--encrypted-file", help="Encrypted file to analyze")
    parser.add_argument("--output", help="Output JSON report")

    args = parser.parse_args()

    if args.sample:
        report = analyze_sample(args.sample)
    elif args.encrypted_file:
        report = analyze_encrypted_file(args.encrypted_file)
    else:
        parser.print_help()
        return

    print(json.dumps(report, indent=2))
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)


if __name__ == "__main__":
    main()
