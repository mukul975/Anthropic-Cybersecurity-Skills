#!/usr/bin/env python3
"""Ransomware encryption mechanism analysis agent.

Analyzes encryption algorithms, key management, file encryption routines,
and assesses decryption feasibility for ransomware samples and encrypted files.
"""

import os
import sys
import struct
import hashlib
import math
import json
import re
from collections import Counter


def compute_hash(filepath):
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def shannon_entropy(data):
    """Calculate Shannon entropy of byte data."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


CRYPTO_CONSTANTS = {
    bytes.fromhex("637c777bf26b6fc53001672bfed7ab76"): "AES S-Box (Rijndael)",
    bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb"): "AES S-Box (continued)",
    bytes.fromhex("6a09e667bb67ae853c6ef372a54ff53a"): "SHA-256 initialization vector",
    b"expand 32-byte k": "ChaCha20/Salsa20 constant (256-bit key)",
    b"expand 16-byte k": "ChaCha20/Salsa20 constant (128-bit key)",
    bytes.fromhex("d1310ba698dfb5ac"): "Blowfish P-array fragment",
}

CRYPTO_API_NAMES = [
    b"CryptAcquireContext", b"CryptGenKey", b"CryptEncrypt", b"CryptDecrypt",
    b"CryptImportKey", b"CryptExportKey", b"CryptGenRandom", b"CryptDeriveKey",
    b"BCryptOpenAlgorithmProvider", b"BCryptEncrypt", b"BCryptGenerateKeyPair",
    b"BCryptGenerateSymmetricKey", b"BCryptCreateHash",
    b"RtlEncryptMemory", b"RtlDecryptMemory",
]

RANSOMWARE_EXTENSIONS = {
    ".locked": ["LockBit", "Generic"],
    ".encrypt": ["Generic"],
    ".crypt": ["CryptXXX", "Generic"],
    ".locky": ["Locky"],
    ".cerber": ["Cerber"],
    ".zepto": ["Locky variant"],
    ".odin": ["Locky variant"],
    ".aesir": ["Locky variant"],
    ".wncry": ["WannaCry"],
    ".WNCRY": ["WannaCry"],
    ".wnry": ["WannaCry"],
    ".wcry": ["WannaCry"],
    ".dharma": ["Dharma/CrySiS"],
    ".basta": ["Black Basta"],
    ".blackcat": ["BlackCat/ALPHV"],
    ".hive": ["Hive"],
    ".royal": ["Royal"],
    ".rhysida": ["Rhysida"],
    ".akira": ["Akira"],
    ".lockbit": ["LockBit 3.0"],
    ".conti": ["Conti"],
    ".ryuk": ["Ryuk"],
    ".maze": ["Maze"],
    ".revil": ["REvil/Sodinokibi"],
    ".sodinokibi": ["REvil/Sodinokibi"],
    ".phobos": ["Phobos"],
    ".makop": ["Makop"],
    ".stop": ["STOP/Djvu"],
    ".djvu": ["STOP/Djvu"],
}


def identify_ransomware_extension(filepath):
    """Identify ransomware family from file extension."""
    ext = os.path.splitext(filepath)[1].lower()
    if ext in RANSOMWARE_EXTENSIONS:
        return {"extension": ext, "families": RANSOMWARE_EXTENSIONS[ext]}
    for known_ext, families in RANSOMWARE_EXTENSIONS.items():
        if ext.endswith(known_ext):
            return {"extension": ext, "families": families}
    return {"extension": ext, "families": ["Unknown"]}


def scan_crypto_constants(filepath):
    """Scan binary for known cryptographic constants."""
    with open(filepath, "rb") as f:
        data = f.read()
    findings = []
    for const_bytes, description in CRYPTO_CONSTANTS.items():
        offset = data.find(const_bytes)
        if offset != -1:
            findings.append({
                "constant": description,
                "offset": f"0x{offset:08X}",
                "hex": const_bytes[:16].hex(),
            })
    return findings


def scan_crypto_apis(filepath):
    """Scan binary for Windows Crypto API string references."""
    with open(filepath, "rb") as f:
        data = f.read()
    found = []
    for api in CRYPTO_API_NAMES:
        if api in data:
            found.append(api.decode("ascii", errors="replace"))
    return found


def analyze_encrypted_file(filepath):
    """Analyze an encrypted file for ransomware characteristics."""
    with open(filepath, "rb") as f:
        data = f.read()

    file_size = len(data)
    entropy = shannon_entropy(data)

    # Check for appended metadata (many ransomware families append key material)
    tail_256 = data[-256:] if file_size >= 256 else data
    tail_entropy = shannon_entropy(tail_256)

    # Check for ECB mode (duplicate 16-byte blocks)
    blocks_16 = [data[i:i+16] for i in range(0, min(len(data), 65536), 16)]
    unique_16 = len(set(blocks_16))
    total_16 = len(blocks_16)
    ecb_ratio = 1.0 - (unique_16 / total_16) if total_16 > 0 else 0

    # Check for partial encryption (low entropy regions)
    chunk_size = min(4096, file_size // 4) if file_size > 16 else file_size
    first_entropy = shannon_entropy(data[:chunk_size]) if chunk_size > 0 else 0
    mid_offset = file_size // 2
    mid_entropy = shannon_entropy(data[mid_offset:mid_offset+chunk_size]) if chunk_size > 0 else 0
    last_entropy = shannon_entropy(data[-chunk_size:]) if chunk_size > 0 else 0

    # Detect magic bytes at tail (ransomware markers)
    tail_8 = data[-8:] if file_size >= 8 else data
    tail_marker = tail_8.hex() if all(b > 0 for b in tail_8) else None

    return {
        "file_size": file_size,
        "overall_entropy": round(entropy, 4),
        "tail_256_entropy": round(tail_entropy, 4),
        "ecb_duplicate_ratio": round(ecb_ratio, 4),
        "ecb_likely": ecb_ratio > 0.05,
        "partial_encryption": {
            "first_chunk_entropy": round(first_entropy, 4),
            "mid_chunk_entropy": round(mid_entropy, 4),
            "last_chunk_entropy": round(last_entropy, 4),
            "likely_partial": abs(first_entropy - mid_entropy) > 2.0,
        },
        "tail_marker_hex": tail_marker,
        "fully_encrypted": entropy > 7.5,
    }


def xor_key_recovery(encrypted_data, known_plaintext):
    """Attempt XOR key recovery from known plaintext-ciphertext pair."""
    if len(known_plaintext) == 0:
        return None
    key_stream = bytes(c ^ p for c, p in zip(encrypted_data, known_plaintext))
    # Detect repeating key
    for key_len in range(1, min(256, len(key_stream) // 2)):
        candidate = key_stream[:key_len]
        match = all(
            key_stream[i] == candidate[i % key_len]
            for i in range(min(len(key_stream), key_len * 4))
        )
        if match and key_len < len(key_stream):
            return {"key_hex": candidate.hex(), "key_length": key_len, "key_ascii": candidate.decode("ascii", errors="replace")}
    return None


def check_file_header_known_plaintext(encrypted_filepath):
    """Check if encrypted file retains known file header (partial encryption indicator)."""
    KNOWN_HEADERS = {
        b"%PDF": "PDF document",
        b"PK\x03\x04": "ZIP/DOCX/XLSX archive",
        b"\x89PNG": "PNG image",
        b"\xff\xd8\xff": "JPEG image",
        b"MZ": "PE executable",
        b"\x7fELF": "ELF executable",
        b"Rar!": "RAR archive",
        b"\xd0\xcf\x11\xe0": "OLE2 (DOC/XLS)",
        b"SQLite format 3": "SQLite database",
    }
    with open(encrypted_filepath, "rb") as f:
        header = f.read(16)
    for magic, filetype in KNOWN_HEADERS.items():
        if header[:len(magic)] == magic:
            return {"detected": True, "original_type": filetype,
                    "note": "File header intact - partial encryption or not encrypted"}
    return {"detected": False, "note": "No known file header found - likely fully encrypted from start"}


def assess_decryption_feasibility(crypto_constants, crypto_apis, enc_analysis):
    """Assess decryption feasibility based on analysis results."""
    weaknesses = []
    strong_points = []

    if enc_analysis.get("ecb_likely"):
        weaknesses.append("ECB mode detected - block patterns preserved, partial plaintext recovery possible")
    if enc_analysis.get("partial_encryption", {}).get("likely_partial"):
        weaknesses.append("Partial encryption detected - unencrypted file regions may aid recovery")
    if enc_analysis.get("overall_entropy", 8) < 6.0:
        weaknesses.append("Low entropy suggests weak or partial encryption")

    has_csprng = any("GenRandom" in api for api in crypto_apis)
    has_rsa = any("KeyPair" in api or "ImportKey" in api for api in crypto_apis)
    has_aes = any("AES" in c.get("constant", "") or "Rijndael" in c.get("constant", "") for c in crypto_constants)
    has_chacha = any("ChaCha" in c.get("constant", "") or "Salsa" in c.get("constant", "") for c in crypto_constants)

    if has_csprng:
        strong_points.append("CSPRNG key generation (CryptGenRandom) - keys not predictable")
    if has_rsa:
        strong_points.append("RSA key wrapping - per-file keys protected by asymmetric encryption")
    if has_aes:
        strong_points.append("AES encryption identified")
    if has_chacha:
        strong_points.append("ChaCha20/Salsa20 stream cipher identified")

    if not has_csprng:
        weaknesses.append("No CSPRNG detected - key generation may be predictable")

    feasibility = "NOT POSSIBLE" if len(strong_points) >= 2 and len(weaknesses) == 0 else \
                  "POSSIBLE" if len(weaknesses) >= 2 else \
                  "UNLIKELY - check for specific implementation flaws"

    return {
        "feasibility": feasibility,
        "weaknesses": weaknesses,
        "strong_points": strong_points,
        "recommendation": "Check NoMoreRansom.org and memory forensics" if feasibility != "NOT POSSIBLE"
                          else "Restore from backups; no cryptographic weakness found",
    }


def generate_report(sample_path=None, encrypted_path=None):
    """Generate full ransomware encryption analysis report."""
    report = {"analysis_type": "Ransomware Encryption Mechanism Analysis"}

    if sample_path and os.path.exists(sample_path):
        report["sample"] = {
            "path": sample_path,
            "sha256": compute_hash(sample_path),
            "size": os.path.getsize(sample_path),
            "entropy": round(shannon_entropy(open(sample_path, "rb").read()), 4),
        }
        report["crypto_constants"] = scan_crypto_constants(sample_path)
        report["crypto_apis"] = scan_crypto_apis(sample_path)

    if encrypted_path and os.path.exists(encrypted_path):
        report["encrypted_file"] = {
            "path": encrypted_path,
            "sha256": compute_hash(encrypted_path),
            "family_match": identify_ransomware_extension(encrypted_path),
        }
        report["encryption_analysis"] = analyze_encrypted_file(encrypted_path)
        report["header_check"] = check_file_header_known_plaintext(encrypted_path)

    if "crypto_constants" in report or "encryption_analysis" in report:
        report["feasibility"] = assess_decryption_feasibility(
            report.get("crypto_constants", []),
            report.get("crypto_apis", []),
            report.get("encryption_analysis", {}),
        )

    return report


if __name__ == "__main__":
    print("=" * 60)
    print("Ransomware Encryption Mechanism Analysis Agent")
    print("Algorithm identification, key analysis, decryption feasibility")
    print("=" * 60)

    if len(sys.argv) < 2:
        print("\n[DEMO] Usage:")
        print("  python agent.py <ransomware_binary>               # Analyze ransomware sample")
        print("  python agent.py <ransomware_binary> <encrypted_file>  # Full analysis")
        print("  python agent.py --encrypted <encrypted_file>      # Analyze encrypted file only")
        sys.exit(0)

    sample = None
    encrypted = None

    if sys.argv[1] == "--encrypted" and len(sys.argv) > 2:
        encrypted = sys.argv[2]
    else:
        sample = sys.argv[1]
        encrypted = sys.argv[2] if len(sys.argv) > 2 else None

    report = generate_report(sample_path=sample, encrypted_path=encrypted)

    if sample and os.path.exists(sample):
        info = report.get("sample", {})
        print(f"\n[*] Sample: {sample}")
        print(f"    SHA-256: {info.get('sha256', 'N/A')}")
        print(f"    Size: {info.get('size', 0)} bytes")
        print(f"    Entropy: {info.get('entropy', 0)}")

        print("\n--- Crypto Constants Found ---")
        for c in report.get("crypto_constants", []):
            print(f"  [{c['offset']}] {c['constant']}")

        print("\n--- Crypto API Imports ---")
        for api in report.get("crypto_apis", []):
            print(f"  {api}")

    if encrypted and os.path.exists(encrypted):
        fm = report.get("encrypted_file", {}).get("family_match", {})
        print(f"\n[*] Encrypted file: {encrypted}")
        print(f"    Extension: {fm.get('extension', '?')}")
        print(f"    Possible families: {', '.join(fm.get('families', ['Unknown']))}")

        ea = report.get("encryption_analysis", {})
        print(f"\n--- Encryption Analysis ---")
        print(f"  Overall entropy: {ea.get('overall_entropy', 0)}")
        print(f"  Fully encrypted: {ea.get('fully_encrypted', False)}")
        print(f"  ECB mode likely: {ea.get('ecb_likely', False)}")
        partial = ea.get("partial_encryption", {})
        print(f"  Partial encryption: {partial.get('likely_partial', False)}")

        hc = report.get("header_check", {})
        print(f"\n--- Header Check ---")
        print(f"  Known header: {hc.get('detected', False)}")
        print(f"  Note: {hc.get('note', '')}")

    if "feasibility" in report:
        f = report["feasibility"]
        print(f"\n--- Decryption Feasibility ---")
        print(f"  Assessment: {f['feasibility']}")
        print(f"  Weaknesses:")
        for w in f.get("weaknesses", []):
            print(f"    [!] {w}")
        print(f"  Strong points:")
        for s in f.get("strong_points", []):
            print(f"    [+] {s}")
        print(f"  Recommendation: {f['recommendation']}")

    print(f"\n[*] Full report:\n{json.dumps(report, indent=2, default=str)}")
