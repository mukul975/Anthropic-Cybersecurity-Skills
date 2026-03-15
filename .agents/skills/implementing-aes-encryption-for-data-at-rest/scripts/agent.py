#!/usr/bin/env python3
"""Agent for implementing AES-256-GCM encryption for data at rest."""

import os
import json
import argparse
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # 256 bits
TAG_SIZE = 16
PBKDF2_ITERATIONS = 600_000


def derive_key(password, salt=None):
    """Derive AES-256 key from password using PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = os.urandom(SALT_SIZE)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = kdf.derive(password.encode("utf-8"))
    return key, salt


def encrypt_file(input_path, output_path, password):
    """Encrypt a file using AES-256-GCM with PBKDF2 key derivation."""
    key, salt = derive_key(password)
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)

    with open(input_path, "rb") as f:
        plaintext = f.read()

    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    with open(output_path, "wb") as f:
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)

    return {
        "input": str(input_path),
        "output": str(output_path),
        "original_size": len(plaintext),
        "encrypted_size": SALT_SIZE + NONCE_SIZE + len(ciphertext),
        "algorithm": "AES-256-GCM",
        "kdf": f"PBKDF2-HMAC-SHA256 ({PBKDF2_ITERATIONS} iterations)",
    }


def decrypt_file(input_path, output_path, password):
    """Decrypt an AES-256-GCM encrypted file."""
    with open(input_path, "rb") as f:
        salt = f.read(SALT_SIZE)
        nonce = f.read(NONCE_SIZE)
        ciphertext = f.read()

    key, _ = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    with open(output_path, "wb") as f:
        f.write(plaintext)

    return {
        "input": str(input_path),
        "output": str(output_path),
        "decrypted_size": len(plaintext),
    }


def encrypt_directory(dir_path, output_dir, password):
    """Encrypt all files in a directory tree."""
    src = Path(dir_path)
    dst = Path(output_dir)
    dst.mkdir(parents=True, exist_ok=True)
    results = []
    for filepath in src.rglob("*"):
        if filepath.is_file():
            rel = filepath.relative_to(src)
            out = dst / (str(rel) + ".enc")
            out.parent.mkdir(parents=True, exist_ok=True)
            result = encrypt_file(str(filepath), str(out), password)
            results.append(result)
    return results


def generate_random_key():
    """Generate a random AES-256 key."""
    key = os.urandom(KEY_SIZE)
    return {
        "key_hex": key.hex(),
        "key_size_bits": KEY_SIZE * 8,
        "algorithm": "AES-256",
    }


def verify_encryption(original_path, encrypted_path, password):
    """Verify encryption by decrypting and comparing."""
    with open(original_path, "rb") as f:
        original = f.read()

    with open(encrypted_path, "rb") as f:
        salt = f.read(SALT_SIZE)
        nonce = f.read(NONCE_SIZE)
        ciphertext = f.read()

    key, _ = derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        match = original == decrypted
        return {"status": "PASS" if match else "FAIL", "content_match": match}
    except Exception as e:
        return {"status": "FAIL", "error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="AES-256-GCM Encryption Agent")
    parser.add_argument("--action", required=True,
                        choices=["encrypt", "decrypt", "encrypt_dir", "genkey", "verify"])
    parser.add_argument("--input", help="Input file or directory")
    parser.add_argument("--output", help="Output file or directory")
    parser.add_argument("--password", help="Encryption password")
    parser.add_argument("--report", default="aes_encryption_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "action": args.action}

    if args.action == "encrypt":
        result = encrypt_file(args.input, args.output, args.password)
        report["result"] = result
        print(f"[+] Encrypted: {args.input} -> {args.output}")

    elif args.action == "decrypt":
        result = decrypt_file(args.input, args.output, args.password)
        report["result"] = result
        print(f"[+] Decrypted: {args.input} -> {args.output}")

    elif args.action == "encrypt_dir":
        results = encrypt_directory(args.input, args.output, args.password)
        report["results"] = results
        print(f"[+] Encrypted {len(results)} files")

    elif args.action == "genkey":
        result = generate_random_key()
        report["result"] = result
        print(f"[+] Key: {result['key_hex']}")

    elif args.action == "verify":
        result = verify_encryption(args.input, args.output, args.password)
        report["result"] = result
        print(f"[+] Verification: {result['status']}")

    with open(args.report, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.report}")


if __name__ == "__main__":
    main()
