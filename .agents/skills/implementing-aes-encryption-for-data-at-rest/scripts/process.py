#!/usr/bin/env python3
"""
AES-256-GCM Encryption for Data at Rest

Implements file and directory encryption using AES-256-GCM with
PBKDF2 key derivation. Supports single file, streaming large file,
and directory tree encryption.

Requirements:
    pip install cryptography

Usage:
    python process.py encrypt --input secret.pdf --output secret.pdf.enc --password "MySecurePass"
    python process.py decrypt --input secret.pdf.enc --output secret.pdf --password "MySecurePass"
    python process.py encrypt-dir --input ./sensitive/ --output ./encrypted/ --password "MySecurePass"
"""

import os
import sys
import json
import struct
import hashlib
import argparse
import logging
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Constants
SALT_LENGTH = 16          # 128-bit salt
NONCE_LENGTH = 12         # 96-bit nonce (recommended for GCM)
TAG_LENGTH = 16           # 128-bit authentication tag
KEY_LENGTH = 32           # 256-bit key
PBKDF2_ITERATIONS = 600_000  # OWASP 2024 recommendation
CHUNK_SIZE = 64 * 1024    # 64KB chunks for streaming
MAGIC_BYTES = b"AES256GCM"  # File format identifier
VERSION = 1


def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Derive a 256-bit encryption key from a password using PBKDF2-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    """
    Encrypt plaintext bytes using AES-256-GCM with PBKDF2 key derivation.

    Output format:
        MAGIC (9 bytes) || VERSION (1 byte) || SALT (16 bytes) || NONCE (12 bytes) || CIPHERTEXT+TAG (variable)

    The authentication tag is appended to ciphertext by AESGCM.
    """
    salt = os.urandom(SALT_LENGTH)
    nonce = os.urandom(NONCE_LENGTH)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    header = MAGIC_BYTES + struct.pack("B", VERSION)
    return header + salt + nonce + ciphertext


def decrypt_bytes(data: bytes, password: str) -> bytes:
    """
    Decrypt AES-256-GCM encrypted data.

    Raises:
        ValueError: If file format is invalid or authentication fails.
    """
    magic_len = len(MAGIC_BYTES)
    min_length = magic_len + 1 + SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH

    if len(data) < min_length:
        raise ValueError("Data too short to be a valid encrypted file")

    magic = data[:magic_len]
    if magic != MAGIC_BYTES:
        raise ValueError(f"Invalid file format: expected magic bytes {MAGIC_BYTES!r}, got {magic!r}")

    version = struct.unpack("B", data[magic_len : magic_len + 1])[0]
    if version != VERSION:
        raise ValueError(f"Unsupported version: {version}")

    offset = magic_len + 1
    salt = data[offset : offset + SALT_LENGTH]
    offset += SALT_LENGTH
    nonce = data[offset : offset + NONCE_LENGTH]
    offset += NONCE_LENGTH
    ciphertext = data[offset:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except Exception as e:
        raise ValueError(
            "Decryption failed: authentication tag verification failed. "
            "Either the password is wrong or the data has been tampered with."
        ) from e

    return plaintext


def encrypt_file(input_path: str, output_path: str, password: str) -> dict:
    """Encrypt a single file."""
    input_file = Path(input_path)
    if not input_file.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    plaintext = input_file.read_bytes()
    original_size = len(plaintext)
    original_hash = hashlib.sha256(plaintext).hexdigest()

    ciphertext = encrypt_bytes(plaintext, password)

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_bytes(ciphertext)

    encrypted_size = len(ciphertext)
    logger.info(f"Encrypted {input_path} -> {output_path} ({original_size} -> {encrypted_size} bytes)")

    return {
        "input": str(input_path),
        "output": str(output_path),
        "original_size": original_size,
        "encrypted_size": encrypted_size,
        "original_sha256": original_hash,
        "algorithm": "AES-256-GCM",
        "kdf": "PBKDF2-SHA256",
        "kdf_iterations": PBKDF2_ITERATIONS,
    }


def decrypt_file(input_path: str, output_path: str, password: str) -> dict:
    """Decrypt a single file."""
    input_file = Path(input_path)
    if not input_file.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    data = input_file.read_bytes()
    plaintext = decrypt_bytes(data, password)

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_bytes(plaintext)

    recovered_hash = hashlib.sha256(plaintext).hexdigest()
    logger.info(f"Decrypted {input_path} -> {output_path} ({len(plaintext)} bytes)")

    return {
        "input": str(input_path),
        "output": str(output_path),
        "decrypted_size": len(plaintext),
        "recovered_sha256": recovered_hash,
    }


def encrypt_directory(input_dir: str, output_dir: str, password: str) -> dict:
    """Encrypt all files in a directory tree, preserving structure."""
    input_path = Path(input_dir)
    output_path = Path(output_dir)

    if not input_path.is_dir():
        raise NotADirectoryError(f"Input is not a directory: {input_dir}")

    output_path.mkdir(parents=True, exist_ok=True)

    manifest = {
        "algorithm": "AES-256-GCM",
        "kdf": "PBKDF2-SHA256",
        "kdf_iterations": PBKDF2_ITERATIONS,
        "files": [],
    }

    file_count = 0
    total_original = 0
    total_encrypted = 0

    for file in sorted(input_path.rglob("*")):
        if file.is_file():
            relative = file.relative_to(input_path)
            encrypted_name = str(relative) + ".enc"
            dest = output_path / encrypted_name

            result = encrypt_file(str(file), str(dest), password)
            manifest["files"].append({
                "original_path": str(relative),
                "encrypted_path": encrypted_name,
                "original_sha256": result["original_sha256"],
                "original_size": result["original_size"],
            })

            file_count += 1
            total_original += result["original_size"]
            total_encrypted += result["encrypted_size"]

    manifest_path = output_path / "manifest.json"
    manifest_encrypted = encrypt_bytes(json.dumps(manifest, indent=2).encode(), password)
    (output_path / "manifest.json.enc").write_bytes(manifest_encrypted)

    logger.info(
        f"Encrypted {file_count} files from {input_dir} -> {output_dir} "
        f"({total_original} -> {total_encrypted} bytes)"
    )

    return {
        "files_encrypted": file_count,
        "total_original_bytes": total_original,
        "total_encrypted_bytes": total_encrypted,
        "output_directory": str(output_path),
    }


def decrypt_directory(input_dir: str, output_dir: str, password: str) -> dict:
    """Decrypt all .enc files in a directory tree."""
    input_path = Path(input_dir)
    output_path = Path(output_dir)

    if not input_path.is_dir():
        raise NotADirectoryError(f"Input is not a directory: {input_dir}")

    output_path.mkdir(parents=True, exist_ok=True)

    file_count = 0
    total_decrypted = 0

    for file in sorted(input_path.rglob("*.enc")):
        if file.name == "manifest.json.enc":
            continue
        if file.is_file():
            relative = file.relative_to(input_path)
            decrypted_name = str(relative).removesuffix(".enc")
            dest = output_path / decrypted_name

            result = decrypt_file(str(file), str(dest), password)
            file_count += 1
            total_decrypted += result["decrypted_size"]

    logger.info(f"Decrypted {file_count} files from {input_dir} -> {output_dir}")

    return {
        "files_decrypted": file_count,
        "total_decrypted_bytes": total_decrypted,
        "output_directory": str(output_path),
    }


def verify_roundtrip(test_data: bytes, password: str) -> bool:
    """Verify encryption/decryption roundtrip integrity."""
    encrypted = encrypt_bytes(test_data, password)
    decrypted = decrypt_bytes(encrypted, password)
    return decrypted == test_data


def main():
    parser = argparse.ArgumentParser(description="AES-256-GCM File Encryption Tool")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Encrypt command
    enc = subparsers.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("--input", "-i", required=True, help="Input file path")
    enc.add_argument("--output", "-o", required=True, help="Output file path")
    enc.add_argument("--password", "-p", required=True, help="Encryption password")

    # Decrypt command
    dec = subparsers.add_parser("decrypt", help="Decrypt a file")
    dec.add_argument("--input", "-i", required=True, help="Input file path")
    dec.add_argument("--output", "-o", required=True, help="Output file path")
    dec.add_argument("--password", "-p", required=True, help="Decryption password")

    # Encrypt directory command
    encdir = subparsers.add_parser("encrypt-dir", help="Encrypt a directory")
    encdir.add_argument("--input", "-i", required=True, help="Input directory path")
    encdir.add_argument("--output", "-o", required=True, help="Output directory path")
    encdir.add_argument("--password", "-p", required=True, help="Encryption password")

    # Decrypt directory command
    decdir = subparsers.add_parser("decrypt-dir", help="Decrypt a directory")
    decdir.add_argument("--input", "-i", required=True, help="Input directory path")
    decdir.add_argument("--output", "-o", required=True, help="Output directory path")
    decdir.add_argument("--password", "-p", required=True, help="Decryption password")

    # Verify command
    subparsers.add_parser("verify", help="Run roundtrip verification test")

    args = parser.parse_args()

    if args.command == "encrypt":
        result = encrypt_file(args.input, args.output, args.password)
        print(json.dumps(result, indent=2))
    elif args.command == "decrypt":
        result = decrypt_file(args.input, args.output, args.password)
        print(json.dumps(result, indent=2))
    elif args.command == "encrypt-dir":
        result = encrypt_directory(args.input, args.output, args.password)
        print(json.dumps(result, indent=2))
    elif args.command == "decrypt-dir":
        result = decrypt_directory(args.input, args.output, args.password)
        print(json.dumps(result, indent=2))
    elif args.command == "verify":
        test_data = b"The quick brown fox jumps over the lazy dog. " * 100
        password = "test_password_123!"
        success = verify_roundtrip(test_data, password)
        print(f"Roundtrip verification: {'PASSED' if success else 'FAILED'}")
        if not success:
            sys.exit(1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
