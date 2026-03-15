#!/usr/bin/env python3
"""
RSA Key Pair Management Tool

Implements RSA key generation, serialization, signing, verification,
encryption, and key rotation using the cryptography library.

Requirements:
    pip install cryptography

Usage:
    python process.py generate --size 4096 --output ./keys --passphrase "MyKeyPass"
    python process.py sign --key ./keys/private.pem --input document.pdf --passphrase "MyKeyPass"
    python process.py verify --key ./keys/public.pem --input document.pdf --signature document.pdf.sig
    python process.py info --key ./keys/public.pem
    python process.py rotate --keystore ./keys --passphrase "MyKeyPass"
"""

import os
import sys
import json
import hashlib
import argparse
import logging
import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

RECOMMENDED_KEY_SIZE = 4096
PUBLIC_EXPONENT = 65537


def generate_rsa_keypair(
    key_size: int = RECOMMENDED_KEY_SIZE,
    passphrase: Optional[str] = None,
) -> Tuple[bytes, bytes, Dict]:
    """
    Generate an RSA key pair.

    Returns:
        Tuple of (private_key_pem, public_key_pem, metadata)
    """
    if key_size < 2048:
        raise ValueError("Key size must be at least 2048 bits (3072+ recommended)")

    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=key_size,
        backend=default_backend(),
    )

    if passphrase:
        encryption = serialization.BestAvailableEncryption(passphrase.encode())
    else:
        encryption = serialization.NoEncryption()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Compute fingerprint (SHA-256 of DER-encoded public key)
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = hashlib.sha256(public_der).hexdigest()

    metadata = {
        "algorithm": "RSA",
        "key_size": key_size,
        "public_exponent": PUBLIC_EXPONENT,
        "fingerprint_sha256": fingerprint,
        "created_at": datetime.datetime.utcnow().isoformat() + "Z",
        "passphrase_protected": passphrase is not None,
        "format": "PKCS#8 PEM",
    }

    return private_pem, public_pem, metadata


def save_keypair(
    output_dir: str,
    private_pem: bytes,
    public_pem: bytes,
    metadata: Dict,
    version: int = 1,
) -> Dict:
    """Save key pair to files with metadata."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    prefix = f"v{version}_" if version > 1 else ""

    private_path = output_path / f"{prefix}private.pem"
    public_path = output_path / f"{prefix}public.pem"
    meta_path = output_path / f"{prefix}key_metadata.json"

    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)

    metadata["version"] = version
    metadata["private_key_path"] = str(private_path)
    metadata["public_key_path"] = str(public_path)

    meta_path.write_text(json.dumps(metadata, indent=2))

    logger.info(f"Key pair saved to {output_dir} (version {version})")

    return metadata


def load_private_key(key_path: str, passphrase: Optional[str] = None):
    """Load an RSA private key from PEM file."""
    key_data = Path(key_path).read_bytes()
    pwd = passphrase.encode() if passphrase else None
    return serialization.load_pem_private_key(key_data, password=pwd, backend=default_backend())


def load_public_key(key_path: str):
    """Load an RSA public key from PEM file."""
    key_data = Path(key_path).read_bytes()
    return serialization.load_pem_public_key(key_data, backend=default_backend())


def sign_data(data: bytes, private_key) -> bytes:
    """Sign data using RSA-PSS with SHA-256."""
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


def verify_signature(data: bytes, signature: bytes, public_key) -> bool:
    """Verify RSA-PSS signature."""
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def encrypt_data(plaintext: bytes, public_key) -> bytes:
    """Encrypt data using RSA-OAEP."""
    max_size = (public_key.key_size // 8) - 2 * 32 - 2  # OAEP with SHA-256
    if len(plaintext) > max_size:
        raise ValueError(
            f"Plaintext too large for RSA-OAEP ({len(plaintext)} bytes, max {max_size}). "
            "Use envelope encryption for large data."
        )
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt_data(ciphertext: bytes, private_key) -> bytes:
    """Decrypt RSA-OAEP encrypted data."""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def get_key_info(key_path: str, passphrase: Optional[str] = None) -> Dict:
    """Get information about an RSA key."""
    key_data = Path(key_path).read_bytes()

    try:
        pwd = passphrase.encode() if passphrase else None
        key = serialization.load_pem_private_key(key_data, password=pwd, backend=default_backend())
        key_type = "private"
        public_key = key.public_key()
    except (ValueError, TypeError):
        key = serialization.load_pem_public_key(key_data, backend=default_backend())
        key_type = "public"
        public_key = key

    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = hashlib.sha256(public_der).hexdigest()

    numbers = public_key.public_numbers()

    info = {
        "key_type": key_type,
        "algorithm": "RSA",
        "key_size": public_key.key_size,
        "public_exponent": numbers.e,
        "fingerprint_sha256": fingerprint,
        "modulus_hex_prefix": hex(numbers.n)[:32] + "...",
    }

    if public_key.key_size < 2048:
        info["warning"] = "Key size below 2048 bits is considered insecure"
    elif public_key.key_size < 3072:
        info["note"] = "Key size below 3072 bits; consider upgrading for post-2030 use"

    return info


def rotate_keys(keystore_dir: str, passphrase: Optional[str] = None) -> Dict:
    """Rotate RSA key pair, archiving the old one."""
    keystore = Path(keystore_dir)

    # Find current version
    version = 1
    meta_files = sorted(keystore.glob("*key_metadata.json"))
    if meta_files:
        for mf in meta_files:
            meta = json.loads(mf.read_text())
            v = meta.get("version", 1)
            if v >= version:
                version = v + 1

    # Generate new key pair
    private_pem, public_pem, metadata = generate_rsa_keypair(
        key_size=RECOMMENDED_KEY_SIZE, passphrase=passphrase
    )

    result = save_keypair(keystore_dir, private_pem, public_pem, metadata, version=version)

    # Update current key symlink info
    current_meta = {
        "current_version": version,
        "current_fingerprint": metadata["fingerprint_sha256"],
        "rotated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "all_versions": list(range(1, version + 1)),
    }
    (keystore / "current.json").write_text(json.dumps(current_meta, indent=2))

    logger.info(f"Key rotated to version {version}")
    return result


def sign_file(key_path: str, input_path: str, passphrase: Optional[str] = None) -> str:
    """Sign a file and save the signature."""
    private_key = load_private_key(key_path, passphrase)
    data = Path(input_path).read_bytes()
    signature = sign_data(data, private_key)

    sig_path = input_path + ".sig"
    Path(sig_path).write_bytes(signature)
    logger.info(f"Signature saved to {sig_path}")
    return sig_path


def verify_file(key_path: str, input_path: str, sig_path: str) -> bool:
    """Verify a file's signature."""
    public_key = load_public_key(key_path)
    data = Path(input_path).read_bytes()
    signature = Path(sig_path).read_bytes()
    valid = verify_signature(data, signature, public_key)
    logger.info(f"Signature verification: {'VALID' if valid else 'INVALID'}")
    return valid


def main():
    parser = argparse.ArgumentParser(description="RSA Key Pair Management Tool")
    subparsers = parser.add_subparsers(dest="command")

    gen = subparsers.add_parser("generate", help="Generate RSA key pair")
    gen.add_argument("--size", type=int, default=4096, help="Key size in bits")
    gen.add_argument("--output", "-o", default="./keys", help="Output directory")
    gen.add_argument("--passphrase", "-p", help="Passphrase for private key")

    sig = subparsers.add_parser("sign", help="Sign a file")
    sig.add_argument("--key", required=True, help="Private key path")
    sig.add_argument("--input", "-i", required=True, help="File to sign")
    sig.add_argument("--passphrase", "-p", help="Key passphrase")

    ver = subparsers.add_parser("verify", help="Verify a signature")
    ver.add_argument("--key", required=True, help="Public key path")
    ver.add_argument("--input", "-i", required=True, help="Original file")
    ver.add_argument("--signature", "-s", required=True, help="Signature file")

    info = subparsers.add_parser("info", help="Show key information")
    info.add_argument("--key", required=True, help="Key file path")
    info.add_argument("--passphrase", "-p", help="Key passphrase")

    rot = subparsers.add_parser("rotate", help="Rotate key pair")
    rot.add_argument("--keystore", required=True, help="Keystore directory")
    rot.add_argument("--passphrase", "-p", help="Passphrase for new key")

    args = parser.parse_args()

    if args.command == "generate":
        priv, pub, meta = generate_rsa_keypair(args.size, args.passphrase)
        result = save_keypair(args.output, priv, pub, meta)
        print(json.dumps(result, indent=2))
    elif args.command == "sign":
        sig_path = sign_file(args.key, args.input, args.passphrase)
        print(json.dumps({"signature_file": sig_path}))
    elif args.command == "verify":
        valid = verify_file(args.key, args.input, args.signature)
        print(json.dumps({"valid": valid}))
        if not valid:
            sys.exit(1)
    elif args.command == "info":
        result = get_key_info(args.key, args.passphrase)
        print(json.dumps(result, indent=2))
    elif args.command == "rotate":
        result = rotate_keys(args.keystore, args.passphrase)
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
