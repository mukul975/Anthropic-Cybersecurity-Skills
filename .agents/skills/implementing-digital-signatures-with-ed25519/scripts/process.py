#!/usr/bin/env python3
"""
Ed25519 Digital Signature Tool

Implements Ed25519 key generation, signing, verification, and a
simple code signing system.

Requirements:
    pip install cryptography

Usage:
    python process.py generate --output ./keys
    python process.py sign --key ./keys/private.pem --input document.pdf
    python process.py verify --key ./keys/public.pem --input document.pdf --signature document.pdf.sig
    python process.py code-sign --key ./keys/private.pem --artifact ./build/app.zip
    python process.py benchmark
"""

import os
import sys
import json
import time
import hashlib
import argparse
import logging
import datetime
import base64
from pathlib import Path
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def generate_ed25519_keypair(
    output_dir: str, passphrase: Optional[str] = None
) -> Dict:
    """Generate an Ed25519 key pair."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    if passphrase:
        enc = serialization.BestAvailableEncryption(passphrase.encode())
    else:
        enc = serialization.NoEncryption()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )
    (output_path / "private.pem").write_bytes(private_pem)

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (output_path / "public.pem").write_bytes(public_pem)

    # Compute fingerprint
    public_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fingerprint = hashlib.sha256(public_raw).hexdigest()

    metadata = {
        "algorithm": "Ed25519",
        "public_key_hex": public_raw.hex(),
        "fingerprint_sha256": fingerprint,
        "created_at": datetime.datetime.utcnow().isoformat() + "Z",
        "private_key_path": str(output_path / "private.pem"),
        "public_key_path": str(output_path / "public.pem"),
    }
    (output_path / "key_metadata.json").write_text(json.dumps(metadata, indent=2))

    logger.info(f"Ed25519 key pair generated in {output_dir}")
    logger.info(f"Fingerprint: {fingerprint}")
    return metadata


def load_private_key(path: str, passphrase: Optional[str] = None) -> Ed25519PrivateKey:
    """Load Ed25519 private key from PEM file."""
    data = Path(path).read_bytes()
    pwd = passphrase.encode() if passphrase else None
    key = serialization.load_pem_private_key(data, password=pwd)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("Key is not Ed25519")
    return key


def load_public_key(path: str) -> Ed25519PublicKey:
    """Load Ed25519 public key from PEM file."""
    data = Path(path).read_bytes()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("Key is not Ed25519")
    return key


def sign_data(data: bytes, private_key: Ed25519PrivateKey) -> bytes:
    """Sign data with Ed25519."""
    return private_key.sign(data)


def verify_data(data: bytes, signature: bytes, public_key: Ed25519PublicKey) -> bool:
    """Verify Ed25519 signature."""
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False


def sign_file(key_path: str, input_path: str, passphrase: Optional[str] = None) -> Dict:
    """Sign a file and save the signature."""
    private_key = load_private_key(key_path, passphrase)
    data = Path(input_path).read_bytes()

    signature = sign_data(data, private_key)
    sig_path = input_path + ".sig"
    Path(sig_path).write_bytes(signature)

    # Also save base64 signature for text-friendly contexts
    sig_b64_path = input_path + ".sig.b64"
    Path(sig_b64_path).write_text(base64.b64encode(signature).decode())

    file_hash = hashlib.sha256(data).hexdigest()

    logger.info(f"Signed {input_path} ({len(data)} bytes)")
    return {
        "file": input_path,
        "signature_file": sig_path,
        "signature_b64_file": sig_b64_path,
        "signature_hex": signature.hex(),
        "file_sha256": file_hash,
        "algorithm": "Ed25519",
    }


def verify_file(key_path: str, input_path: str, sig_path: str) -> Dict:
    """Verify a file's Ed25519 signature."""
    public_key = load_public_key(key_path)
    data = Path(input_path).read_bytes()
    signature = Path(sig_path).read_bytes()

    # Handle base64 encoded signatures
    if len(signature) != 64:
        try:
            signature = base64.b64decode(signature)
        except Exception:
            pass

    valid = verify_data(data, signature, public_key)
    logger.info(f"Verification: {'VALID' if valid else 'INVALID'}")

    return {
        "file": input_path,
        "valid": valid,
        "file_sha256": hashlib.sha256(data).hexdigest(),
        "algorithm": "Ed25519",
    }


def code_sign(key_path: str, artifact_path: str, passphrase: Optional[str] = None) -> Dict:
    """Create a code signing manifest for an artifact."""
    private_key = load_private_key(key_path, passphrase)
    data = Path(artifact_path).read_bytes()

    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    manifest = {
        "artifact": Path(artifact_path).name,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
        "signer_public_key": public_raw.hex(),
        "signer_fingerprint": hashlib.sha256(public_raw).hexdigest(),
        "signed_at": datetime.datetime.utcnow().isoformat() + "Z",
        "algorithm": "Ed25519",
    }

    manifest_json = json.dumps(manifest, indent=2, sort_keys=True).encode()
    signature = sign_data(manifest_json, private_key)

    signed_manifest = {
        **manifest,
        "signature": base64.b64encode(signature).decode(),
    }

    manifest_path = artifact_path + ".manifest.json"
    Path(manifest_path).write_text(json.dumps(signed_manifest, indent=2))

    logger.info(f"Code signed: {artifact_path}")
    return signed_manifest


def verify_code_signature(manifest_path: str, artifact_path: str) -> Dict:
    """Verify a code signing manifest."""
    signed_manifest = json.loads(Path(manifest_path).read_text())
    signature = base64.b64decode(signed_manifest["signature"])

    public_raw = bytes.fromhex(signed_manifest["signer_public_key"])
    public_key = Ed25519PublicKey.from_public_bytes(public_raw)

    manifest_copy = {k: v for k, v in signed_manifest.items() if k != "signature"}
    manifest_json = json.dumps(manifest_copy, indent=2, sort_keys=True).encode()

    sig_valid = verify_data(manifest_json, signature, public_key)

    data = Path(artifact_path).read_bytes()
    hash_valid = hashlib.sha256(data).hexdigest() == signed_manifest["sha256"]

    return {
        "artifact": artifact_path,
        "signature_valid": sig_valid,
        "hash_valid": hash_valid,
        "overall_valid": sig_valid and hash_valid,
        "signer_fingerprint": signed_manifest["signer_fingerprint"],
    }


def benchmark():
    """Benchmark Ed25519 operations."""
    print("=== Ed25519 Benchmark ===\n")

    # Key generation
    count = 1000
    start = time.time()
    for _ in range(count):
        Ed25519PrivateKey.generate()
    elapsed = time.time() - start
    print(f"Key generation: {count / elapsed:.0f} keys/s ({elapsed / count * 1e6:.1f} us/key)")

    # Signing
    key = Ed25519PrivateKey.generate()
    message = b"Benchmark message for Ed25519 signing performance test." * 10
    count = 5000
    start = time.time()
    for _ in range(count):
        key.sign(message)
    elapsed = time.time() - start
    print(f"Signing:        {count / elapsed:.0f} sigs/s ({elapsed / count * 1e6:.1f} us/sig)")

    # Verification
    public_key = key.public_key()
    signature = key.sign(message)
    count = 2000
    start = time.time()
    for _ in range(count):
        public_key.verify(signature, message)
    elapsed = time.time() - start
    print(f"Verification:   {count / elapsed:.0f} verifs/s ({elapsed / count * 1e6:.1f} us/verify)")


def main():
    parser = argparse.ArgumentParser(description="Ed25519 Digital Signature Tool")
    subparsers = parser.add_subparsers(dest="command")

    gen = subparsers.add_parser("generate", help="Generate Ed25519 key pair")
    gen.add_argument("--output", "-o", default="./keys", help="Output directory")
    gen.add_argument("--passphrase", "-p", help="Passphrase for private key")

    sig = subparsers.add_parser("sign", help="Sign a file")
    sig.add_argument("--key", required=True, help="Private key path")
    sig.add_argument("--input", "-i", required=True, help="File to sign")
    sig.add_argument("--passphrase", "-p", help="Key passphrase")

    ver = subparsers.add_parser("verify", help="Verify signature")
    ver.add_argument("--key", required=True, help="Public key path")
    ver.add_argument("--input", "-i", required=True, help="File to verify")
    ver.add_argument("--signature", "-s", required=True, help="Signature file")

    cs = subparsers.add_parser("code-sign", help="Code sign an artifact")
    cs.add_argument("--key", required=True, help="Private key path")
    cs.add_argument("--artifact", required=True, help="Artifact to sign")
    cs.add_argument("--passphrase", "-p", help="Key passphrase")

    csv = subparsers.add_parser("code-verify", help="Verify code signature")
    csv.add_argument("--manifest", required=True, help="Manifest file path")
    csv.add_argument("--artifact", required=True, help="Artifact file path")

    subparsers.add_parser("benchmark", help="Benchmark Ed25519 performance")

    args = parser.parse_args()

    if args.command == "generate":
        result = generate_ed25519_keypair(args.output, args.passphrase)
        print(json.dumps(result, indent=2))
    elif args.command == "sign":
        result = sign_file(args.key, args.input, args.passphrase)
        print(json.dumps(result, indent=2))
    elif args.command == "verify":
        result = verify_file(args.key, args.input, args.signature)
        print(json.dumps(result, indent=2))
    elif args.command == "code-sign":
        result = code_sign(args.key, args.artifact, args.passphrase)
        print(json.dumps(result, indent=2))
    elif args.command == "code-verify":
        result = verify_code_signature(args.manifest, args.artifact)
        print(json.dumps(result, indent=2))
    elif args.command == "benchmark":
        benchmark()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
