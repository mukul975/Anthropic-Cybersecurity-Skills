#!/usr/bin/env python3
"""Ed25519 digital signature agent using the cryptography library."""

import argparse
import base64
import hashlib
import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.exit("cryptography required: pip install cryptography")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def generate_keypair(output_dir: str, key_name: str = "ed25519") -> dict:
    """Generate Ed25519 keypair and save to PEM files."""
    private_key = Ed25519PrivateKey.generate()
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    priv_path = os.path.join(output_dir, f"{key_name}_private.pem")
    pub_path = os.path.join(output_dir, f"{key_name}_public.pem")
    with open(priv_path, "wb") as f:
        f.write(priv_pem)
    with open(pub_path, "wb") as f:
        f.write(pub_pem)
    logger.info("Keypair saved: %s, %s", priv_path, pub_path)
    return {"private_key_path": priv_path, "public_key_path": pub_path}


def load_private_key(path: str) -> Ed25519PrivateKey:
    """Load Ed25519 private key from PEM file."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(path: str) -> Ed25519PublicKey:
    """Load Ed25519 public key from PEM file."""
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def sign_message(private_key_path: str, message: bytes) -> dict:
    """Sign a message with Ed25519 private key."""
    key = load_private_key(private_key_path)
    signature = key.sign(message)
    return {
        "signature_b64": base64.b64encode(signature).decode(),
        "signature_hex": signature.hex(),
        "message_hash": hashlib.sha256(message).hexdigest(),
        "signature_bytes": len(signature),
    }


def sign_file(private_key_path: str, file_path: str) -> dict:
    """Sign a file with Ed25519 and write signature to .sig file."""
    with open(file_path, "rb") as f:
        data = f.read()
    result = sign_message(private_key_path, data)
    sig_path = file_path + ".ed25519.sig"
    with open(sig_path, "w") as f:
        json.dump({"signature": result["signature_b64"],
                    "file_hash": result["message_hash"],
                    "algorithm": "Ed25519",
                    "signed_at": datetime.utcnow().isoformat()}, f, indent=2)
    result["signature_file"] = sig_path
    return result


def verify_message(public_key_path: str, message: bytes, signature_b64: str) -> dict:
    """Verify an Ed25519 signature on a message."""
    key = load_public_key(public_key_path)
    signature = base64.b64decode(signature_b64)
    try:
        key.verify(signature, message)
        return {"valid": True, "algorithm": "Ed25519"}
    except InvalidSignature:
        return {"valid": False, "error": "Signature verification failed"}


def verify_file(public_key_path: str, file_path: str, sig_path: str) -> dict:
    """Verify a file's Ed25519 signature."""
    with open(file_path, "rb") as f:
        data = f.read()
    with open(sig_path) as f:
        sig_data = json.load(f)
    result = verify_message(public_key_path, data, sig_data["signature"])
    result["file"] = file_path
    result["file_hash"] = hashlib.sha256(data).hexdigest()
    result["hash_matches"] = result["file_hash"] == sig_data.get("file_hash", "")
    return result


def batch_verify(public_key_path: str, files: List[str]) -> List[dict]:
    """Verify signatures for multiple files."""
    results = []
    for file_path in files:
        sig_path = file_path + ".ed25519.sig"
        if os.path.isfile(sig_path):
            results.append(verify_file(public_key_path, file_path, sig_path))
        else:
            results.append({"file": file_path, "valid": False, "error": "No signature file"})
    return results


def main():
    parser = argparse.ArgumentParser(description="Ed25519 Digital Signature Agent")
    parser.add_argument("--generate-keys", action="store_true")
    parser.add_argument("--sign", help="File to sign")
    parser.add_argument("--verify", nargs="+", help="Files to verify")
    parser.add_argument("--private-key", help="Private key PEM path")
    parser.add_argument("--public-key", help="Public key PEM path")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--output", default="signature_report.json")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    if args.generate_keys:
        result = generate_keypair(args.output_dir)
        print(json.dumps(result, indent=2))
    elif args.sign and args.private_key:
        result = sign_file(args.private_key, args.sign)
        print(json.dumps(result, indent=2))
    elif args.verify and args.public_key:
        results = batch_verify(args.public_key, args.verify)
        report = {"verifications": results,
                  "valid": sum(1 for r in results if r.get("valid")),
                  "invalid": sum(1 for r in results if not r.get("valid"))}
        out_path = os.path.join(args.output_dir, args.output)
        with open(out_path, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
