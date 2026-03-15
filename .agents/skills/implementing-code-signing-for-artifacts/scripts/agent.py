#!/usr/bin/env python3
"""Code signing verification agent using cryptography library for Ed25519/RSA signature operations."""

import argparse
import hashlib
import json
import logging
import os
import subprocess
import sys
from datetime import datetime
from typing import Dict, List, Optional

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.exit("cryptography required: pip install cryptography")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def compute_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """Compute hash digest of a file."""
    h = hashlib.new(algorithm)
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def generate_ed25519_keypair(output_dir: str) -> dict:
    """Generate Ed25519 signing keypair."""
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path = os.path.join(output_dir, "signing_key.pem")
    pub_path = os.path.join(output_dir, "signing_key.pub")
    with open(priv_path, "wb") as f:
        f.write(private_bytes)
    with open(pub_path, "wb") as f:
        f.write(public_bytes)
    return {"private_key": priv_path, "public_key": pub_path, "algorithm": "Ed25519"}


def sign_artifact(file_path: str, private_key_path: str) -> dict:
    """Sign a file artifact using Ed25519."""
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(file_path, "rb") as f:
        data = f.read()
    signature = private_key.sign(data)
    sig_path = file_path + ".sig"
    with open(sig_path, "wb") as f:
        f.write(signature)
    return {
        "file": file_path,
        "signature_file": sig_path,
        "hash_sha256": hashlib.sha256(data).hexdigest(),
        "algorithm": "Ed25519",
    }


def verify_signature(file_path: str, signature_path: str, public_key_path: str) -> dict:
    """Verify an Ed25519 signature against a file."""
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    with open(file_path, "rb") as f:
        data = f.read()
    with open(signature_path, "rb") as f:
        signature = f.read()
    try:
        public_key.verify(signature, data)
        return {"file": file_path, "valid": True, "algorithm": "Ed25519"}
    except InvalidSignature:
        return {"file": file_path, "valid": False, "error": "Invalid signature"}


def verify_cosign_signature(image: str) -> dict:
    """Verify container image signature using cosign CLI."""
    try:
        result = subprocess.run(
            ["cosign", "verify", image], capture_output=True, text=True, timeout=30)
        return {"image": image, "verified": result.returncode == 0,
                "output": result.stdout[:500]}
    except FileNotFoundError:
        return {"image": image, "error": "cosign not installed"}


def batch_verify(artifacts: List[dict], public_key_path: str) -> List[dict]:
    """Verify signatures for multiple artifacts."""
    results = []
    for art in artifacts:
        result = verify_signature(art["file"], art["signature"], public_key_path)
        results.append(result)
    return results


def generate_report(artifacts: List[str], public_key_path: str) -> dict:
    """Generate code signing verification report."""
    report = {"analysis_date": datetime.utcnow().isoformat(), "verifications": []}
    for art_path in artifacts:
        sig_path = art_path + ".sig"
        if os.path.isfile(sig_path):
            result = verify_signature(art_path, sig_path, public_key_path)
        else:
            result = {"file": art_path, "valid": False, "error": "No signature file found"}
        result["hash_sha256"] = compute_file_hash(art_path)
        report["verifications"].append(result)
    valid = sum(1 for v in report["verifications"] if v.get("valid"))
    report["summary"] = {
        "total": len(report["verifications"]),
        "valid": valid,
        "invalid": len(report["verifications"]) - valid,
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="Code Signing Verification Agent")
    parser.add_argument("--artifacts", nargs="+", help="Files to verify")
    parser.add_argument("--public-key", help="Path to public key PEM")
    parser.add_argument("--generate-keys", action="store_true", help="Generate new keypair")
    parser.add_argument("--sign", help="File to sign (requires --private-key)")
    parser.add_argument("--private-key", help="Path to private key PEM")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--output", default="signing_report.json")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    if args.generate_keys:
        keys = generate_ed25519_keypair(args.output_dir)
        print(json.dumps(keys, indent=2))
        return
    if args.sign and args.private_key:
        result = sign_artifact(args.sign, args.private_key)
        print(json.dumps(result, indent=2))
        return
    if args.artifacts and args.public_key:
        report = generate_report(args.artifacts, args.public_key)
        out_path = os.path.join(args.output_dir, args.output)
        with open(out_path, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report["summary"], indent=2))


if __name__ == "__main__":
    main()
