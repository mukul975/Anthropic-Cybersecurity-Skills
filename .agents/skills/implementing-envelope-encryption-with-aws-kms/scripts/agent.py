#!/usr/bin/env python3
"""Agent for implementing envelope encryption using AWS KMS."""

import json
import argparse
import os
import base64
from datetime import datetime

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    boto3 = None

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    AESGCM = None

NONCE_SIZE = 12


def generate_data_key(kms_key_id, region="us-east-1"):
    """Generate a data encryption key using AWS KMS."""
    kms = boto3.client("kms", region_name=region)
    resp = kms.generate_data_key(KeyId=kms_key_id, KeySpec="AES_256")
    return {
        "plaintext_key": resp["Plaintext"],
        "encrypted_key": resp["CiphertextBlob"],
        "key_id": resp["KeyId"],
    }


def encrypt_data(plaintext_bytes, kms_key_id, region="us-east-1"):
    """Encrypt data using envelope encryption with AWS KMS."""
    key_data = generate_data_key(kms_key_id, region)
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key_data["plaintext_key"])
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)

    # Zero out plaintext key from memory
    key_data["plaintext_key"] = b"\x00" * 32

    envelope = {
        "encrypted_data_key": base64.b64encode(key_data["encrypted_key"]).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "kms_key_id": key_data["key_id"],
        "algorithm": "AES-256-GCM",
        "envelope_version": 1,
    }
    return envelope


def decrypt_data(envelope, region="us-east-1"):
    """Decrypt envelope-encrypted data using AWS KMS."""
    kms = boto3.client("kms", region_name=region)
    encrypted_key = base64.b64decode(envelope["encrypted_data_key"])
    resp = kms.decrypt(CiphertextBlob=encrypted_key)
    plaintext_key = resp["Plaintext"]

    nonce = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    aesgcm = AESGCM(plaintext_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    # Zero out plaintext key
    plaintext_key = b"\x00" * 32
    return plaintext


def encrypt_file(input_path, output_path, kms_key_id, region="us-east-1"):
    """Encrypt a file using envelope encryption."""
    with open(input_path, "rb") as f:
        plaintext = f.read()
    envelope = encrypt_data(plaintext, kms_key_id, region)
    with open(output_path, "w") as f:
        json.dump(envelope, f, indent=2)
    return {
        "input": str(input_path),
        "output": str(output_path),
        "original_size": len(plaintext),
        "kms_key_id": envelope["kms_key_id"],
    }


def decrypt_file(input_path, output_path, region="us-east-1"):
    """Decrypt an envelope-encrypted file."""
    with open(input_path, "r") as f:
        envelope = json.load(f)
    plaintext = decrypt_data(envelope, region)
    with open(output_path, "wb") as f:
        f.write(plaintext)
    return {"input": str(input_path), "output": str(output_path), "decrypted_size": len(plaintext)}


def list_kms_keys(region="us-east-1"):
    """List available KMS keys."""
    kms = boto3.client("kms", region_name=region)
    paginator = kms.get_paginator("list_keys")
    keys = []
    for page in paginator.paginate():
        for key in page["Keys"]:
            try:
                desc = kms.describe_key(KeyId=key["KeyId"])
                meta = desc["KeyMetadata"]
                keys.append({
                    "key_id": meta["KeyId"],
                    "arn": meta["Arn"],
                    "description": meta.get("Description", ""),
                    "state": meta["KeyState"],
                    "key_usage": meta["KeyUsage"],
                    "origin": meta["Origin"],
                })
            except ClientError:
                keys.append({"key_id": key["KeyId"], "error": "access denied"})
    return {"keys": keys, "total": len(keys)}


def audit_key_policy(key_id, region="us-east-1"):
    """Audit a KMS key's policy for overly permissive access."""
    kms = boto3.client("kms", region_name=region)
    policy = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
    findings = []
    for stmt in policy.get("Statement", []):
        principal = stmt.get("Principal", {})
        if principal == "*" or principal.get("AWS") == "*":
            findings.append({
                "severity": "HIGH",
                "finding": "Key policy allows access to all AWS principals",
                "statement_id": stmt.get("Sid", "unknown"),
            })
    return {"key_id": key_id, "policy": policy, "findings": findings}


def main():
    if not boto3 or not AESGCM:
        print(json.dumps({"error": "boto3 and cryptography required"}))
        return
    parser = argparse.ArgumentParser(description="AWS KMS Envelope Encryption Agent")
    parser.add_argument("--region", default="us-east-1")
    sub = parser.add_subparsers(dest="command")
    e = sub.add_parser("encrypt", help="Encrypt file with envelope encryption")
    e.add_argument("--input", required=True)
    e.add_argument("--output", required=True)
    e.add_argument("--key-id", required=True, help="KMS key ID or ARN")
    d = sub.add_parser("decrypt", help="Decrypt envelope-encrypted file")
    d.add_argument("--input", required=True)
    d.add_argument("--output", required=True)
    sub.add_parser("list-keys", help="List KMS keys")
    a = sub.add_parser("audit", help="Audit KMS key policy")
    a.add_argument("--key-id", required=True)
    args = parser.parse_args()
    if args.command == "encrypt":
        result = encrypt_file(args.input, args.output, args.key_id, args.region)
    elif args.command == "decrypt":
        result = decrypt_file(args.input, args.output, args.region)
    elif args.command == "list-keys":
        result = list_kms_keys(args.region)
    elif args.command == "audit":
        result = audit_key_policy(args.key_id, args.region)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
