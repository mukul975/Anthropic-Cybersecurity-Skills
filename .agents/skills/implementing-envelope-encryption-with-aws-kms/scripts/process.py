#!/usr/bin/env python3
"""
Envelope Encryption with AWS KMS

Implements envelope encryption pattern using AWS KMS for master key management
and local AES-256-GCM for data encryption.

Requirements:
    pip install boto3 cryptography

Usage:
    python process.py encrypt --key-id alias/my-key --input data.json --output data.json.enc
    python process.py decrypt --input data.json.enc --output data.json
    python process.py encrypt-file --key-id alias/my-key --input largefile.zip --output largefile.zip.enc
    python process.py re-encrypt --key-id alias/new-key --input data.json.enc --output data.json.reenc

Environment:
    AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION
    or ~/.aws/credentials
"""

import os
import sys
import json
import struct
import argparse
import logging
import base64
import ctypes
from pathlib import Path
from typing import Dict, Optional, Tuple

import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

NONCE_LENGTH = 12
MAGIC_BYTES = b"ENVKMS01"


def secure_wipe(data: bytearray):
    """Attempt to securely wipe sensitive data from memory."""
    if isinstance(data, (bytearray, memoryview)):
        for i in range(len(data)):
            data[i] = 0


def generate_data_key(
    kms_client,
    key_id: str,
    encryption_context: Optional[Dict[str, str]] = None,
) -> Tuple[bytes, bytes]:
    """
    Generate a data encryption key (DEK) using AWS KMS.

    Returns:
        Tuple of (plaintext_key, encrypted_key)
    """
    params = {
        "KeyId": key_id,
        "KeySpec": "AES_256",
    }
    if encryption_context:
        params["EncryptionContext"] = encryption_context

    try:
        response = kms_client.generate_data_key(**params)
        plaintext_key = response["Plaintext"]
        encrypted_key = response["CiphertextBlob"]
        logger.info(f"Generated data key using KMS key: {key_id}")
        return plaintext_key, encrypted_key
    except ClientError as e:
        logger.error(f"KMS GenerateDataKey failed: {e}")
        raise


def decrypt_data_key(
    kms_client,
    encrypted_key: bytes,
    encryption_context: Optional[Dict[str, str]] = None,
) -> bytes:
    """Decrypt an encrypted data key using AWS KMS."""
    params = {"CiphertextBlob": encrypted_key}
    if encryption_context:
        params["EncryptionContext"] = encryption_context

    try:
        response = kms_client.decrypt(**params)
        return response["Plaintext"]
    except ClientError as e:
        logger.error(f"KMS Decrypt failed: {e}")
        raise


def re_encrypt_data_key(
    kms_client,
    encrypted_key: bytes,
    new_key_id: str,
    source_context: Optional[Dict[str, str]] = None,
    dest_context: Optional[Dict[str, str]] = None,
) -> bytes:
    """Re-encrypt a data key with a new master key without exposing plaintext."""
    params = {
        "CiphertextBlob": encrypted_key,
        "DestinationKeyId": new_key_id,
    }
    if source_context:
        params["SourceEncryptionContext"] = source_context
    if dest_context:
        params["DestinationEncryptionContext"] = dest_context

    try:
        response = kms_client.re_encrypt(**params)
        return response["CiphertextBlob"]
    except ClientError as e:
        logger.error(f"KMS ReEncrypt failed: {e}")
        raise


def envelope_encrypt(
    data: bytes,
    kms_client,
    key_id: str,
    encryption_context: Optional[Dict[str, str]] = None,
) -> bytes:
    """
    Encrypt data using envelope encryption.

    Output format:
        MAGIC (8 bytes) || encrypted_key_len (4 bytes, big-endian) ||
        encrypted_key (variable) || context_len (4 bytes) || context_json (variable) ||
        nonce (12 bytes) || ciphertext+tag (variable)
    """
    plaintext_key, encrypted_key = generate_data_key(kms_client, key_id, encryption_context)

    try:
        nonce = os.urandom(NONCE_LENGTH)
        aesgcm = AESGCM(plaintext_key)
        ciphertext = aesgcm.encrypt(nonce, data, associated_data=None)
    finally:
        # Wipe plaintext key
        if isinstance(plaintext_key, bytes):
            plaintext_key = bytearray(plaintext_key)
        secure_wipe(plaintext_key)

    context_json = json.dumps(encryption_context or {}).encode()

    output = bytearray()
    output.extend(MAGIC_BYTES)
    output.extend(struct.pack(">I", len(encrypted_key)))
    output.extend(encrypted_key)
    output.extend(struct.pack(">I", len(context_json)))
    output.extend(context_json)
    output.extend(nonce)
    output.extend(ciphertext)

    return bytes(output)


def envelope_decrypt(
    data: bytes,
    kms_client,
) -> Tuple[bytes, Dict]:
    """
    Decrypt envelope-encrypted data.

    Returns:
        Tuple of (plaintext, encryption_context)
    """
    if not data.startswith(MAGIC_BYTES):
        raise ValueError("Invalid envelope encryption format")

    offset = len(MAGIC_BYTES)

    enc_key_len = struct.unpack(">I", data[offset : offset + 4])[0]
    offset += 4
    encrypted_key = data[offset : offset + enc_key_len]
    offset += enc_key_len

    ctx_len = struct.unpack(">I", data[offset : offset + 4])[0]
    offset += 4
    context_json = data[offset : offset + ctx_len]
    offset += ctx_len
    encryption_context = json.loads(context_json.decode())

    nonce = data[offset : offset + NONCE_LENGTH]
    offset += NONCE_LENGTH
    ciphertext = data[offset:]

    plaintext_key = decrypt_data_key(
        kms_client,
        encrypted_key,
        encryption_context if encryption_context else None,
    )

    try:
        aesgcm = AESGCM(plaintext_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    finally:
        if isinstance(plaintext_key, bytes):
            plaintext_key = bytearray(plaintext_key)
        secure_wipe(plaintext_key)

    return plaintext, encryption_context


def envelope_re_encrypt(
    data: bytes,
    kms_client,
    new_key_id: str,
) -> bytes:
    """Re-encrypt an envelope-encrypted file with a new KMS key."""
    if not data.startswith(MAGIC_BYTES):
        raise ValueError("Invalid envelope encryption format")

    offset = len(MAGIC_BYTES)
    enc_key_len = struct.unpack(">I", data[offset : offset + 4])[0]
    offset += 4
    encrypted_key = data[offset : offset + enc_key_len]
    offset += enc_key_len

    ctx_len = struct.unpack(">I", data[offset : offset + 4])[0]
    ctx_start = offset + 4
    context_json = data[ctx_start : ctx_start + ctx_len]
    encryption_context = json.loads(context_json.decode())

    remainder = data[ctx_start + ctx_len :]

    new_encrypted_key = re_encrypt_data_key(
        kms_client,
        encrypted_key,
        new_key_id,
        source_context=encryption_context if encryption_context else None,
        dest_context=encryption_context if encryption_context else None,
    )

    output = bytearray()
    output.extend(MAGIC_BYTES)
    output.extend(struct.pack(">I", len(new_encrypted_key)))
    output.extend(new_encrypted_key)
    output.extend(struct.pack(">I", ctx_len))
    output.extend(context_json)
    output.extend(remainder)

    logger.info(f"Re-encrypted data key with new KMS key: {new_key_id}")
    return bytes(output)


def encrypt_file(
    input_path: str,
    output_path: str,
    kms_client,
    key_id: str,
    encryption_context: Optional[Dict[str, str]] = None,
) -> Dict:
    """Encrypt a file using envelope encryption."""
    plaintext = Path(input_path).read_bytes()

    if encryption_context is None:
        encryption_context = {"filename": Path(input_path).name}

    encrypted = envelope_encrypt(plaintext, kms_client, key_id, encryption_context)

    Path(output_path).write_bytes(encrypted)
    logger.info(f"Encrypted {input_path} -> {output_path}")

    return {
        "input": input_path,
        "output": output_path,
        "original_size": len(plaintext),
        "encrypted_size": len(encrypted),
        "kms_key_id": key_id,
        "encryption_context": encryption_context,
    }


def decrypt_file(input_path: str, output_path: str, kms_client) -> Dict:
    """Decrypt an envelope-encrypted file."""
    data = Path(input_path).read_bytes()
    plaintext, context = envelope_decrypt(data, kms_client)

    Path(output_path).write_bytes(plaintext)
    logger.info(f"Decrypted {input_path} -> {output_path}")

    return {
        "input": input_path,
        "output": output_path,
        "decrypted_size": len(plaintext),
        "encryption_context": context,
    }


def main():
    parser = argparse.ArgumentParser(description="Envelope Encryption with AWS KMS")
    parser.add_argument("--region", default=None, help="AWS region")
    parser.add_argument("--profile", default=None, help="AWS profile")
    subparsers = parser.add_subparsers(dest="command")

    enc = subparsers.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("--key-id", required=True, help="KMS key ID or alias")
    enc.add_argument("--input", "-i", required=True, help="Input file")
    enc.add_argument("--output", "-o", required=True, help="Output file")
    enc.add_argument("--context", help="Encryption context as JSON string")

    dec = subparsers.add_parser("decrypt", help="Decrypt a file")
    dec.add_argument("--input", "-i", required=True, help="Encrypted input file")
    dec.add_argument("--output", "-o", required=True, help="Output file")

    reenc = subparsers.add_parser("re-encrypt", help="Re-encrypt with new key")
    reenc.add_argument("--key-id", required=True, help="New KMS key ID or alias")
    reenc.add_argument("--input", "-i", required=True, help="Encrypted input file")
    reenc.add_argument("--output", "-o", required=True, help="Output file")

    args = parser.parse_args()

    session_kwargs = {}
    if args.region:
        session_kwargs["region_name"] = args.region
    if args.profile:
        session_kwargs["profile_name"] = args.profile

    session = boto3.Session(**session_kwargs)
    kms_client = session.client("kms")

    if args.command == "encrypt":
        context = json.loads(args.context) if args.context else None
        result = encrypt_file(args.input, args.output, kms_client, args.key_id, context)
        print(json.dumps(result, indent=2))
    elif args.command == "decrypt":
        result = decrypt_file(args.input, args.output, kms_client)
        print(json.dumps(result, indent=2))
    elif args.command == "re-encrypt":
        data = Path(args.input).read_bytes()
        result = envelope_re_encrypt(data, kms_client, args.key_id)
        Path(args.output).write_bytes(result)
        print(json.dumps({"input": args.input, "output": args.output, "new_key_id": args.key_id}))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
