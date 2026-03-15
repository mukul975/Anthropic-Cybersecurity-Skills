#!/usr/bin/env python3
"""Agent for implementing end-to-end encryption (E2EE) for messaging using X25519 + AES-GCM."""

import json
import argparse
import os
from datetime import datetime

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes, serialization
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

NONCE_SIZE = 12
KEY_SIZE = 32
HKDF_INFO = b"e2ee-messaging-v1"


def generate_keypair():
    """Generate X25519 key pair for Diffie-Hellman key exchange."""
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    priv_bytes = private_key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    pub_bytes = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {
        "private_key_hex": priv_bytes.hex(),
        "public_key_hex": pub_bytes.hex(),
        "algorithm": "X25519",
    }


def derive_shared_secret(my_private_hex, their_public_hex):
    """Derive shared secret using X25519 ECDH + HKDF-SHA256."""
    my_private = X25519PrivateKey.from_private_bytes(bytes.fromhex(my_private_hex))
    their_public = X25519PublicKey.from_public_bytes(bytes.fromhex(their_public_hex))
    shared_key = my_private.exchange(their_public)
    derived_key = HKDF(
        algorithm=hashes.SHA256(), length=KEY_SIZE, salt=None, info=HKDF_INFO
    ).derive(shared_key)
    return derived_key


def encrypt_message(message, shared_key_hex):
    """Encrypt a message using AES-256-GCM with a shared key."""
    key = bytes.fromhex(shared_key_hex)
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, message.encode("utf-8"), None)
    return {
        "nonce_hex": nonce.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "algorithm": "AES-256-GCM",
    }


def decrypt_message(nonce_hex, ciphertext_hex, shared_key_hex):
    """Decrypt a message using AES-256-GCM."""
    key = bytes.fromhex(shared_key_hex)
    nonce = bytes.fromhex(nonce_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return {"plaintext": plaintext.decode("utf-8")}


def simulate_key_exchange(alice_name="Alice", bob_name="Bob"):
    """Simulate a complete key exchange between two parties."""
    alice_kp = generate_keypair()
    bob_kp = generate_keypair()

    alice_shared = derive_shared_secret(alice_kp["private_key_hex"], bob_kp["public_key_hex"])
    bob_shared = derive_shared_secret(bob_kp["private_key_hex"], alice_kp["public_key_hex"])

    keys_match = alice_shared == bob_shared
    return {
        "alice_public_key": alice_kp["public_key_hex"],
        "bob_public_key": bob_kp["public_key_hex"],
        "shared_secret_match": keys_match,
        "shared_key_hex": alice_shared.hex() if keys_match else None,
        "key_exchange": "X25519 ECDH",
        "kdf": "HKDF-SHA256",
        "encryption": "AES-256-GCM",
    }


def demo_full_flow():
    """Demonstrate complete E2EE message flow."""
    kx = simulate_key_exchange()
    if not kx["shared_secret_match"]:
        return {"error": "Key exchange failed"}
    shared_key = kx["shared_key_hex"]
    test_message = "Hello, this is an end-to-end encrypted message."
    encrypted = encrypt_message(test_message, shared_key)
    decrypted = decrypt_message(encrypted["nonce_hex"], encrypted["ciphertext_hex"], shared_key)
    return {
        "key_exchange": kx,
        "original_message": test_message,
        "encrypted": encrypted,
        "decrypted": decrypted,
        "integrity_check": decrypted["plaintext"] == test_message,
    }


def main():
    if not HAS_CRYPTO:
        print(json.dumps({"error": "cryptography library not installed"}))
        return
    parser = argparse.ArgumentParser(description="E2EE Messaging Agent (X25519 + AES-256-GCM)")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("keygen", help="Generate X25519 key pair")
    sub.add_parser("exchange", help="Simulate key exchange")
    sub.add_parser("demo", help="Full E2EE demo flow")
    e = sub.add_parser("encrypt", help="Encrypt message")
    e.add_argument("--message", required=True)
    e.add_argument("--key", required=True, help="Shared key hex")
    d = sub.add_parser("decrypt", help="Decrypt message")
    d.add_argument("--nonce", required=True)
    d.add_argument("--ciphertext", required=True)
    d.add_argument("--key", required=True, help="Shared key hex")
    args = parser.parse_args()
    if args.command == "keygen":
        result = generate_keypair()
    elif args.command == "exchange":
        result = simulate_key_exchange()
    elif args.command == "demo":
        result = demo_full_flow()
    elif args.command == "encrypt":
        result = encrypt_message(args.message, args.key)
    elif args.command == "decrypt":
        result = decrypt_message(args.nonce, args.ciphertext, args.key)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
