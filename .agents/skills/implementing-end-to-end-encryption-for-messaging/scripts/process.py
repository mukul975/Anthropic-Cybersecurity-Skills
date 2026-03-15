#!/usr/bin/env python3
"""
End-to-End Encryption for Messaging (Simplified Double Ratchet)

Implements a simplified version of the Signal Protocol's Double Ratchet
algorithm using X25519 key exchange, HKDF key derivation, and AES-256-GCM.

Requirements:
    pip install cryptography

Usage:
    python process.py demo
    python process.py benchmark --messages 1000
"""

import os
import sys
import json
import time
import struct
import hashlib
import argparse
import logging
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, List

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

INFO_ROOT_KEY = b"DoubleRatchetRootKey"
INFO_CHAIN_KEY = b"DoubleRatchetChainKey"
CHAIN_KEY_CONSTANT = b"\x01"
MESSAGE_KEY_CONSTANT = b"\x02"


def generate_x25519_keypair() -> Tuple[X25519PrivateKey, bytes]:
    """Generate an X25519 key pair, returning (private_key, public_key_bytes)."""
    private_key = X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private_key, public_bytes


def dh(private_key: X25519PrivateKey, public_key_bytes: bytes) -> bytes:
    """Perform X25519 Diffie-Hellman key exchange."""
    public_key = X25519PublicKey.from_public_bytes(public_key_bytes)
    return private_key.exchange(public_key)


def hkdf_derive(input_key: bytes, info: bytes, length: int = 64) -> bytes:
    """Derive key material using HKDF-SHA256."""
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=b"\x00" * 32,
        info=info,
        backend=default_backend(),
    ).derive(input_key)
    return derived


def hmac_derive(key: bytes, constant: bytes) -> bytes:
    """Derive a key using HMAC-SHA256."""
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(constant)
    return h.finalize()


def kdf_rk(root_key: bytes, dh_output: bytes) -> Tuple[bytes, bytes]:
    """Root key KDF: derive new root key and chain key from DH output."""
    derived = hkdf_derive(dh_output + root_key, INFO_ROOT_KEY, 64)
    new_root_key = derived[:32]
    new_chain_key = derived[32:]
    return new_root_key, new_chain_key


def kdf_ck(chain_key: bytes) -> Tuple[bytes, bytes]:
    """Chain key KDF: derive next chain key and message key."""
    new_chain_key = hmac_derive(chain_key, CHAIN_KEY_CONSTANT)
    message_key = hmac_derive(chain_key, MESSAGE_KEY_CONSTANT)
    return new_chain_key, message_key


def encrypt_message(message_key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """Encrypt a message using AES-256-GCM."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(message_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext


def decrypt_message(message_key: bytes, data: bytes, associated_data: bytes = b"") -> bytes:
    """Decrypt a message using AES-256-GCM."""
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(message_key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)


@dataclass
class MessageHeader:
    """Header included with each encrypted message."""
    dh_public_key: bytes
    previous_chain_length: int
    message_number: int

    def serialize(self) -> bytes:
        return (
            self.dh_public_key
            + struct.pack(">II", self.previous_chain_length, self.message_number)
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "MessageHeader":
        dh_public_key = data[:32]
        prev_chain_len, msg_num = struct.unpack(">II", data[32:40])
        return cls(dh_public_key, prev_chain_len, msg_num)


@dataclass
class DoubleRatchetState:
    """State for one side of the Double Ratchet."""
    dh_self_private: Optional[X25519PrivateKey] = None
    dh_self_public: bytes = b""
    dh_remote_public: bytes = b""
    root_key: bytes = b""
    sending_chain_key: Optional[bytes] = None
    receiving_chain_key: Optional[bytes] = None
    send_count: int = 0
    recv_count: int = 0
    previous_send_count: int = 0
    skipped_keys: Dict[Tuple[bytes, int], bytes] = field(default_factory=dict)
    max_skip: int = 100


def initialize_alice(shared_secret: bytes, bob_dh_public: bytes) -> DoubleRatchetState:
    """Initialize the ratchet for Alice (initiator)."""
    state = DoubleRatchetState()
    state.dh_remote_public = bob_dh_public

    state.dh_self_private, state.dh_self_public = generate_x25519_keypair()

    dh_output = dh(state.dh_self_private, bob_dh_public)
    state.root_key, state.sending_chain_key = kdf_rk(shared_secret, dh_output)
    state.receiving_chain_key = None
    state.send_count = 0
    state.recv_count = 0
    state.previous_send_count = 0

    return state


def initialize_bob(shared_secret: bytes, bob_dh_keypair: Tuple[X25519PrivateKey, bytes]) -> DoubleRatchetState:
    """Initialize the ratchet for Bob (responder)."""
    state = DoubleRatchetState()
    state.dh_self_private = bob_dh_keypair[0]
    state.dh_self_public = bob_dh_keypair[1]
    state.root_key = shared_secret
    state.sending_chain_key = None
    state.receiving_chain_key = None
    state.send_count = 0
    state.recv_count = 0
    state.previous_send_count = 0

    return state


def ratchet_encrypt(state: DoubleRatchetState, plaintext: bytes) -> Tuple[MessageHeader, bytes]:
    """Encrypt a message using the Double Ratchet."""
    state.sending_chain_key, message_key = kdf_ck(state.sending_chain_key)

    header = MessageHeader(
        dh_public_key=state.dh_self_public,
        previous_chain_length=state.previous_send_count,
        message_number=state.send_count,
    )

    ciphertext = encrypt_message(message_key, plaintext, header.serialize())
    state.send_count += 1

    return header, ciphertext


def dh_ratchet_step(state: DoubleRatchetState, header: MessageHeader):
    """Perform a DH ratchet step when receiving a new public key."""
    state.previous_send_count = state.send_count
    state.send_count = 0
    state.recv_count = 0
    state.dh_remote_public = header.dh_public_key

    dh_recv = dh(state.dh_self_private, state.dh_remote_public)
    state.root_key, state.receiving_chain_key = kdf_rk(state.root_key, dh_recv)

    state.dh_self_private, state.dh_self_public = generate_x25519_keypair()

    dh_send = dh(state.dh_self_private, state.dh_remote_public)
    state.root_key, state.sending_chain_key = kdf_rk(state.root_key, dh_send)


def skip_message_keys(state: DoubleRatchetState, until: int):
    """Skip and store message keys for out-of-order messages."""
    if state.receiving_chain_key is None:
        return
    while state.recv_count < until:
        state.receiving_chain_key, mk = kdf_ck(state.receiving_chain_key)
        state.skipped_keys[(state.dh_remote_public, state.recv_count)] = mk
        state.recv_count += 1
        if len(state.skipped_keys) > state.max_skip:
            oldest = next(iter(state.skipped_keys))
            del state.skipped_keys[oldest]


def ratchet_decrypt(state: DoubleRatchetState, header: MessageHeader, ciphertext: bytes) -> bytes:
    """Decrypt a message using the Double Ratchet."""
    # Check skipped keys
    skip_key = (header.dh_public_key, header.message_number)
    if skip_key in state.skipped_keys:
        mk = state.skipped_keys.pop(skip_key)
        return decrypt_message(mk, ciphertext, header.serialize())

    # DH ratchet step if new public key
    if header.dh_public_key != state.dh_remote_public:
        if state.receiving_chain_key is not None:
            skip_message_keys(state, header.previous_chain_length)
        dh_ratchet_step(state, header)

    skip_message_keys(state, header.message_number)
    state.receiving_chain_key, message_key = kdf_ck(state.receiving_chain_key)
    state.recv_count += 1

    return decrypt_message(message_key, ciphertext, header.serialize())


def demo_conversation():
    """Demonstrate a complete E2EE conversation."""
    print("=== End-to-End Encryption Demo ===\n")

    # Simulate X3DH: both parties derive the same shared secret
    alice_ik_private, alice_ik_public = generate_x25519_keypair()
    bob_ik_private, bob_ik_public = generate_x25519_keypair()
    bob_spk_private, bob_spk_public = generate_x25519_keypair()
    alice_ek_private, alice_ek_public = generate_x25519_keypair()

    # Alice computes shared secret
    dh1 = dh(alice_ik_private, bob_spk_public)
    dh2 = dh(alice_ek_private, bob_ik_public)
    dh3 = dh(alice_ek_private, bob_spk_public)
    alice_shared = hkdf_derive(dh1 + dh2 + dh3, b"X3DH", 32)

    # Bob computes same shared secret
    bob_ik_pub_obj = X25519PublicKey.from_public_bytes(alice_ik_public)
    bob_ek_pub_obj = X25519PublicKey.from_public_bytes(alice_ek_public)
    dh1_b = bob_spk_private.exchange(bob_ik_pub_obj)
    dh2_b = bob_ik_private.exchange(bob_ek_pub_obj)
    dh3_b = bob_spk_private.exchange(bob_ek_pub_obj)
    bob_shared = hkdf_derive(dh1_b + dh2_b + dh3_b, b"X3DH", 32)

    assert alice_shared == bob_shared, "X3DH shared secret mismatch!"
    print("[OK] X3DH key agreement: shared secrets match\n")

    # Initialize Double Ratchet
    bob_dh_private, bob_dh_public = generate_x25519_keypair()
    alice_state = initialize_alice(alice_shared, bob_dh_public)
    bob_state = initialize_bob(bob_shared, (bob_dh_private, bob_dh_public))

    # Alice sends messages to Bob
    messages = [
        b"Hello Bob! This is an encrypted message.",
        b"Can you read this?",
        b"This uses the Double Ratchet algorithm.",
    ]

    print("--- Alice sends to Bob ---")
    for msg in messages:
        header, ct = ratchet_encrypt(alice_state, msg)
        pt = ratchet_decrypt(bob_state, header, ct)
        print(f"  Alice -> Bob: {pt.decode()}")
        assert pt == msg

    # Bob replies to Alice
    replies = [
        b"Hi Alice! Yes, I can read your messages.",
        b"The DH ratchet just advanced!",
    ]

    print("\n--- Bob sends to Alice ---")
    for msg in replies:
        header, ct = ratchet_encrypt(bob_state, msg)
        pt = ratchet_decrypt(alice_state, header, ct)
        print(f"  Bob -> Alice: {pt.decode()}")
        assert pt == msg

    # Alice sends again (another DH ratchet)
    print("\n--- Alice sends again (new DH ratchet) ---")
    msg = b"This message uses a new DH ratchet step."
    header, ct = ratchet_encrypt(alice_state, msg)
    pt = ratchet_decrypt(bob_state, header, ct)
    print(f"  Alice -> Bob: {pt.decode()}")
    assert pt == msg

    print("\n[OK] All messages encrypted and decrypted successfully")
    print("[OK] Forward secrecy: each message uses a unique key")
    print("[OK] DH ratchet advanced on direction change")


def benchmark(num_messages: int = 1000):
    """Benchmark encryption/decryption throughput."""
    alice_ik_private, _ = generate_x25519_keypair()
    bob_spk_private, bob_spk_public = generate_x25519_keypair()
    shared = dh(alice_ik_private, bob_spk_public)
    shared_key = hkdf_derive(shared, b"benchmark", 32)

    bob_dh_private, bob_dh_public = generate_x25519_keypair()
    alice_state = initialize_alice(shared_key, bob_dh_public)
    bob_state = initialize_bob(shared_key, (bob_dh_private, bob_dh_public))

    message = b"Benchmark message for throughput testing. " * 10

    start = time.time()
    for _ in range(num_messages):
        header, ct = ratchet_encrypt(alice_state, message)
        pt = ratchet_decrypt(bob_state, header, ct)
    elapsed = time.time() - start

    print(f"Messages: {num_messages}")
    print(f"Time: {elapsed:.3f}s")
    print(f"Throughput: {num_messages / elapsed:.0f} msg/s")
    print(f"Latency: {elapsed / num_messages * 1000:.2f} ms/msg")


def main():
    parser = argparse.ArgumentParser(description="E2EE Messaging Demo")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("demo", help="Run E2EE conversation demo")

    bench = subparsers.add_parser("benchmark", help="Benchmark throughput")
    bench.add_argument("--messages", type=int, default=1000, help="Number of messages")

    args = parser.parse_args()

    if args.command == "demo":
        demo_conversation()
    elif args.command == "benchmark":
        benchmark(args.messages)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
