#!/usr/bin/env python3
"""Agent for implementing zero-knowledge proof authentication using Schnorr protocol."""

import hashlib
import secrets
import json
import argparse
import sys
from datetime import datetime


# Safe prime and generator for discrete log ZKP
SAFE_PRIME = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
GENERATOR = 2


def generate_keypair():
    """Generate a ZKP key pair (private key x, public key y = g^x mod p)."""
    x = secrets.randbelow(SAFE_PRIME - 2) + 1
    y = pow(GENERATOR, x, SAFE_PRIME)
    print(f"[*] Generated key pair")
    print(f"  Public key (y): {hex(y)[:40]}...")
    return x, y


def schnorr_prove(private_key):
    """Generate a Schnorr ZKP proof (commitment, challenge, response)."""
    k = secrets.randbelow(SAFE_PRIME - 2) + 1
    r = pow(GENERATOR, k, SAFE_PRIME)
    # Fiat-Shamir heuristic: non-interactive challenge
    c_input = f"{GENERATOR}{r}{pow(GENERATOR, private_key, SAFE_PRIME)}"
    c = int(hashlib.sha256(c_input.encode()).hexdigest(), 16) % SAFE_PRIME
    s = (k - c * private_key) % (SAFE_PRIME - 1)
    return {"commitment": r, "challenge": c, "response": s}


def schnorr_verify(public_key, proof):
    """Verify a Schnorr ZKP proof without learning the private key."""
    r, c, s = proof["commitment"], proof["challenge"], proof["response"]
    lhs = pow(GENERATOR, s, SAFE_PRIME) * pow(public_key, c, SAFE_PRIME) % SAFE_PRIME
    valid = lhs == r
    print(f"  [{'+'if valid else '!'}] Verification: {'PASSED' if valid else 'FAILED'}")
    return valid


def zkp_password_register(password):
    """Register a password using ZKP (server stores only public key)."""
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    x = int.from_bytes(pwd_hash, "big") % (SAFE_PRIME - 2) + 1
    y = pow(GENERATOR, x, SAFE_PRIME)
    print(f"[*] Registered user (server stores salt + public key, never the password)")
    return {"salt": salt, "public_key": y, "private_key": x}


def zkp_password_authenticate(password, registration):
    """Authenticate using ZKP (prove password knowledge without revealing it)."""
    salt = registration["salt"]
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    x = int.from_bytes(pwd_hash, "big") % (SAFE_PRIME - 2) + 1
    proof = schnorr_prove(x)
    valid = schnorr_verify(registration["public_key"], proof)
    return valid


def run_protocol_demo(rounds=5):
    """Demonstrate ZKP authentication protocol with multiple rounds."""
    print("[*] ZKP Schnorr Protocol Demo\n")
    x, y = generate_keypair()
    successes = 0
    for i in range(rounds):
        print(f"\n[*] Round {i+1}/{rounds}")
        proof = schnorr_prove(x)
        if schnorr_verify(y, proof):
            successes += 1
    print(f"\n[*] Protocol: {successes}/{rounds} rounds passed")
    print(f"[*] Completeness: {'VERIFIED' if successes == rounds else 'FAILED'}")
    # Soundness test: wrong key should fail
    wrong_x = secrets.randbelow(SAFE_PRIME - 2) + 1
    wrong_proof = schnorr_prove(wrong_x)
    forgery = schnorr_verify(y, wrong_proof)
    print(f"[*] Soundness (wrong key rejected): {'VERIFIED' if not forgery else 'FAILED'}")
    return successes == rounds and not forgery


def run_password_demo(password="SecureP@ss123"):
    """Demonstrate ZKP password authentication."""
    print("\n[*] ZKP Password Authentication Demo\n")
    reg = zkp_password_register(password)
    print("\n[*] Authenticating with correct password...")
    ok = zkp_password_authenticate(password, reg)
    print(f"  Result: {'Authenticated' if ok else 'Rejected'}")
    print("\n[*] Authenticating with wrong password...")
    bad = zkp_password_authenticate("WrongPassword", reg)
    print(f"  Result: {'Authenticated' if bad else 'Rejected'}")
    return ok and not bad


def main():
    parser = argparse.ArgumentParser(description="Zero-Knowledge Proof Authentication Agent")
    parser.add_argument("action", choices=["demo-protocol", "demo-password", "keygen", "full-test"])
    parser.add_argument("--rounds", type=int, default=5, help="Protocol verification rounds")
    parser.add_argument("--password", default="SecureP@ss123", help="Password for ZKP demo")
    parser.add_argument("-o", "--output", default="zkp_report.json")
    args = parser.parse_args()

    report = {"date": datetime.now().isoformat(), "action": args.action}
    if args.action == "keygen":
        x, y = generate_keypair()
        report["public_key"] = hex(y)
    elif args.action == "demo-protocol":
        report["protocol_valid"] = run_protocol_demo(args.rounds)
    elif args.action == "demo-password":
        report["password_auth_valid"] = run_password_demo(args.password)
    elif args.action == "full-test":
        report["protocol_valid"] = run_protocol_demo(args.rounds)
        report["password_auth_valid"] = run_password_demo(args.password)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[*] Report saved to {args.output}")


if __name__ == "__main__":
    main()
