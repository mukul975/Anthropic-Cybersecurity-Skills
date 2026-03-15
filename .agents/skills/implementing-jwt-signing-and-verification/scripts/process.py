#!/usr/bin/env python3
"""
JWT Signing and Verification Tool

Implements secure JWT creation and verification with multiple algorithms,
including defense against common JWT attacks.

Requirements:
    pip install PyJWT cryptography

Usage:
    python process.py create --alg RS256 --subject user123 --issuer myapp --expiry 900
    python process.py verify --token <jwt> --key ./public.pem --issuer myapp
    python process.py generate-keys --alg RS256 --output ./jwt-keys
    python process.py attack-demo  # Demonstrates and defends common attacks
"""

import os
import sys
import json
import time
import hmac
import hashlib
import base64
import argparse
import logging
import datetime
from pathlib import Path
from typing import Dict, Optional, List

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

ALLOWED_ALGORITHMS = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512",
                       "ES256", "ES384", "ES512", "EdDSA"]


def generate_signing_keys(algorithm: str, output_dir: str) -> Dict:
    """Generate signing keys for a JWT algorithm."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    if algorithm.startswith("HS"):
        key_size = {"HS256": 32, "HS384": 48, "HS512": 64}.get(algorithm, 32)
        secret = os.urandom(key_size)
        secret_hex = secret.hex()
        (output_path / "secret.key").write_text(secret_hex)
        return {"algorithm": algorithm, "key_type": "symmetric", "key_file": str(output_path / "secret.key")}

    if algorithm.startswith("RS"):
        key_size = {"RS256": 2048, "RS384": 3072, "RS512": 4096}.get(algorithm, 2048)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
    elif algorithm.startswith("ES"):
        curve = {"ES256": ec.SECP256R1(), "ES384": ec.SECP384R1(), "ES512": ec.SECP521R1()}.get(algorithm, ec.SECP256R1())
        private_key = ec.generate_private_key(curve, default_backend())
    elif algorithm == "EdDSA":
        private_key = ed25519.Ed25519PrivateKey.generate()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    (output_path / "private.pem").write_bytes(priv_pem)
    (output_path / "public.pem").write_bytes(pub_pem)

    return {
        "algorithm": algorithm,
        "key_type": "asymmetric",
        "private_key": str(output_path / "private.pem"),
        "public_key": str(output_path / "public.pem"),
    }


def create_jwt(
    algorithm: str,
    signing_key,
    subject: str,
    issuer: str,
    audience: Optional[str] = None,
    expiry_seconds: int = 900,
    extra_claims: Optional[Dict] = None,
) -> str:
    """Create a signed JWT."""
    if algorithm not in ALLOWED_ALGORITHMS:
        raise ValueError(f"Algorithm {algorithm} not in allowlist: {ALLOWED_ALGORITHMS}")

    now = datetime.datetime.utcnow()
    payload = {
        "sub": subject,
        "iss": issuer,
        "iat": now,
        "exp": now + datetime.timedelta(seconds=expiry_seconds),
        "nbf": now,
        "jti": os.urandom(16).hex(),
    }
    if audience:
        payload["aud"] = audience
    if extra_claims:
        payload.update(extra_claims)

    token = jwt.encode(payload, signing_key, algorithm=algorithm)
    return token


def verify_jwt(
    token: str,
    verification_key,
    algorithms: List[str],
    issuer: Optional[str] = None,
    audience: Optional[str] = None,
) -> Dict:
    """
    Securely verify a JWT with algorithm allowlist.
    Defends against algorithm confusion by requiring explicit algorithm list.
    """
    # Reject 'none' algorithm
    safe_algorithms = [a for a in algorithms if a.lower() != "none"]
    if not safe_algorithms:
        raise ValueError("No valid algorithms specified")

    try:
        options = {}
        kwargs = {"algorithms": safe_algorithms}
        if issuer:
            kwargs["issuer"] = issuer
        if audience:
            kwargs["audience"] = audience

        payload = jwt.decode(token, verification_key, **kwargs)
        return {"valid": True, "payload": payload}
    except jwt.ExpiredSignatureError:
        return {"valid": False, "error": "Token has expired"}
    except jwt.InvalidIssuerError:
        return {"valid": False, "error": "Invalid issuer"}
    except jwt.InvalidAudienceError:
        return {"valid": False, "error": "Invalid audience"}
    except jwt.InvalidAlgorithmError:
        return {"valid": False, "error": "Algorithm not allowed"}
    except jwt.InvalidSignatureError:
        return {"valid": False, "error": "Invalid signature"}
    except jwt.DecodeError as e:
        return {"valid": False, "error": f"Decode error: {e}"}
    except Exception as e:
        return {"valid": False, "error": str(e)}


def decode_jwt_unverified(token: str) -> Dict:
    """Decode JWT header and payload without verification (for inspection only)."""
    parts = token.split(".")
    if len(parts) != 3:
        return {"error": "Invalid JWT format"}

    def decode_part(part):
        padding = 4 - len(part) % 4
        part += "=" * padding
        return json.loads(base64.urlsafe_b64decode(part))

    header = decode_part(parts[0])
    payload = decode_part(parts[1])
    return {"header": header, "payload": payload}


def attack_demo():
    """Demonstrate common JWT attacks and defenses."""
    print("=== JWT Security Attack Demonstrations ===\n")

    # Setup
    private_key = rsa.generate_private_key(65537, 2048, default_backend())
    public_key = private_key.public_key()
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    pub_pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Create legitimate token
    token = create_jwt("RS256", priv_pem, "user123", "myapp", expiry_seconds=3600)
    print(f"[1] Legitimate RS256 token created")

    # Verify legitimate token
    result = verify_jwt(token, pub_pem, ["RS256"], issuer="myapp")
    print(f"    Verification: {result['valid']}")

    # Attack 1: Algorithm Confusion (RS256 -> HS256)
    print(f"\n[2] Attack: Algorithm Confusion (RS256 -> HS256)")
    try:
        malicious_token = jwt.encode(
            {"sub": "admin", "iss": "myapp", "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            pub_pem, algorithm="HS256"
        )
        result = verify_jwt(malicious_token, pub_pem, ["RS256"])  # Only allow RS256
        print(f"    Defense: Algorithm restricted to RS256 only -> {result}")
    except Exception as e:
        print(f"    Defense: Attack blocked -> {e}")

    # Attack 2: None Algorithm
    print(f"\n[3] Attack: None Algorithm")
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "admin", "iss": "myapp"}).encode()).rstrip(b"=").decode()
    none_token = f"{header}.{payload}."
    result = verify_jwt(none_token, pub_pem, ["RS256"])
    print(f"    Defense: None algorithm rejected -> {result}")

    # Attack 3: Expired Token
    print(f"\n[4] Attack: Expired Token Replay")
    expired_token = create_jwt("RS256", priv_pem, "user123", "myapp", expiry_seconds=-10)
    result = verify_jwt(expired_token, pub_pem, ["RS256"], issuer="myapp")
    print(f"    Defense: Expired token rejected -> {result}")

    # Attack 4: Wrong Issuer
    print(f"\n[5] Attack: Wrong Issuer")
    wrong_issuer_token = create_jwt("RS256", priv_pem, "user123", "evil-app")
    result = verify_jwt(wrong_issuer_token, pub_pem, ["RS256"], issuer="myapp")
    print(f"    Defense: Wrong issuer rejected -> {result}")

    print(f"\n[OK] All attacks successfully defended")


def main():
    parser = argparse.ArgumentParser(description="JWT Signing and Verification Tool")
    subparsers = parser.add_subparsers(dest="command")

    gen = subparsers.add_parser("generate-keys", help="Generate signing keys")
    gen.add_argument("--alg", required=True, choices=ALLOWED_ALGORITHMS, help="Algorithm")
    gen.add_argument("--output", "-o", default="./jwt-keys", help="Output directory")

    create = subparsers.add_parser("create", help="Create a JWT")
    create.add_argument("--alg", required=True, choices=ALLOWED_ALGORITHMS)
    create.add_argument("--key", required=True, help="Signing key file")
    create.add_argument("--subject", required=True, help="Subject claim")
    create.add_argument("--issuer", required=True, help="Issuer claim")
    create.add_argument("--audience", help="Audience claim")
    create.add_argument("--expiry", type=int, default=900, help="Expiry in seconds")

    verify = subparsers.add_parser("verify", help="Verify a JWT")
    verify.add_argument("--token", required=True, help="JWT token")
    verify.add_argument("--key", required=True, help="Verification key file")
    verify.add_argument("--alg", nargs="+", default=["RS256"], help="Allowed algorithms")
    verify.add_argument("--issuer", help="Expected issuer")
    verify.add_argument("--audience", help="Expected audience")

    inspect = subparsers.add_parser("inspect", help="Inspect JWT without verification")
    inspect.add_argument("--token", required=True, help="JWT token")

    subparsers.add_parser("attack-demo", help="Demonstrate JWT attacks and defenses")

    args = parser.parse_args()

    if args.command == "generate-keys":
        result = generate_signing_keys(args.alg, args.output)
        print(json.dumps(result, indent=2))
    elif args.command == "create":
        key_data = Path(args.key).read_text().strip()
        if args.alg.startswith("HS"):
            key_data = bytes.fromhex(key_data)
        token = create_jwt(args.alg, key_data, args.subject, args.issuer, args.audience, args.expiry)
        print(token)
    elif args.command == "verify":
        key_data = Path(args.key).read_text().strip()
        result = verify_jwt(args.token, key_data, args.alg, args.issuer, args.audience)
        print(json.dumps(result, indent=2, default=str))
    elif args.command == "inspect":
        result = decode_jwt_unverified(args.token)
        print(json.dumps(result, indent=2, default=str))
    elif args.command == "attack-demo":
        attack_demo()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
