#!/usr/bin/env python3
"""Agent for JWT signing, verification, and security auditing."""

import json
import argparse
import base64
import hmac
import hashlib
import time
from datetime import datetime

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, utils
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


def b64url_encode(data):
    """Base64url encode without padding."""
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(data):
    """Base64url decode with padding restoration."""
    padding_needed = 4 - len(data) % 4
    if padding_needed != 4:
        data += "=" * padding_needed
    return base64.urlsafe_b64decode(data)


def create_jwt_hs256(payload, secret):
    """Create a JWT signed with HMAC-SHA256."""
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header))
    payload_b64 = b64url_encode(json.dumps(payload))
    signing_input = f"{header_b64}.{payload_b64}"
    signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    sig_b64 = b64url_encode(signature)
    return f"{signing_input}.{sig_b64}"


def verify_jwt_hs256(token, secret):
    """Verify an HS256 JWT and return claims."""
    parts = token.split(".")
    if len(parts) != 3:
        return {"valid": False, "error": "Invalid token format"}
    header_b64, payload_b64, sig_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}"
    expected_sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    actual_sig = b64url_decode(sig_b64)
    if not hmac.compare_digest(expected_sig, actual_sig):
        return {"valid": False, "error": "Signature verification failed"}
    header = json.loads(b64url_decode(header_b64))
    payload = json.loads(b64url_decode(payload_b64))
    now = int(time.time())
    if payload.get("exp") and payload["exp"] < now:
        return {"valid": False, "error": "Token expired", "claims": payload}
    if payload.get("nbf") and payload["nbf"] > now:
        return {"valid": False, "error": "Token not yet valid", "claims": payload}
    return {"valid": True, "header": header, "claims": payload}


def decode_jwt_unsafe(token):
    """Decode a JWT without verification (for inspection only)."""
    parts = token.split(".")
    if len(parts) != 3:
        return {"error": "Invalid token format"}
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return {"header": header, "payload": payload, "signature_present": len(parts[2]) > 0}


def audit_jwt_security(token):
    """Audit a JWT for common security vulnerabilities."""
    findings = []
    decoded = decode_jwt_unsafe(token)
    if "error" in decoded:
        return [{"issue": decoded["error"], "severity": "HIGH"}]
    header = decoded["header"]
    payload = decoded["payload"]

    alg = header.get("alg", "")
    if alg == "none":
        findings.append({"issue": "Algorithm 'none' - unsigned token",
                         "severity": "CRITICAL"})
    if alg == "HS256" and header.get("jwk"):
        findings.append({"issue": "JWK in header with symmetric algorithm - key injection risk",
                         "severity": "CRITICAL"})
    if alg in ("HS256", "HS384", "HS512"):
        findings.append({"issue": f"Symmetric algorithm {alg} - shared secret risk",
                         "severity": "MEDIUM",
                         "recommendation": "Use RS256 or ES256 for multi-party verification"})

    if not payload.get("exp"):
        findings.append({"issue": "No expiration claim (exp)", "severity": "HIGH"})
    else:
        exp = payload["exp"]
        now = int(time.time())
        if exp - now > 86400:
            findings.append({"issue": f"Long expiration: {(exp - now) / 3600:.0f} hours",
                             "severity": "MEDIUM"})
    if not payload.get("iss"):
        findings.append({"issue": "No issuer claim (iss)", "severity": "MEDIUM"})
    if not payload.get("aud"):
        findings.append({"issue": "No audience claim (aud)", "severity": "MEDIUM"})
    if not payload.get("iat"):
        findings.append({"issue": "No issued-at claim (iat)", "severity": "LOW"})
    if not payload.get("jti"):
        findings.append({"issue": "No JWT ID (jti) - replay attack risk", "severity": "MEDIUM"})

    sensitive_keys = ["password", "secret", "ssn", "credit_card", "api_key"]
    for key in payload:
        if any(s in key.lower() for s in sensitive_keys):
            findings.append({"issue": f"Sensitive data in claim: {key}",
                             "severity": "HIGH"})

    return findings


def generate_rsa_keypair():
    """Generate RSA key pair for RS256 JWT signing."""
    if not HAS_CRYPTO:
        return {"error": "cryptography library not available"}
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return {"private_key": priv_pem, "public_key": pub_pem, "algorithm": "RS256"}


def main():
    parser = argparse.ArgumentParser(description="JWT Security Agent")
    parser.add_argument("--create", help="JSON payload to sign as JWT")
    parser.add_argument("--verify", help="JWT token to verify")
    parser.add_argument("--audit", help="JWT token to audit for vulnerabilities")
    parser.add_argument("--decode", help="JWT token to decode (no verification)")
    parser.add_argument("--secret", default="change-me-secret", help="HMAC secret")
    parser.add_argument("--gen-keys", action="store_true", help="Generate RSA key pair")
    parser.add_argument("--output", default="jwt_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "results": {}}

    if args.create:
        payload = json.loads(args.create)
        payload.setdefault("iat", int(time.time()))
        payload.setdefault("exp", int(time.time()) + 3600)
        token = create_jwt_hs256(payload, args.secret)
        report["results"]["token"] = token
        print(f"[+] JWT: {token[:50]}...")

    if args.verify:
        result = verify_jwt_hs256(args.verify, args.secret)
        report["results"]["verification"] = result
        print(f"[+] Valid: {result['valid']}")

    if args.audit:
        findings = audit_jwt_security(args.audit)
        report["results"]["audit"] = findings
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        print(f"[+] Audit: {len(findings)} findings, {critical} critical")

    if args.decode:
        decoded = decode_jwt_unsafe(args.decode)
        report["results"]["decoded"] = decoded
        print(f"[+] Algorithm: {decoded.get('header', {}).get('alg', 'unknown')}")

    if args.gen_keys:
        keys = generate_rsa_keypair()
        report["results"]["keys"] = keys
        print("[+] RSA-2048 key pair generated")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
