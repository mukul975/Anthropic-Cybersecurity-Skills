#!/usr/bin/env python3
"""Agent for testing API authentication weaknesses.

Tests JWT implementation flaws, unauthenticated endpoint access,
token lifecycle issues, password policy enforcement, and credential
brute-force resistance aligned with OWASP API2:2023.
"""

import json
import base64
import hmac
import hashlib
import sys
import time
from pathlib import Path
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None


COMMON_JWT_SECRETS = [
    "secret", "password", "123456", "jwt_secret", "supersecret",
    "key", "test", "admin", "changeme", "default",
    "your-256-bit-secret", "my-secret-key", "jwt-secret",
    "s3cr3t", "secret123", "mysecretkey", "apisecret",
]


class APIAuthTestAgent:
    """Tests API authentication mechanisms for weaknesses."""

    def __init__(self, base_url, output_dir="./api_auth_test"):
        self.base_url = base_url.rstrip("/")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    def _get(self, path, headers=None, timeout=10):
        if not requests:
            return None
        try:
            return requests.get(f"{self.base_url}{path}", headers=headers, timeout=timeout)
        except requests.RequestException:
            return None

    def _post(self, path, data=None, headers=None, timeout=10):
        if not requests:
            return None
        try:
            return requests.post(f"{self.base_url}{path}", json=data,
                                 headers=headers, timeout=timeout)
        except requests.RequestException:
            return None

    def decode_jwt(self, token):
        """Decode JWT header and payload without verification."""
        parts = token.split(".")
        if len(parts) != 3:
            return None, None
        def pad(s):
            return s + "=" * (4 - len(s) % 4)
        try:
            header = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
            payload = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
            return header, payload
        except Exception:
            return None, None

    def test_unauthenticated_endpoints(self, paths=None):
        """Test endpoints for missing authentication."""
        default_paths = [
            "/users", "/users/me", "/admin/users", "/admin/settings",
            "/health", "/metrics", "/debug", "/actuator", "/actuator/env",
            "/swagger.json", "/api-docs", "/graphql", "/config", "/status",
        ]
        open_endpoints = []
        for path in (paths or default_paths):
            resp = self._get(path)
            if resp and resp.status_code not in (401, 403, 404, 405):
                open_endpoints.append({
                    "path": path,
                    "status": resp.status_code,
                    "preview": resp.text[:100],
                })
                if path not in ("/health", "/status"):
                    self.findings.append({
                        "severity": "high" if "/admin" in path else "medium",
                        "type": "Unauthenticated Access",
                        "detail": f"{path} accessible without auth (HTTP {resp.status_code})",
                    })
        return open_endpoints

    def analyze_jwt(self, token):
        """Analyze JWT token for security issues."""
        header, payload = self.decode_jwt(token)
        if not header:
            return {"error": "Invalid JWT"}

        issues = []
        if header.get("alg") == "none":
            issues.append({"severity": "critical", "issue": "Algorithm set to 'none'"})
        if header.get("alg") in ("HS256", "HS384", "HS512"):
            issues.append({"severity": "info", "issue": "Symmetric HMAC algorithm - check for weak secrets"})
        if "exp" not in payload:
            issues.append({"severity": "high", "issue": "No expiration claim"})
        elif payload["exp"] - time.time() > 86400:
            ttl_hours = (payload["exp"] - time.time()) / 3600
            issues.append({"severity": "medium", "issue": f"Long TTL: {ttl_hours:.0f} hours"})

        sensitive = ["password", "ssn", "credit_card", "secret", "private_key"]
        for field in sensitive:
            if field in payload:
                issues.append({"severity": "high", "issue": f"Sensitive field '{field}' in payload"})

        missing_claims = [c for c in ["iss", "aud", "exp", "iat", "sub"] if c not in payload]
        if missing_claims:
            issues.append({"severity": "medium", "issue": f"Missing claims: {missing_claims}"})

        for issue in issues:
            self.findings.append({"severity": issue["severity"], "type": "JWT Issue", "detail": issue["issue"]})

        return {"header": header, "payload": payload, "issues": issues}

    def brute_force_jwt_secret(self, token):
        """Test JWT against common HMAC secrets."""
        header, _ = self.decode_jwt(token)
        if not header or header.get("alg") not in ("HS256", "HS384", "HS512"):
            return None

        parts = token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        signature = parts[2]

        alg_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        hash_func = alg_map[header["alg"]]

        for secret in COMMON_JWT_SECRETS:
            expected = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), signing_input, hash_func).digest()
            ).decode().rstrip("=")
            if expected == signature:
                self.findings.append({
                    "severity": "critical",
                    "type": "Weak JWT Secret",
                    "detail": f"JWT secret brute-forced: '{secret}'",
                })
                return secret
        return None

    def test_token_after_logout(self, token, logout_path="/auth/logout"):
        """Test if token remains valid after logout."""
        headers = {"Authorization": f"Bearer {token}"}
        self._post(logout_path, headers=headers)
        resp = self._get("/users/me", headers=headers)
        if resp and resp.status_code == 200:
            self.findings.append({
                "severity": "high",
                "type": "Token Not Revoked",
                "detail": "Token valid after logout - no server-side revocation",
            })
            return True
        return False

    def test_account_enumeration(self, login_path="/auth/login"):
        """Check for account enumeration via login response differences."""
        valid_resp = self._post(login_path,
                                {"username": "admin@example.com", "password": "wrong"})
        invalid_resp = self._post(login_path,
                                  {"username": "nonexistent_xyz@example.com", "password": "wrong"})
        if valid_resp and invalid_resp:
            if valid_resp.text != invalid_resp.text or valid_resp.status_code != invalid_resp.status_code:
                self.findings.append({
                    "severity": "medium",
                    "type": "Account Enumeration",
                    "detail": "Different responses for valid vs invalid accounts",
                })
                return True
        return False

    def generate_report(self, token=None):
        unauth = self.test_unauthenticated_endpoints()
        jwt_analysis = None
        secret_found = None
        if token:
            jwt_analysis = self.analyze_jwt(token)
            secret_found = self.brute_force_jwt_secret(token)

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "base_url": self.base_url,
            "unauthenticated_endpoints": unauth,
            "jwt_analysis": jwt_analysis,
            "secret_found": bool(secret_found),
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        out = self.output_dir / "api_auth_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <base_url> [--token <jwt>]")
        sys.exit(1)
    url = sys.argv[1]
    token = None
    if "--token" in sys.argv:
        token = sys.argv[sys.argv.index("--token") + 1]
    agent = APIAuthTestAgent(url)
    agent.generate_report(token)


if __name__ == "__main__":
    main()
