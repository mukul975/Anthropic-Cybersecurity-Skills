#!/usr/bin/env python3
"""Agent for testing mobile API authentication security.

Tests mobile app backend APIs for broken authentication, insecure
token management, session fixation, privilege escalation, and
IDOR vulnerabilities using intercepted traffic analysis.
"""

import json
import base64
import hashlib
import hmac
import sys
from pathlib import Path
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None


AUTH_ENDPOINTS = [
    "/api/v1/login", "/api/v1/register", "/api/v1/token",
    "/api/v1/refresh", "/api/v1/logout", "/api/v1/forgot-password",
    "/api/v1/reset-password", "/api/v1/verify-otp", "/api/v1/me",
    "/api/v2/auth/login", "/auth/token", "/oauth/token",
]

WEAK_SECRETS = [
    "secret", "password", "123456", "mobile_secret", "app_secret",
    "changeme", "default", "your-256-bit-secret", "s3cr3t",
]


class MobileAPIAuthAgent:
    """Tests mobile API authentication mechanisms."""

    def __init__(self, base_url, output_dir="./mobile_api_auth_test"):
        self.base_url = base_url.rstrip("/")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    def _req(self, method, path, **kwargs):
        if not requests:
            return None
        kwargs.setdefault("timeout", 10)
        try:
            return requests.request(method, f"{self.base_url}{path}", **kwargs)
        except requests.RequestException:
            return None

    def discover_auth_endpoints(self):
        """Probe common mobile auth endpoints."""
        found = []
        for ep in AUTH_ENDPOINTS:
            resp = self._req("OPTIONS", ep)
            if resp and resp.status_code != 404:
                found.append({"endpoint": ep, "status": resp.status_code,
                              "methods": resp.headers.get("Allow", "")})
        return found

    def test_no_auth_access(self, endpoints=None):
        """Test endpoints without authentication token."""
        targets = endpoints or ["/api/v1/me", "/api/v1/users", "/api/v1/orders",
                                "/api/v1/settings", "/api/v1/notifications"]
        results = []
        for ep in targets:
            resp = self._req("GET", ep)
            if resp and resp.status_code == 200:
                results.append({"endpoint": ep, "status": 200, "body_len": len(resp.text)})
                self.findings.append({"severity": "critical", "type": "No Auth Required",
                                      "detail": f"{ep} accessible without token"})
        return results

    def decode_jwt(self, token):
        parts = token.split(".")
        if len(parts) != 3:
            return None, None
        def pad(s): return s + "=" * (4 - len(s) % 4)
        try:
            header = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
            payload = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
            return header, payload
        except Exception:
            return None, None

    def analyze_token(self, token):
        """Analyze JWT for mobile-specific weaknesses."""
        header, payload = self.decode_jwt(token)
        if not header:
            return {"error": "Invalid token"}
        issues = []
        if header.get("alg") == "none":
            issues.append({"severity": "critical", "issue": "alg:none - no signature"})
        if "exp" not in payload:
            issues.append({"severity": "high", "issue": "No expiration - token lives forever"})
        if "device_id" not in payload and "did" not in payload:
            issues.append({"severity": "medium", "issue": "No device binding in token"})
        if header.get("alg", "").startswith("HS"):
            issues.append({"severity": "info", "issue": "Symmetric HMAC - test weak secrets"})
        for i in issues:
            self.findings.append({"severity": i["severity"], "type": "Token Analysis", "detail": i["issue"]})
        return {"header": header, "payload": payload, "issues": issues}

    def test_token_reuse_after_logout(self, token, logout_path="/api/v1/logout"):
        """Test if token remains valid after logout."""
        headers = {"Authorization": f"Bearer {token}"}
        self._req("POST", logout_path, headers=headers)
        resp = self._req("GET", "/api/v1/me", headers=headers)
        if resp and resp.status_code == 200:
            self.findings.append({"severity": "high", "type": "Token Reuse After Logout",
                                  "detail": "Token still valid after logout call"})
            return {"reusable": True}
        return {"reusable": False}

    def test_rate_limiting(self, login_path="/api/v1/login", attempts=20):
        """Test brute-force protection on login endpoint."""
        blocked = False
        for i in range(attempts):
            resp = self._req("POST", login_path, json={"username": "test", "password": f"wrong{i}"})
            if resp and resp.status_code == 429:
                blocked = True
                break
        if not blocked:
            self.findings.append({"severity": "high", "type": "No Rate Limiting",
                                  "detail": f"Login accepted {attempts} attempts without blocking"})
        return {"rate_limited": blocked, "attempts": attempts}

    def test_idor(self, token, resource_path="/api/v1/users/{id}", own_id="1", other_id="2"):
        """Test for IDOR by accessing another user's resource."""
        headers = {"Authorization": f"Bearer {token}"}
        own = self._req("GET", resource_path.format(id=own_id), headers=headers)
        other = self._req("GET", resource_path.format(id=other_id), headers=headers)
        if own and other and other.status_code == 200:
            self.findings.append({"severity": "critical", "type": "IDOR",
                                  "detail": f"User {own_id} can access user {other_id} data"})
            return {"vulnerable": True}
        return {"vulnerable": False}

    def brute_force_jwt_secret(self, token):
        """Test for weak HMAC signing secrets."""
        header, _ = self.decode_jwt(token)
        if not header or header.get("alg") not in ("HS256", "HS384", "HS512"):
            return None
        parts = token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        alg_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        h = alg_map[header["alg"]]
        for secret in WEAK_SECRETS:
            expected = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), signing_input, h).digest()
            ).decode().rstrip("=")
            if expected == parts[2]:
                self.findings.append({"severity": "critical", "type": "Weak JWT Secret",
                                      "detail": f"Secret cracked: '{secret}'"})
                return secret
        return None

    def generate_report(self, token=None):
        endpoints = self.discover_auth_endpoints()
        no_auth = self.test_no_auth_access()
        token_analysis = self.analyze_token(token) if token else None
        secret = self.brute_force_jwt_secret(token) if token else None

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "target": self.base_url,
            "auth_endpoints": endpoints,
            "unauthenticated_access": no_auth,
            "token_analysis": token_analysis,
            "weak_secret": secret,
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        out = self.output_dir / "mobile_api_auth_report.json"
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
    agent = MobileAPIAuthAgent(url)
    agent.generate_report(token)


if __name__ == "__main__":
    main()
