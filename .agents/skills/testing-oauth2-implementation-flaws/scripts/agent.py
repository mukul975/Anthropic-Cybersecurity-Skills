#!/usr/bin/env python3
"""Agent for testing OAuth 2.0 implementation flaws.

Tests OAuth authorization code flow, redirect URI validation,
state/PKCE enforcement, token leakage, scope escalation, and
OIDC ID token validation weaknesses.
"""

import json
import sys
import re
import secrets
import hashlib
import base64
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode

try:
    import requests
except ImportError:
    requests = None


class OAuth2TestAgent:
    """Tests OAuth 2.0 / OIDC implementations for security flaws."""

    def __init__(self, auth_url, token_url, client_id, redirect_uri,
                 output_dir="./oauth2_test"):
        self.auth_url = auth_url
        self.token_url = token_url
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    def _get(self, url, **kwargs):
        if not requests:
            return None
        kwargs.setdefault("timeout", 10)
        kwargs.setdefault("allow_redirects", False)
        try:
            return requests.get(url, **kwargs)
        except requests.RequestException:
            return None

    def _post(self, url, **kwargs):
        if not requests:
            return None
        kwargs.setdefault("timeout", 10)
        try:
            return requests.post(url, **kwargs)
        except requests.RequestException:
            return None

    def test_redirect_uri_validation(self):
        """Test redirect_uri for open redirect and bypass techniques."""
        bypasses = [
            self.redirect_uri + ".evil.com",
            self.redirect_uri + "@evil.com",
            self.redirect_uri + "/../evil.com",
            "https://evil.com",
            self.redirect_uri.replace("https://", "http://"),
            self.redirect_uri + "%23@evil.com",
            self.redirect_uri + "?next=https://evil.com",
        ]
        results = []
        for uri in bypasses:
            params = {
                "response_type": "code", "client_id": self.client_id,
                "redirect_uri": uri, "scope": "openid",
                "state": secrets.token_urlsafe(16),
            }
            resp = self._get(f"{self.auth_url}?{urlencode(params)}")
            if resp and resp.status_code in (301, 302, 303, 307):
                location = resp.headers.get("Location", "")
                if "code=" in location or uri in location:
                    results.append({"redirect_uri": uri, "accepted": True, "location": location[:200]})
                    self.findings.append({"severity": "critical", "type": "Redirect URI Bypass",
                                          "detail": f"Server accepted redirect_uri: {uri}"})
        return results

    def test_state_parameter(self):
        """Test if state parameter is enforced (CSRF protection)."""
        params = {
            "response_type": "code", "client_id": self.client_id,
            "redirect_uri": self.redirect_uri, "scope": "openid",
        }
        resp = self._get(f"{self.auth_url}?{urlencode(params)}")
        if resp and resp.status_code in (301, 302, 303, 307):
            location = resp.headers.get("Location", "")
            if "state=" not in location:
                self.findings.append({"severity": "high", "type": "Missing State Parameter",
                                      "detail": "OAuth flow proceeds without state (CSRF risk)"})
                return {"state_enforced": False}
        return {"state_enforced": True}

    def test_pkce_enforcement(self):
        """Test if PKCE is required for public clients."""
        params = {
            "response_type": "code", "client_id": self.client_id,
            "redirect_uri": self.redirect_uri, "scope": "openid",
            "state": secrets.token_urlsafe(16),
        }
        resp = self._get(f"{self.auth_url}?{urlencode(params)}")
        if resp and resp.status_code in (301, 302, 303, 307):
            self.findings.append({"severity": "high", "type": "PKCE Not Required",
                                  "detail": "Authorization proceeds without code_challenge"})
            return {"pkce_required": False}
        return {"pkce_required": True}

    def test_scope_escalation(self, extra_scopes=None):
        """Test requesting more scopes than authorized."""
        scopes = extra_scopes or ["admin", "write", "delete", "users:admin", "openid profile email"]
        results = []
        for scope in scopes:
            params = {
                "response_type": "code", "client_id": self.client_id,
                "redirect_uri": self.redirect_uri, "scope": scope,
                "state": secrets.token_urlsafe(16),
            }
            resp = self._get(f"{self.auth_url}?{urlencode(params)}")
            if resp and resp.status_code in (301, 302, 303, 307):
                results.append({"scope": scope, "accepted": True})
                self.findings.append({"severity": "high", "type": "Scope Escalation",
                                      "detail": f"Server granted scope: {scope}"})
        return results

    def test_code_reuse(self, auth_code):
        """Test if authorization code can be reused multiple times."""
        data = {
            "grant_type": "authorization_code", "code": auth_code,
            "client_id": self.client_id, "redirect_uri": self.redirect_uri,
        }
        resp1 = self._post(self.token_url, data=data)
        resp2 = self._post(self.token_url, data=data)
        if resp2 and resp2.status_code == 200:
            self.findings.append({"severity": "high", "type": "Code Reuse",
                                  "detail": "Authorization code accepted multiple times"})
            return {"reusable": True}
        return {"reusable": False}

    def test_token_in_url(self):
        """Test if implicit flow returns tokens in URL fragment."""
        params = {
            "response_type": "token", "client_id": self.client_id,
            "redirect_uri": self.redirect_uri, "scope": "openid",
            "state": secrets.token_urlsafe(16),
        }
        resp = self._get(f"{self.auth_url}?{urlencode(params)}")
        if resp and resp.status_code in (301, 302, 303, 307):
            location = resp.headers.get("Location", "")
            if "access_token=" in location:
                self.findings.append({"severity": "medium", "type": "Implicit Flow Token Exposure",
                                      "detail": "Access token returned in URL fragment"})
                return {"token_in_url": True}
        return {"token_in_url": False}

    def generate_report(self, auth_code=None):
        redirect_results = self.test_redirect_uri_validation()
        state = self.test_state_parameter()
        pkce = self.test_pkce_enforcement()
        scope = self.test_scope_escalation()
        token_url = self.test_token_in_url()
        code_reuse = self.test_code_reuse(auth_code) if auth_code else None

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "auth_url": self.auth_url,
            "redirect_uri_bypasses": redirect_results,
            "state_parameter": state,
            "pkce_enforcement": pkce,
            "scope_escalation": scope,
            "implicit_flow": token_url,
            "code_reuse": code_reuse,
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        out = self.output_dir / "oauth2_test_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 5:
        print("Usage: agent.py <auth_url> <token_url> <client_id> <redirect_uri> [--code <auth_code>]")
        sys.exit(1)
    auth_url, token_url, client_id, redirect_uri = sys.argv[1:5]
    code = None
    if "--code" in sys.argv:
        code = sys.argv[sys.argv.index("--code") + 1]
    agent = OAuth2TestAgent(auth_url, token_url, client_id, redirect_uri)
    agent.generate_report(code)


if __name__ == "__main__":
    main()
