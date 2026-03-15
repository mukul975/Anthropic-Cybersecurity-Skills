#!/usr/bin/env python3
# For authorized testing in lab/CTF environments only
"""OAuth 2.0 misconfiguration detection agent for testing redirect URI, state, and PKCE."""

import argparse
import json
import logging
import sys
import urllib.parse
from typing import List

try:
    import requests
except ImportError:
    sys.exit("requests is required: pip install requests")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def discover_oidc_config(base_url: str) -> dict:
    """Discover OpenID Connect / OAuth configuration endpoints."""
    endpoints = [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ]
    for ep in endpoints:
        try:
            resp = requests.get(f"{base_url}{ep}", timeout=10, verify=False)
            if resp.status_code == 200:
                config = resp.json()
                logger.info("OIDC config found at %s%s", base_url, ep)
                return config
        except (requests.RequestException, ValueError):
            continue
    logger.warning("No OIDC configuration endpoint found")
    return {}


def test_redirect_uri_bypasses(auth_endpoint: str, client_id: str,
                                 legitimate_uri: str) -> List[dict]:
    """Test redirect_uri validation with common bypass techniques."""
    parsed = urllib.parse.urlparse(legitimate_uri)
    domain = parsed.netloc

    bypass_uris = [
        "https://evil.com",
        f"https://{domain}.evil.com/callback",
        f"https://{domain}@evil.com/callback",
        f"https://evil.com/.{domain}",
        f"https://{domain}/callback/../../../evil.com",
        f"https://{domain}/callback?next=https://evil.com",
        f"https://{domain.upper()}/callback",
        f"http://{domain}/callback",
        f"https://{domain}/CALLBACK",
        f"https://{domain}/callback%0d%0aLocation:https://evil.com",
    ]

    results = []
    for uri in bypass_uris:
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": uri,
            "scope": "openid",
            "state": "test123",
        }
        try:
            resp = requests.get(auth_endpoint, params=params, timeout=10,
                                allow_redirects=False, verify=False)
            accepted = resp.status_code in (302, 301, 200)
            location = resp.headers.get("Location", "")
            results.append({
                "redirect_uri": uri,
                "status_code": resp.status_code,
                "accepted": accepted,
                "redirected_to": location[:120] if location else "",
            })
            if accepted:
                logger.warning("Redirect URI bypass accepted: %s", uri)
        except requests.RequestException as exc:
            results.append({"redirect_uri": uri, "error": str(exc)})

    return results


def test_state_parameter(auth_endpoint: str, client_id: str,
                          redirect_uri: str) -> dict:
    """Test if the state parameter is required and validated."""
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid",
    }
    resp = requests.get(auth_endpoint, params=params, timeout=10,
                        allow_redirects=False, verify=False)
    no_state_accepted = resp.status_code in (302, 301, 200)

    params["state"] = "aaaa"
    resp2 = requests.get(auth_endpoint, params=params, timeout=10,
                         allow_redirects=False, verify=False)

    return {
        "state_required": not no_state_accepted,
        "no_state_status": resp.status_code,
        "predictable_state_status": resp2.status_code,
        "csrf_risk": no_state_accepted,
    }


def test_pkce_requirement(auth_endpoint: str, client_id: str,
                           redirect_uri: str) -> dict:
    """Test if PKCE (code_challenge) is required."""
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid",
        "state": "pkce_test",
    }
    resp_no_pkce = requests.get(auth_endpoint, params=params, timeout=10,
                                 allow_redirects=False, verify=False)

    import hashlib, base64, os
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    params["code_challenge"] = challenge
    params["code_challenge_method"] = "S256"
    resp_with_pkce = requests.get(auth_endpoint, params=params, timeout=10,
                                   allow_redirects=False, verify=False)

    return {
        "pkce_required": resp_no_pkce.status_code >= 400,
        "without_pkce_status": resp_no_pkce.status_code,
        "with_pkce_status": resp_with_pkce.status_code,
        "risk": "HIGH" if resp_no_pkce.status_code < 400 else "LOW",
    }


def test_code_reuse(token_endpoint: str, auth_code: str, client_id: str,
                     client_secret: str, redirect_uri: str) -> dict:
    """Test if authorization codes can be reused."""
    data = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    resp1 = requests.post(token_endpoint, data=data, timeout=10, verify=False)
    resp2 = requests.post(token_endpoint, data=data, timeout=10, verify=False)

    return {
        "first_exchange_status": resp1.status_code,
        "second_exchange_status": resp2.status_code,
        "code_reusable": resp2.status_code == 200,
        "risk": "MEDIUM" if resp2.status_code == 200 else "LOW",
    }


def test_scope_escalation(auth_endpoint: str, client_id: str,
                           redirect_uri: str) -> dict:
    """Test if additional scopes beyond authorization can be requested."""
    elevated_scopes = "openid profile email admin write delete"
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": elevated_scopes,
        "state": "scope_test",
    }
    resp = requests.get(auth_endpoint, params=params, timeout=10,
                        allow_redirects=False, verify=False)
    return {
        "requested_scopes": elevated_scopes,
        "status_code": resp.status_code,
        "accepted": resp.status_code in (302, 301, 200),
    }


def run_assessment(config: dict, client_id: str, redirect_uri: str) -> dict:
    """Run the full OAuth security assessment."""
    auth_ep = config.get("authorization_endpoint", "")
    findings = []

    redirect_tests = test_redirect_uri_bypasses(auth_ep, client_id, redirect_uri) if auth_ep else []
    bypasses = [t for t in redirect_tests if t.get("accepted")]
    if bypasses:
        findings.append(f"HIGH: {len(bypasses)} redirect_uri bypass(es) accepted")

    state_test = test_state_parameter(auth_ep, client_id, redirect_uri) if auth_ep else {}
    if state_test.get("csrf_risk"):
        findings.append("MEDIUM: State parameter not required (CSRF risk)")

    pkce_test = test_pkce_requirement(auth_ep, client_id, redirect_uri) if auth_ep else {}
    if not pkce_test.get("pkce_required", True):
        findings.append("HIGH: PKCE not required")

    scope_test = test_scope_escalation(auth_ep, client_id, redirect_uri) if auth_ep else {}

    return {
        "oidc_config": config,
        "redirect_uri_tests": redirect_tests,
        "state_parameter": state_test,
        "pkce": pkce_test,
        "scope_escalation": scope_test,
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(description="OAuth Misconfiguration Assessment Agent")
    parser.add_argument("--url", required=True, help="OAuth provider base URL")
    parser.add_argument("--client-id", required=True, help="OAuth client ID")
    parser.add_argument("--redirect-uri", required=True, help="Legitimate redirect URI")
    parser.add_argument("--output", default="oauth_report.json")
    args = parser.parse_args()

    config = discover_oidc_config(args.url)
    report = run_assessment(config, args.client_id, args.redirect_uri)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
