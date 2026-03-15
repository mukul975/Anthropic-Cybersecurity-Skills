#!/usr/bin/env python3
"""OAuth 2.0 authorization flow security audit agent."""

import json
import sys
import argparse
import urllib.parse
from datetime import datetime

try:
    import requests
except ImportError:
    print("Install: pip install requests")
    sys.exit(1)


def discover_oauth_endpoints(issuer_url):
    """Discover OAuth 2.0 / OIDC endpoints from well-known configuration."""
    discovery_url = f"{issuer_url.rstrip('/')}/.well-known/openid-configuration"
    try:
        resp = requests.get(discovery_url, timeout=10)
        resp.raise_for_status()
        config = resp.json()
        return {
            "issuer": config.get("issuer", ""),
            "authorization_endpoint": config.get("authorization_endpoint", ""),
            "token_endpoint": config.get("token_endpoint", ""),
            "userinfo_endpoint": config.get("userinfo_endpoint", ""),
            "jwks_uri": config.get("jwks_uri", ""),
            "supported_grant_types": config.get("grant_types_supported", []),
            "supported_scopes": config.get("scopes_supported", []),
            "supported_response_types": config.get("response_types_supported", []),
            "token_endpoint_auth_methods": config.get("token_endpoint_auth_methods_supported", []),
        }
    except Exception as e:
        return {"error": str(e)}


def audit_oauth_security(config):
    """Audit OAuth configuration for security issues."""
    findings = []
    if "implicit" in config.get("supported_grant_types", []):
        findings.append({
            "issue": "Implicit grant type supported",
            "severity": "HIGH",
            "recommendation": "Disable implicit flow; use authorization code + PKCE",
        })
    if "password" in config.get("supported_grant_types", []):
        findings.append({
            "issue": "Resource owner password grant supported",
            "severity": "MEDIUM",
            "recommendation": "Disable ROPC grant; use authorization code flow",
        })
    auth_methods = config.get("token_endpoint_auth_methods", [])
    if "none" in auth_methods:
        findings.append({
            "issue": "Token endpoint allows unauthenticated clients",
            "severity": "MEDIUM",
            "recommendation": "Require client_secret_basic or private_key_jwt",
        })
    if "code" in config.get("supported_response_types", []):
        if "code id_token" not in config.get("supported_response_types", []):
            findings.append({
                "issue": "Authorization code flow available",
                "severity": "INFO",
                "note": "Ensure PKCE is enforced for public clients",
            })
    return findings


def test_token_endpoint(token_url, client_id, client_secret, grant_type="client_credentials"):
    """Test token endpoint with client credentials."""
    try:
        resp = requests.post(token_url, data={
            "grant_type": grant_type,
            "client_id": client_id,
            "client_secret": client_secret,
        }, timeout=10)
        if resp.status_code == 200:
            token_data = resp.json()
            return {
                "status": "success",
                "token_type": token_data.get("token_type", ""),
                "expires_in": token_data.get("expires_in", 0),
                "scope": token_data.get("scope", ""),
            }
        return {"status": "failed", "code": resp.status_code, "body": resp.text[:200]}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def run_audit(issuer_url, client_id=None, client_secret=None):
    """Execute OAuth 2.0 security audit."""
    print(f"\n{'='*60}")
    print(f"  OAUTH 2.0 AUTHORIZATION FLOW AUDIT")
    print(f"  Issuer: {issuer_url}")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    config = discover_oauth_endpoints(issuer_url)
    if "error" in config:
        print(f"  Error: {config['error']}")
        return config

    print(f"--- DISCOVERED ENDPOINTS ---")
    print(f"  Authorization: {config.get('authorization_endpoint', 'N/A')}")
    print(f"  Token: {config.get('token_endpoint', 'N/A')}")
    print(f"  JWKS: {config.get('jwks_uri', 'N/A')}")
    print(f"  Grant types: {config.get('supported_grant_types', [])}")

    findings = audit_oauth_security(config)
    print(f"\n--- SECURITY FINDINGS ({len(findings)}) ---")
    for f in findings:
        print(f"  [{f['severity']}] {f['issue']}")

    token_test = {}
    if client_id and client_secret and config.get("token_endpoint"):
        token_test = test_token_endpoint(config["token_endpoint"], client_id, client_secret)
        print(f"\n--- TOKEN ENDPOINT TEST ---")
        print(f"  Status: {token_test.get('status', 'N/A')}")

    return {"config": config, "findings": findings, "token_test": token_test}


def main():
    parser = argparse.ArgumentParser(description="OAuth 2.0 Audit Agent")
    parser.add_argument("--issuer", required=True, help="OAuth issuer URL")
    parser.add_argument("--client-id", help="Client ID for token test")
    parser.add_argument("--client-secret", help="Client secret for token test")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args.issuer, args.client_id, args.client_secret)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
