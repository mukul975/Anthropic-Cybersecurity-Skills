#!/usr/bin/env python3
"""Cloudflare Access zero trust audit agent using Cloudflare API."""

import json
import sys
import argparse
from datetime import datetime

try:
    import requests
except ImportError:
    print("Install: pip install requests")
    sys.exit(1)


class CloudflareAccessClient:
    """Cloudflare Access API client."""

    def __init__(self, api_token, account_id):
        self.base = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/access"
        self.headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}

    def _get(self, endpoint):
        resp = requests.get(f"{self.base}/{endpoint}", headers=self.headers)
        resp.raise_for_status()
        return resp.json()

    def list_applications(self):
        return self._get("apps")

    def list_policies(self, app_id):
        return self._get(f"apps/{app_id}/policies")

    def list_groups(self):
        return self._get("groups")

    def list_identity_providers(self):
        return self._get("identity_providers")

    def list_service_tokens(self):
        return self._get("service_tokens")


def audit_access_config(client):
    """Audit Cloudflare Access configuration."""
    findings = []
    apps = client.list_applications()
    for app in apps.get("result", []):
        if not app.get("session_duration"):
            findings.append({
                "type": "no_session_timeout",
                "app": app.get("name", ""),
                "severity": "MEDIUM",
            })
    tokens = client.list_service_tokens()
    for token in tokens.get("result", []):
        if token.get("expires_at"):
            expiry = datetime.fromisoformat(token["expires_at"].replace("Z", "+00:00"))
            if expiry.replace(tzinfo=None) < datetime.utcnow():
                findings.append({
                    "type": "expired_service_token",
                    "token_name": token.get("name", ""),
                    "severity": "HIGH",
                })
    return findings


def run_audit(api_token, account_id):
    """Execute Cloudflare Access audit."""
    client = CloudflareAccessClient(api_token, account_id)
    print(f"\n{'='*60}")
    print(f"  CLOUDFLARE ACCESS ZERO TRUST AUDIT")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    apps = client.list_applications()
    app_list = apps.get("result", [])
    print(f"--- APPLICATIONS ({len(app_list)}) ---")
    for a in app_list[:10]:
        print(f"  {a.get('name', '')}: domain={a.get('domain', '')} type={a.get('type', '')}")

    idps = client.list_identity_providers()
    idp_list = idps.get("result", [])
    print(f"\n--- IDENTITY PROVIDERS ({len(idp_list)}) ---")
    for idp in idp_list:
        print(f"  {idp.get('name', '')}: type={idp.get('type', '')}")

    findings = audit_access_config(client)
    print(f"\n--- FINDINGS ({len(findings)}) ---")
    for f in findings:
        print(f"  [{f['severity']}] {f['type']}: {f.get('app', f.get('token_name', ''))}")

    return {"apps": len(app_list), "idps": len(idp_list), "findings": findings}


def main():
    parser = argparse.ArgumentParser(description="Cloudflare Access Audit Agent")
    parser.add_argument("--api-token", required=True, help="Cloudflare API token")
    parser.add_argument("--account-id", required=True, help="Cloudflare account ID")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args.api_token, args.account_id)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
