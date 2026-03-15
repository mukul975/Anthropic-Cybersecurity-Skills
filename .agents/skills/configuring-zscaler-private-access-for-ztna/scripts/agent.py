#!/usr/bin/env python3
"""Zscaler Private Access (ZPA) ZTNA audit agent using ZPA API."""

import json
import sys
import argparse
from datetime import datetime

try:
    import requests
except ImportError:
    print("Install: pip install requests")
    sys.exit(1)


class ZPAClient:
    """Zscaler Private Access API client."""

    def __init__(self, client_id, client_secret, customer_id):
        self.base_url = "https://config.private.zscaler.com"
        self.customer_id = customer_id
        self.token = self._authenticate(client_id, client_secret)

    def _authenticate(self, client_id, client_secret):
        resp = requests.post(f"{self.base_url}/signin", json={
            "client_id": client_id, "client_secret": client_secret,
        })
        resp.raise_for_status()
        return resp.json()["token"]

    def _get(self, endpoint):
        resp = requests.get(f"{self.base_url}/mgmtconfig/v1/admin/customers/{self.customer_id}/{endpoint}",
                            headers={"Authorization": f"Bearer {self.token}"})
        resp.raise_for_status()
        return resp.json()

    def list_app_segments(self):
        return self._get("application")

    def list_server_groups(self):
        return self._get("serverGroup")

    def list_app_connectors(self):
        return self._get("connector")

    def list_access_policies(self):
        return self._get("policySet/rules")

    def list_segment_groups(self):
        return self._get("segmentGroup")


def audit_zpa_config(client):
    """Audit ZPA configuration for security posture."""
    findings = []
    apps = client.list_app_segments()
    for app in apps.get("list", []):
        if not app.get("enabled"):
            findings.append({
                "type": "disabled_app_segment",
                "name": app.get("name", ""),
                "severity": "LOW",
            })
        if app.get("bypassType") == "ALWAYS":
            findings.append({
                "type": "bypass_enabled",
                "name": app.get("name", ""),
                "severity": "HIGH",
                "recommendation": "Remove bypass to enforce ZPA inspection",
            })
    connectors = client.list_app_connectors()
    for conn in connectors.get("list", []):
        if conn.get("runtimeStatus") != "running":
            findings.append({
                "type": "connector_down",
                "name": conn.get("name", ""),
                "status": conn.get("runtimeStatus", ""),
                "severity": "CRITICAL",
            })
    return findings


def run_audit(client_id, client_secret, customer_id):
    """Execute ZPA ZTNA audit."""
    client = ZPAClient(client_id, client_secret, customer_id)
    print(f"\n{'='*60}")
    print(f"  ZSCALER PRIVATE ACCESS ZTNA AUDIT")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    apps = client.list_app_segments()
    app_list = apps.get("list", [])
    print(f"--- APPLICATION SEGMENTS ({len(app_list)}) ---")
    for a in app_list[:10]:
        print(f"  {a.get('name', '')}: enabled={a.get('enabled', '')} bypass={a.get('bypassType', '')}")

    connectors = client.list_app_connectors()
    conn_list = connectors.get("list", [])
    print(f"\n--- APP CONNECTORS ({len(conn_list)}) ---")
    for c in conn_list[:10]:
        print(f"  {c.get('name', '')}: {c.get('runtimeStatus', '')}")

    findings = audit_zpa_config(client)
    print(f"\n--- AUDIT FINDINGS ({len(findings)}) ---")
    for f in findings:
        print(f"  [{f['severity']}] {f['type']}: {f.get('name', '')}")

    return {"apps": len(app_list), "connectors": len(conn_list), "findings": findings}


def main():
    parser = argparse.ArgumentParser(description="ZPA ZTNA Audit Agent")
    parser.add_argument("--client-id", required=True, help="ZPA API client ID")
    parser.add_argument("--client-secret", required=True, help="ZPA API client secret")
    parser.add_argument("--customer-id", required=True, help="ZPA customer ID")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args.client_id, args.client_secret, args.customer_id)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
