#!/usr/bin/env python3
"""Palo Alto Prisma Access zero trust deployment audit agent."""

import json
import sys
import argparse
from datetime import datetime

try:
    import requests
except ImportError:
    print("Install: pip install requests")
    sys.exit(1)


class PrismaAccessClient:
    """Client for Prisma Access Cloud Management API."""

    def __init__(self, tsg_id, client_id, client_secret):
        self.base_url = "https://api.sase.paloaltonetworks.com"
        self.tsg_id = tsg_id
        self.token = self._authenticate(client_id, client_secret)

    def _authenticate(self, client_id, client_secret):
        resp = requests.post(
            "https://auth.apps.paloaltonetworks.com/oauth2/access_token",
            data={
                "grant_type": "client_credentials",
                "scope": f"tsg_id:{self.tsg_id}",
            },
            auth=(client_id, client_secret),
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def _get(self, path, params=None):
        headers = {"Authorization": f"Bearer {self.token}"}
        resp = requests.get(f"{self.base_url}{path}", headers=headers,
                            params=params, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def list_remote_networks(self):
        return self._get("/sse/config/v1/remote-networks").get("data", [])

    def list_service_connections(self):
        return self._get("/sse/config/v1/service-connections").get("data", [])

    def list_ike_gateways(self):
        return self._get("/sse/config/v1/ike-gateways").get("data", [])

    def list_security_rules(self):
        return self._get("/sse/config/v1/security-rules").get("data", [])

    def list_hip_profiles(self):
        return self._get("/sse/config/v1/hip-profiles").get("data", [])

    def get_mobile_users_config(self):
        return self._get("/sse/config/v1/mobile-agent/global-settings").get("data", {})


def audit_security_rules(rules):
    """Check for overly permissive security rules."""
    findings = []
    for rule in rules:
        if rule.get("action") == "allow":
            src = rule.get("source", [])
            dst = rule.get("destination", [])
            if "any" in src and "any" in dst:
                findings.append({
                    "rule": rule.get("name", ""),
                    "issue": "Allow-any-to-any rule detected",
                    "severity": "HIGH",
                })
        if not rule.get("log_end", False):
            findings.append({
                "rule": rule.get("name", ""),
                "issue": "Logging not enabled on rule",
                "severity": "MEDIUM",
            })
    return findings


def run_audit(tsg_id, client_id, client_secret):
    """Execute Prisma Access zero trust audit."""
    print(f"\n{'='*60}")
    print(f"  PRISMA ACCESS ZERO TRUST AUDIT")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    client = PrismaAccessClient(tsg_id, client_id, client_secret)
    report = {}

    networks = client.list_remote_networks()
    report["remote_networks"] = len(networks)
    print(f"--- REMOTE NETWORKS ({len(networks)}) ---")
    for n in networks[:10]:
        print(f"  {n.get('name', '')}: region={n.get('region', '')}")

    connections = client.list_service_connections()
    report["service_connections"] = len(connections)
    print(f"\n--- SERVICE CONNECTIONS ({len(connections)}) ---")
    for c in connections[:10]:
        print(f"  {c.get('name', '')}: {c.get('ipsec_tunnel', '')}")

    rules = client.list_security_rules()
    findings = audit_security_rules(rules)
    report["security_rules"] = len(rules)
    report["findings"] = findings
    print(f"\n--- SECURITY RULES ({len(rules)}) ---")
    print(f"  Findings: {len(findings)}")
    for f in findings[:10]:
        print(f"  [{f['severity']}] {f['rule']}: {f['issue']}")

    hip = client.list_hip_profiles()
    report["hip_profiles"] = len(hip)
    print(f"\n--- HIP PROFILES ({len(hip)}) ---")
    for h in hip[:5]:
        print(f"  {h.get('name', '')}")

    return report


def main():
    parser = argparse.ArgumentParser(description="Prisma Access Zero Trust Audit")
    parser.add_argument("--tsg-id", required=True, help="Tenant Service Group ID")
    parser.add_argument("--client-id", required=True, help="OAuth client ID")
    parser.add_argument("--client-secret", required=True, help="OAuth client secret")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args.tsg_id, args.client_id, args.client_secret)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
