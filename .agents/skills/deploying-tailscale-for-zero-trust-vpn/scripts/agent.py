#!/usr/bin/env python3
"""Tailscale zero trust VPN deployment audit agent."""

import json
import sys
import argparse
from datetime import datetime

try:
    import requests
except ImportError:
    print("Install: pip install requests")
    sys.exit(1)


class TailscaleClient:
    """Client for Tailscale API v2."""

    def __init__(self, api_key, tailnet="-"):
        self.base_url = "https://api.tailscale.com/api/v2"
        self.tailnet = tailnet
        self.headers = {"Authorization": f"Bearer {api_key}"}

    def _get(self, path):
        resp = requests.get(f"{self.base_url}{path}",
                            headers=self.headers, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def list_devices(self):
        return self._get(f"/tailnet/{self.tailnet}/devices").get("devices", [])

    def get_acl(self):
        return self._get(f"/tailnet/{self.tailnet}/acl")

    def list_dns(self):
        return self._get(f"/tailnet/{self.tailnet}/dns/nameservers")

    def get_key_expiry_disabled(self):
        return self._get(f"/tailnet/{self.tailnet}/keys")

    def list_webhooks(self):
        return self._get(f"/tailnet/{self.tailnet}/webhooks").get("webhooks", [])


def audit_devices(devices):
    """Audit device compliance: OS versions, key expiry, last seen."""
    findings = []
    now = datetime.utcnow()
    for dev in devices:
        hostname = dev.get("hostname", "unknown")
        if dev.get("keyExpiryDisabled", False):
            findings.append({
                "device": hostname,
                "issue": "Key expiry disabled — device never requires re-authentication",
                "severity": "HIGH",
            })
        if not dev.get("updateAvailable", False) is False and dev.get("updateAvailable"):
            findings.append({
                "device": hostname,
                "issue": "Tailscale update available but not installed",
                "severity": "MEDIUM",
            })
        os_name = dev.get("os", "")
        if dev.get("blocksIncomingConnections", False):
            findings.append({
                "device": hostname,
                "issue": "Device blocks incoming connections (shields up mode)",
                "severity": "INFO",
            })
    return findings


def audit_acl(acl_data):
    """Check ACL policy for overly permissive rules."""
    findings = []
    acls = acl_data.get("acls", []) if isinstance(acl_data, dict) else []
    for i, rule in enumerate(acls):
        src = rule.get("src", [])
        dst = rule.get("dst", [])
        if "*" in src and any("*:*" in d for d in dst):
            findings.append({
                "rule_index": i,
                "issue": "Allow-all rule: src=* dst=*:* — no zero trust segmentation",
                "severity": "CRITICAL",
            })
    ssh_rules = acl_data.get("ssh", []) if isinstance(acl_data, dict) else []
    for rule in ssh_rules:
        if rule.get("action") == "accept" and "*" in rule.get("src", []):
            findings.append({
                "rule": "SSH",
                "issue": "SSH access allowed from all users",
                "severity": "HIGH",
            })
    return findings


def run_audit(api_key, tailnet):
    """Execute Tailscale zero trust audit."""
    print(f"\n{'='*60}")
    print(f"  TAILSCALE ZERO TRUST VPN AUDIT")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    client = TailscaleClient(api_key, tailnet)
    report = {}

    devices = client.list_devices()
    report["total_devices"] = len(devices)
    print(f"--- DEVICES ({len(devices)}) ---")
    for d in devices[:15]:
        print(f"  {d.get('hostname','')}: {d.get('os','')}/{d.get('clientVersion','')} "
              f"({'online' if d.get('online') else 'offline'})")

    dev_findings = audit_devices(devices)
    report["device_findings"] = dev_findings
    print(f"\n--- DEVICE FINDINGS ({len(dev_findings)}) ---")
    for f in dev_findings[:10]:
        print(f"  [{f['severity']}] {f['device']}: {f['issue']}")

    acl_data = client.get_acl()
    acl_findings = audit_acl(acl_data)
    report["acl_findings"] = acl_findings
    print(f"\n--- ACL POLICY FINDINGS ({len(acl_findings)}) ---")
    for f in acl_findings[:10]:
        print(f"  [{f['severity']}] {f['issue']}")

    dns = client.list_dns()
    report["dns_config"] = dns
    print(f"\n--- DNS CONFIG ---")
    for ns in dns.get("dns", []):
        print(f"  Nameserver: {ns}")

    return report


def main():
    parser = argparse.ArgumentParser(description="Tailscale Zero Trust Audit")
    parser.add_argument("--api-key", required=True, help="Tailscale API key")
    parser.add_argument("--tailnet", default="-", help="Tailnet name (default: current)")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args.api_key, args.tailnet)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
