#!/usr/bin/env python3
"""Duo MFA configuration and audit agent using Duo Admin API."""

import json
import sys
import argparse
import hmac
import hashlib
import time
import email.utils
import urllib.parse
from datetime import datetime

try:
    import requests
except ImportError:
    print("Install: pip install requests")
    sys.exit(1)


class DuoAdminClient:
    """Duo Admin API client for MFA management."""

    def __init__(self, ikey, skey, host):
        self.ikey = ikey
        self.skey = skey
        self.host = host

    def _sign(self, method, path, params):
        now = email.utils.formatdate()
        canon = [now, method.upper(), self.host.lower(), path]
        body = urllib.parse.urlencode(sorted(params.items()))
        canon.append(body)
        canon_str = "\n".join(canon)
        sig = hmac.new(self.skey.encode(), canon_str.encode(), hashlib.sha1).hexdigest()
        auth = f"{self.ikey}:{sig}"
        import base64
        return {"Date": now, "Authorization": f"Basic {base64.b64encode(auth.encode()).decode()}"}

    def _get(self, endpoint, params=None):
        params = params or {}
        headers = self._sign("GET", endpoint, params)
        resp = requests.get(f"https://{self.host}{endpoint}",
                            headers=headers, params=params)
        resp.raise_for_status()
        return resp.json()

    def list_users(self):
        return self._get("/admin/v1/users")

    def get_user(self, user_id):
        return self._get(f"/admin/v1/users/{user_id}")

    def list_auth_logs(self, mintime=None):
        params = {}
        if mintime:
            params["mintime"] = str(int(mintime))
        return self._get("/admin/v2/logs/authentication", params)

    def get_info_summary(self):
        return self._get("/admin/v1/info/summary")


def audit_mfa_coverage(users_data):
    """Audit MFA enrollment coverage."""
    users = users_data.get("response", [])
    total = len(users)
    enrolled = sum(1 for u in users if u.get("status") == "active" and u.get("phones"))
    bypass = sum(1 for u in users if u.get("status") == "bypass")
    disabled = sum(1 for u in users if u.get("status") == "disabled")
    no_device = [u["username"] for u in users if not u.get("phones") and u.get("status") == "active"]
    return {
        "total_users": total,
        "enrolled": enrolled,
        "bypass_mode": bypass,
        "disabled": disabled,
        "no_device": no_device[:20],
        "enrollment_rate": round(enrolled / max(total, 1) * 100, 1),
        "findings": [
            {"severity": "HIGH", "issue": f"{bypass} users in bypass mode"} if bypass else None,
            {"severity": "MEDIUM", "issue": f"{len(no_device)} users without MFA device"} if no_device else None,
        ],
    }


def analyze_auth_logs(logs_data):
    """Analyze authentication logs for anomalies."""
    logs = logs_data.get("response", {}).get("authlogs", [])
    denied = [l for l in logs if l.get("result") == "denied"]
    fraud = [l for l in logs if l.get("result") == "fraud"]
    return {
        "total_authentications": len(logs),
        "denied": len(denied),
        "fraud_reported": len(fraud),
        "top_denied_users": list(set(l.get("user", {}).get("name", "") for l in denied[:10])),
    }


def run_audit(ikey, skey, host):
    """Execute Duo MFA audit."""
    client = DuoAdminClient(ikey, skey, host)
    print(f"\n{'='*60}")
    print(f"  DUO MFA CONFIGURATION AUDIT")
    print(f"  Host: {host}")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    summary = client.get_info_summary()
    info = summary.get("response", {})
    print(f"--- ACCOUNT SUMMARY ---")
    print(f"  Users: {info.get('user_count', 0)}")
    print(f"  Integrations: {info.get('integration_count', 0)}")

    users = client.list_users()
    coverage = audit_mfa_coverage(users)
    print(f"\n--- MFA COVERAGE ---")
    print(f"  Enrollment rate: {coverage['enrollment_rate']}%")
    print(f"  Bypass mode: {coverage['bypass_mode']}")
    print(f"  No device: {len(coverage['no_device'])}")

    return {"summary": info, "coverage": coverage}


def main():
    parser = argparse.ArgumentParser(description="Duo MFA Audit Agent")
    parser.add_argument("--ikey", required=True, help="Duo integration key")
    parser.add_argument("--skey", required=True, help="Duo secret key")
    parser.add_argument("--host", required=True, help="Duo API hostname")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args.ikey, args.skey, args.host)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
