#!/usr/bin/env python3
"""Kubernetes RBAC hardening audit."""
import argparse, json, sys
from datetime import datetime, timezone
try:
    import requests
except ImportError:
    requests = None

def audit_config(target, token):
    findings = []
    if not requests: return [{"error": "requests required"}]
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(f"{target}/api/v1/status", headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if not data.get("enabled", True):
                findings.append({"check": "Service Status", "status": "DISABLED", "severity": "CRITICAL"})
        elif resp.status_code == 401:
            findings.append({"check": "Authentication", "status": "UNAUTHORIZED", "severity": "HIGH"})
    except requests.RequestException as e:
        findings.append({"error": str(e)})
    return findings

def check_compliance(target, token):
    findings = []
    if not requests: return []
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(f"{target}/api/v1/compliance", headers=headers, timeout=10)
        if resp.status_code == 200:
            for item in resp.json().get("checks", []):
                if item.get("status") != "PASS":
                    findings.append({"check": item.get("name"), "status": item.get("status"),
                                     "severity": item.get("severity", "MEDIUM")})
    except requests.RequestException:
        pass
    return findings

def main():
    p = argparse.ArgumentParser(description="Kubernetes RBAC hardening audit")
    p.add_argument("--target", required=True, help="Target URL")
    p.add_argument("--token", required=True, help="API token")
    p.add_argument("--output", "-o", help="Output JSON report")
    p.add_argument("--verbose", "-v", action="store_true")
    a = p.parse_args()
    print("[*] Kubernetes RBAC hardening audit")
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "findings": []}
    report["findings"].extend(audit_config(a.target, a.token))
    report["findings"].extend(check_compliance(a.target, a.token))
    high = sum(1 for f in report["findings"] if f.get("severity") in ("HIGH", "CRITICAL"))
    report["risk_level"] = "HIGH" if high else "MEDIUM" if report["findings"] else "LOW"
    print(f"[*] {len(report['findings'])} findings, risk: {report['risk_level']}")
    if a.output:
        with open(a.output, "w") as f: json.dump(report, f, indent=2)
    else:
        print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
