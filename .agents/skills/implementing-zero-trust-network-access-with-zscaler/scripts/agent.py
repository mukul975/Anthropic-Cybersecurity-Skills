#!/usr/bin/env python3
"""Agent for auditing Zscaler Private Access (ZPA) zero trust configuration via API."""

import requests
import json
import argparse
from datetime import datetime, timezone

ZPA_BASE = "https://config.private.zscaler.com"


def authenticate(client_id, client_secret, customer_id):
    """Authenticate to Zscaler ZPA API."""
    url = f"{ZPA_BASE}/signin"
    payload = {"client_id": client_id, "client_secret": client_secret}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    resp = requests.post(url, data=payload, headers=headers, timeout=30)
    resp.raise_for_status()
    token = resp.json()["access_token"]
    print("[*] Authenticated to ZPA API")
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def list_app_segments(headers, customer_id):
    """List ZPA application segments."""
    url = f"{ZPA_BASE}/mgmtconfig/v1/admin/customers/{customer_id}/application"
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    apps = resp.json().get("list", [])
    print(f"\n[*] Application Segments: {len(apps)}")
    findings = []
    for app in apps:
        bypass = app.get("bypassType", "NEVER")
        if bypass != "NEVER":
            findings.append({"name": app["name"], "bypass": bypass, "severity": "HIGH"})
        print(f"  {app['name']} - bypass={bypass}, enabled={app.get('enabled', False)}")
    return apps, findings


def list_server_groups(headers, customer_id):
    """List server groups and their connectors."""
    url = f"{ZPA_BASE}/mgmtconfig/v1/admin/customers/{customer_id}/serverGroup"
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    groups = resp.json().get("list", [])
    print(f"\n[*] Server Groups: {len(groups)}")
    for g in groups:
        connectors = g.get("connectors", [])
        print(f"  {g['name']} - {len(connectors)} connectors, enabled={g.get('enabled')}")
    return groups


def list_access_policies(headers, customer_id):
    """List ZPA access policies to verify least-privilege enforcement."""
    url = f"{ZPA_BASE}/mgmtconfig/v1/admin/customers/{customer_id}/policySet/rules"
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    rules = resp.json().get("list", [])
    findings = []
    print(f"\n[*] Access Policy Rules: {len(rules)}")
    for r in rules:
        action = r.get("action", "")
        conditions = r.get("conditions", [])
        if action == "ALLOW" and not conditions:
            findings.append({"rule": r.get("name"), "issue": "ALLOW with no conditions",
                             "severity": "CRITICAL"})
            print(f"  [!] {r.get('name')}: ALLOW without conditions")
        else:
            print(f"  {r.get('name')}: action={action}, conditions={len(conditions)}")
    return rules, findings


def check_connector_health(headers, customer_id):
    """Check connector enrollment and health status."""
    url = f"{ZPA_BASE}/mgmtconfig/v1/admin/customers/{customer_id}/connector"
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    connectors = resp.json().get("list", [])
    issues = []
    for c in connectors:
        status = c.get("currentVersion", "unknown")
        enabled = c.get("enabled", False)
        if not enabled:
            issues.append({"connector": c.get("name"), "issue": "disabled", "severity": "MEDIUM"})
        print(f"  {c.get('name')}: enabled={enabled}, version={status}")
    print(f"[*] Connectors: {len(connectors)} total, {len(issues)} disabled")
    return connectors, issues


def generate_report(apps, app_findings, policy_findings, connector_issues, output_path):
    """Generate ZPA audit report."""
    report = {
        "audit_date": datetime.now(timezone.utc).isoformat(),
        "summary": {"app_segments": len(apps), "bypass_findings": len(app_findings),
                     "policy_findings": len(policy_findings),
                     "connector_issues": len(connector_issues)},
        "bypass_findings": app_findings, "policy_findings": policy_findings,
        "connector_issues": connector_issues,
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[*] Report saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Zscaler ZPA Zero Trust Audit Agent")
    parser.add_argument("action", choices=["apps", "servers", "policies", "connectors", "full-audit"])
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--client-secret", required=True)
    parser.add_argument("--customer-id", required=True)
    parser.add_argument("-o", "--output", default="zpa_audit.json")
    args = parser.parse_args()

    headers = authenticate(args.client_id, args.client_secret, args.customer_id)
    if args.action == "apps":
        list_app_segments(headers, args.customer_id)
    elif args.action == "servers":
        list_server_groups(headers, args.customer_id)
    elif args.action == "policies":
        list_access_policies(headers, args.customer_id)
    elif args.action == "connectors":
        check_connector_health(headers, args.customer_id)
    elif args.action == "full-audit":
        apps, af = list_app_segments(headers, args.customer_id)
        list_server_groups(headers, args.customer_id)
        _, pf = list_access_policies(headers, args.customer_id)
        _, ci = check_connector_health(headers, args.customer_id)
        generate_report(apps, af, pf, ci, args.output)


if __name__ == "__main__":
    main()
