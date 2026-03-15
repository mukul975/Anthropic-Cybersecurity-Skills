#!/usr/bin/env python3
"""Agent for managing Saviynt access recertification campaigns via REST API."""

import requests
import json
import argparse
from datetime import datetime, timezone
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def authenticate(base_url, username, password):
    """Authenticate to Saviynt EIC and get OAuth token."""
    url = f"{base_url}/ECM/api/login"
    payload = {"username": username, "password": password}
    resp = requests.post(url, json=payload, verify=False, timeout=30)
    resp.raise_for_status()
    token = resp.json().get("access_token")
    print(f"[*] Authenticated to Saviynt EIC")
    return {"Authorization": f"Bearer {token}"}


def list_campaigns(base_url, headers, status="active"):
    """List certification campaigns."""
    url = f"{base_url}/ECM/api/v5/listCertification"
    payload = {"certificationstatus": status, "max": 50, "offset": 0}
    resp = requests.post(url, headers=headers, json=payload, verify=False, timeout=30)
    resp.raise_for_status()
    campaigns = resp.json().get("certifications", [])
    print(f"\n[*] Campaigns ({status}): {len(campaigns)}")
    for c in campaigns:
        print(f"  {c.get('certificationname')} - certifier: {c.get('certifier', 'N/A')} "
              f"| due: {c.get('duedate', 'N/A')}")
    return campaigns


def get_campaign_details(base_url, headers, cert_key):
    """Get detailed campaign status including item counts."""
    url = f"{base_url}/ECM/api/v5/getCertificationDetails"
    payload = {"certkey": cert_key}
    resp = requests.post(url, headers=headers, json=payload, verify=False, timeout=30)
    resp.raise_for_status()
    details = resp.json()
    total = details.get("totalitems", 0)
    certified = details.get("certifieditems", 0)
    revoked = details.get("revokeditems", 0)
    pending = total - certified - revoked
    print(f"\n[*] Campaign {cert_key}: total={total}, certified={certified}, "
          f"revoked={revoked}, pending={pending}")
    return details


def get_pending_items(base_url, headers, cert_key, max_items=100):
    """Get items pending review in a certification campaign."""
    url = f"{base_url}/ECM/api/v5/getCertificationItems"
    payload = {"certkey": cert_key, "status": "pending", "max": max_items, "offset": 0}
    resp = requests.post(url, headers=headers, json=payload, verify=False, timeout=30)
    resp.raise_for_status()
    items = resp.json().get("certificationitems", [])
    print(f"\n[*] Pending items: {len(items)}")
    high_risk = [i for i in items if i.get("risk_score", 0) > 7]
    print(f"  High-risk items (score > 7): {len(high_risk)}")
    for i in high_risk[:10]:
        print(f"  [!] {i.get('username')} - {i.get('entitlement_value')} "
              f"(risk: {i.get('risk_score')})")
    return items


def certify_items(base_url, headers, cert_key, item_ids, action="certify"):
    """Certify or revoke items in a campaign."""
    url = f"{base_url}/ECM/api/v5/certifyItems"
    payload = {"certkey": cert_key, "itemids": item_ids, "action": action,
               "comments": f"Auto-{action} by recertification agent"}
    resp = requests.post(url, headers=headers, json=payload, verify=False, timeout=30)
    resp.raise_for_status()
    print(f"[*] {action.capitalize()}d {len(item_ids)} items in campaign {cert_key}")
    return resp.json()


def check_overdue_campaigns(base_url, headers):
    """Find campaigns past their due date."""
    url = f"{base_url}/ECM/api/v5/listCertification"
    payload = {"certificationstatus": "active", "max": 200, "offset": 0}
    resp = requests.post(url, headers=headers, json=payload, verify=False, timeout=30)
    resp.raise_for_status()
    campaigns = resp.json().get("certifications", [])
    now = datetime.now(timezone.utc)
    overdue = []
    for c in campaigns:
        due = c.get("duedate", "")
        if due:
            try:
                due_dt = datetime.fromisoformat(due.replace("Z", "+00:00"))
                if due_dt < now:
                    overdue.append({"name": c.get("certificationname"),
                                    "due": due, "certifier": c.get("certifier")})
            except ValueError:
                pass
    print(f"\n[*] Overdue campaigns: {len(overdue)}")
    for o in overdue:
        print(f"  [!] {o['name']} (due: {o['due']}, certifier: {o['certifier']})")
    return overdue


def generate_report(campaigns, overdue, output_path):
    """Generate recertification status report."""
    report = {"report_date": datetime.now(timezone.utc).isoformat(),
              "active_campaigns": len(campaigns), "overdue_campaigns": len(overdue),
              "campaigns": campaigns[:50], "overdue": overdue}
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[*] Report saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Saviynt Access Recertification Agent")
    parser.add_argument("action", choices=["list", "details", "pending", "overdue", "full-audit"])
    parser.add_argument("--url", required=True, help="Saviynt EIC base URL")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--cert-key", help="Certification campaign key")
    parser.add_argument("-o", "--output", default="recert_report.json")
    args = parser.parse_args()

    headers = authenticate(args.url, args.username, args.password)
    if args.action == "list":
        list_campaigns(args.url, headers)
    elif args.action == "details" and args.cert_key:
        get_campaign_details(args.url, headers, args.cert_key)
    elif args.action == "pending" and args.cert_key:
        get_pending_items(args.url, headers, args.cert_key)
    elif args.action == "overdue":
        check_overdue_campaigns(args.url, headers)
    elif args.action == "full-audit":
        campaigns = list_campaigns(args.url, headers)
        overdue = check_overdue_campaigns(args.url, headers)
        generate_report(campaigns, overdue, args.output)


if __name__ == "__main__":
    main()
