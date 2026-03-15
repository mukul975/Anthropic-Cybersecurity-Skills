#!/usr/bin/env python3
"""DefectDojo Vulnerability Dashboard Automation.

Manages products, engagements, scan imports, and metrics via the
DefectDojo REST API v2.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

DD_URL = os.environ.get("DD_URL", "http://localhost:8080/api/v2")
DD_API_KEY = os.environ.get("DD_API_KEY", "")


def get_headers():
    return {
        "Authorization": f"Token {DD_API_KEY}",
        "Content-Type": "application/json",
    }


def create_product_type(name, description=""):
    resp = requests.post(
        f"{DD_URL}/product_types/",
        headers=get_headers(),
        json={"name": name, "description": description},
        timeout=30,
    )
    resp.raise_for_status()
    pt = resp.json()
    print(f"[+] Created product type: {name} (ID: {pt['id']})")
    return pt["id"]


def create_product(name, product_type_id, description=""):
    resp = requests.post(
        f"{DD_URL}/products/",
        headers=get_headers(),
        json={
            "name": name,
            "description": description,
            "prod_type": product_type_id,
        },
        timeout=30,
    )
    resp.raise_for_status()
    product = resp.json()
    print(f"[+] Created product: {name} (ID: {product['id']})")
    return product["id"]


def create_engagement(name, product_id, start_date=None, end_date=None):
    if not start_date:
        start_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if not end_date:
        end_date = "2025-12-31"
    resp = requests.post(
        f"{DD_URL}/engagements/",
        headers=get_headers(),
        json={
            "name": name,
            "product": product_id,
            "target_start": start_date,
            "target_end": end_date,
            "engagement_type": "CI/CD",
            "status": "In Progress",
        },
        timeout=30,
    )
    resp.raise_for_status()
    eng = resp.json()
    print(f"[+] Created engagement: {name} (ID: {eng['id']})")
    return eng["id"]


def import_scan(scan_file, scan_type, product_name, engagement_name=None):
    """Import or reimport scan results into DefectDojo."""
    data = {
        "scan_type": scan_type,
        "product_name": product_name,
        "auto_create_context": "true",
        "deduplication_on_engagement": "true",
        "close_old_findings": "true",
    }
    if engagement_name:
        data["engagement_name"] = engagement_name

    with open(scan_file, "rb") as f:
        resp = requests.post(
            f"{DD_URL}/reimport-scan/",
            headers={"Authorization": f"Token {DD_API_KEY}"},
            data=data,
            files={"file": f},
            timeout=120,
        )

    if resp.status_code in (200, 201):
        result = resp.json()
        test_id = result.get("test", 0)
        print(f"[+] Scan imported successfully (Test ID: {test_id})")
        print(f"    New findings: {result.get('statistics', {}).get('created', 0)}")
        print(f"    Closed findings: {result.get('statistics', {}).get('closed', 0)}")
        print(f"    Reactivated: {result.get('statistics', {}).get('reactivated', 0)}")
        return result
    else:
        print(f"[-] Import failed: {resp.status_code} {resp.text}")
        return None


def get_findings(product_id=None, severity=None, active=True, limit=100):
    """Query findings with filters."""
    params = {"limit": limit, "active": str(active).lower()}
    if product_id:
        params["test__engagement__product"] = product_id
    if severity:
        params["severity"] = severity

    resp = requests.get(f"{DD_URL}/findings/", headers=get_headers(), params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()


def get_metrics(product_id=None):
    """Get vulnerability metrics for dashboard."""
    params = {"limit": 0}
    if product_id:
        params["test__engagement__product"] = product_id

    metrics = {}
    for severity in ["Critical", "High", "Medium", "Low", "Info"]:
        resp = requests.get(
            f"{DD_URL}/findings/",
            headers=get_headers(),
            params={**params, "severity": severity, "active": "true"},
            timeout=30,
        )
        if resp.status_code == 200:
            metrics[severity] = resp.json().get("count", 0)

    # SLA breached findings
    resp = requests.get(
        f"{DD_URL}/findings/",
        headers=get_headers(),
        params={**params, "active": "true", "is_mitigated": "false"},
        timeout=30,
    )
    if resp.status_code == 200:
        metrics["total_active"] = resp.json().get("count", 0)

    return metrics


def generate_dashboard_report(output_path, product_id=None):
    """Generate dashboard metrics report."""
    metrics = get_metrics(product_id)
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "active_findings": metrics,
        "total_active": metrics.get("total_active", 0),
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] Dashboard Report: {output_path}")
    print(f"    Critical: {metrics.get('Critical', 0)}")
    print(f"    High: {metrics.get('High', 0)}")
    print(f"    Medium: {metrics.get('Medium', 0)}")
    print(f"    Low: {metrics.get('Low', 0)}")
    print(f"    Total Active: {metrics.get('total_active', 0)}")
    return report


def main():
    parser = argparse.ArgumentParser(description="DefectDojo Dashboard Automation")
    parser.add_argument("--url", default=DD_URL, help="DefectDojo API URL")
    parser.add_argument("--api-key", default=DD_API_KEY, help="API key")

    sub = parser.add_subparsers(dest="command")

    setup = sub.add_parser("setup", help="Create product type, product, engagement")
    setup.add_argument("--product-type", required=True)
    setup.add_argument("--product", required=True)
    setup.add_argument("--engagement", default="CI/CD")

    imp = sub.add_parser("import", help="Import scan results")
    imp.add_argument("--file", required=True)
    imp.add_argument("--scan-type", required=True)
    imp.add_argument("--product", required=True)
    imp.add_argument("--engagement")

    dash = sub.add_parser("dashboard", help="Generate dashboard report")
    dash.add_argument("--product-id", type=int)
    dash.add_argument("--output", default="defectdojo_dashboard.json")

    findings = sub.add_parser("findings", help="List findings")
    findings.add_argument("--product-id", type=int)
    findings.add_argument("--severity")
    findings.add_argument("--limit", type=int, default=20)

    args = parser.parse_args()

    global DD_URL, DD_API_KEY
    DD_URL = args.url
    if args.api_key:
        DD_API_KEY = args.api_key

    if args.command == "setup":
        pt_id = create_product_type(args.product_type)
        prod_id = create_product(args.product, pt_id)
        create_engagement(args.engagement, prod_id)
    elif args.command == "import":
        import_scan(args.file, args.scan_type, args.product, args.engagement)
    elif args.command == "dashboard":
        generate_dashboard_report(args.output, args.product_id)
    elif args.command == "findings":
        result = get_findings(args.product_id, args.severity, limit=args.limit)
        for f in result.get("results", []):
            print(f"  [{f['severity']}] {f['title']} (ID: {f['id']})")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
