#!/usr/bin/env python3
"""Agent for testing business logic vulnerabilities during authorized assessments."""

import requests
import json
import sys
import argparse
import urllib3
import threading
from datetime import datetime
from urllib.parse import urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def test_price_manipulation(base_url, token, cart_endpoint="/api/cart/add"):
    """Test price and quantity manipulation in purchase flows."""
    print("\n[*] Testing price/quantity manipulation...")
    findings = []
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    url = urljoin(base_url, cart_endpoint)
    test_cases = [
        {"name": "negative_quantity", "payload": {"product_id": 1, "quantity": -1}, "severity": "CRITICAL"},
        {"name": "zero_price", "payload": {"product_id": 1, "quantity": 1, "price": 0}, "severity": "CRITICAL"},
        {"name": "float_quantity", "payload": {"product_id": 1, "quantity": 0.001}, "severity": "HIGH"},
        {"name": "huge_quantity", "payload": {"product_id": 1, "quantity": 999999999}, "severity": "HIGH"},
        {"name": "negative_price", "payload": {"product_id": 1, "quantity": 1, "price": -99.99}, "severity": "CRITICAL"},
    ]
    for tc in test_cases:
        try:
            resp = requests.post(url, headers=headers, json=tc["payload"], timeout=10, verify=False)
            if resp.status_code in (200, 201):
                findings.append({
                    "type": "PRICE_MANIPULATION", "test": tc["name"],
                    "payload": tc["payload"], "status": resp.status_code,
                    "severity": tc["severity"],
                })
                print(f"  [!] {tc['name']}: Accepted (status {resp.status_code})")
            else:
                print(f"  [+] {tc['name']}: Rejected (status {resp.status_code})")
        except requests.RequestException as e:
            print(f"  [-] {tc['name']}: Error - {e}")
    return findings


def test_checkout_total_override(base_url, token, checkout_endpoint="/api/checkout"):
    """Test if the checkout total can be overridden in the request."""
    print("\n[*] Testing checkout total override...")
    findings = []
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    url = urljoin(base_url, checkout_endpoint)
    payloads = [
        {"cart_id": "test", "total": 0.01, "payment_method": "card"},
        {"cart_id": "test", "total": 0, "payment_method": "card"},
        {"cart_id": "test", "amount": 0.01},
    ]
    for payload in payloads:
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=10, verify=False)
            if resp.status_code in (200, 201):
                findings.append({
                    "type": "TOTAL_OVERRIDE", "payload": payload,
                    "status": resp.status_code, "severity": "CRITICAL",
                })
                print(f"  [!] Checkout accepted with total={payload.get('total', payload.get('amount'))}")
        except requests.RequestException:
            continue
    return findings


def test_coupon_reuse(base_url, token, coupon_endpoint="/api/cart/apply-coupon", code="DISCOUNT50"):
    """Test if a coupon can be applied multiple times."""
    print(f"\n[*] Testing coupon reuse ({code})...")
    findings = []
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    url = urljoin(base_url, coupon_endpoint)
    success_count = 0
    for i in range(5):
        try:
            resp = requests.post(url, headers=headers, json={"coupon_code": code},
                                 timeout=10, verify=False)
            if resp.status_code in (200, 201):
                success_count += 1
        except requests.RequestException:
            break
    if success_count > 1:
        findings.append({
            "type": "COUPON_REUSE", "code": code, "times_applied": success_count,
            "severity": "HIGH",
        })
        print(f"  [!] Coupon applied {success_count} times!")
    else:
        print(f"  [+] Coupon properly limited")
    return findings


def test_workflow_bypass(base_url, token, steps):
    """Test if workflow steps can be skipped."""
    print("\n[*] Testing workflow step bypass...")
    findings = []
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    for step in steps:
        url = urljoin(base_url, step["endpoint"])
        try:
            resp = requests.request(step.get("method", "POST"), url, headers=headers,
                                    json=step.get("payload", {}), timeout=10, verify=False)
            if resp.status_code in (200, 201):
                findings.append({
                    "type": "WORKFLOW_BYPASS", "step": step["name"],
                    "endpoint": step["endpoint"], "status": resp.status_code,
                    "severity": "HIGH",
                })
                print(f"  [!] Step '{step['name']}' bypassed (status {resp.status_code})")
            else:
                print(f"  [+] Step '{step['name']}' enforced (status {resp.status_code})")
        except requests.RequestException:
            continue
    return findings


def test_race_condition(base_url, token, endpoint, payload, concurrent=10):
    """Test for race conditions by sending concurrent requests."""
    print(f"\n[*] Testing race condition on {endpoint} ({concurrent} concurrent requests)...")
    findings = []
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    url = urljoin(base_url, endpoint)
    results = []

    def send_request():
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=10, verify=False)
            results.append({"status": resp.status_code, "body": resp.text[:200]})
        except requests.RequestException:
            results.append({"status": 0, "body": "error"})

    threads = [threading.Thread(target=send_request) for _ in range(concurrent)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = sum(1 for r in results if r["status"] in (200, 201))
    if successes > 1:
        findings.append({
            "type": "RACE_CONDITION", "endpoint": endpoint,
            "concurrent": concurrent, "successes": successes, "severity": "CRITICAL",
        })
        print(f"  [!] {successes}/{concurrent} requests succeeded (potential race condition)")
    else:
        print(f"  [+] {successes}/{concurrent} succeeded (properly serialized)")
    return findings


def test_self_referral(base_url, token, referral_endpoint="/api/referrals/invite", email="self@test.com"):
    """Test if self-referral is possible."""
    print("\n[*] Testing self-referral...")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    url = urljoin(base_url, referral_endpoint)
    try:
        resp = requests.post(url, headers=headers, json={"referral_email": email},
                             timeout=10, verify=False)
        if resp.status_code in (200, 201):
            print(f"  [!] Self-referral accepted")
            return [{"type": "SELF_REFERRAL", "severity": "MEDIUM"}]
        else:
            print(f"  [+] Self-referral blocked (status {resp.status_code})")
    except requests.RequestException:
        pass
    return []


def generate_report(findings, output_path):
    """Generate business logic vulnerability report."""
    report = {
        "assessment_date": datetime.now().isoformat(),
        "total_findings": len(findings),
        "by_type": {},
        "findings": findings,
    }
    for f in findings:
        t = f.get("type", "UNKNOWN")
        report["by_type"][t] = report["by_type"].get(t, 0) + 1
    with open(output_path, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"\n[*] Report: {output_path} | Findings: {len(findings)}")


def main():
    parser = argparse.ArgumentParser(description="Business Logic Vulnerability Testing Agent")
    parser.add_argument("base_url", help="Base URL of the target application")
    parser.add_argument("--token", required=True, help="Bearer token for authentication")
    parser.add_argument("--cart-endpoint", default="/api/cart/add")
    parser.add_argument("--checkout-endpoint", default="/api/checkout")
    parser.add_argument("--coupon-code", default="DISCOUNT50")
    parser.add_argument("-o", "--output", default="business_logic_report.json")
    args = parser.parse_args()

    print(f"[*] Business Logic Vulnerability Assessment: {args.base_url}")
    findings = []
    findings.extend(test_price_manipulation(args.base_url, args.token, args.cart_endpoint))
    findings.extend(test_checkout_total_override(args.base_url, args.token, args.checkout_endpoint))
    findings.extend(test_coupon_reuse(args.base_url, args.token, code=args.coupon_code))
    findings.extend(test_race_condition(args.base_url, args.token,
                                        args.cart_endpoint, {"coupon_code": args.coupon_code}))
    findings.extend(test_self_referral(args.base_url, args.token))
    generate_report(findings, args.output)


if __name__ == "__main__":
    main()
