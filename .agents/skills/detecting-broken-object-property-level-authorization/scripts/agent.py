#!/usr/bin/env python3
"""BOPLA vulnerability scanner for OWASP API3:2023 Broken Object Property Level Authorization.

Tests APIs for excessive data exposure and mass assignment vulnerabilities
by comparing responses against expected field sets and injecting extra properties.
"""

import argparse
import json
import sys
from copy import deepcopy

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)

SENSITIVE_PATTERNS = {
    "critical": ["password", "password_hash", "secret", "token", "api_key",
                 "private_key", "access_token", "refresh_token"],
    "high": ["ssn", "social_security", "tax_id", "credit_card", "card_number",
             "cvv", "bank_account", "routing_number"],
    "medium": ["salary", "income", "internal_notes", "role", "permissions",
               "is_admin", "is_superuser", "session_id", "ip_address"],
    "low": ["phone", "address", "date_of_birth", "dob", "gender"]
}

MASS_ASSIGNMENT_PAYLOADS = [
    ("role", "admin"), ("is_admin", True), ("is_verified", True),
    ("email_verified", True), ("account_type", "premium"),
    ("discount_rate", 100), ("permissions", ["admin", "write", "delete"]),
    ("account_balance", 999999), ("subscription_tier", "enterprise"),
]


def classify_field(field_name):
    lower = field_name.lower().split(".")[-1]
    for severity, patterns in SENSITIVE_PATTERNS.items():
        for p in patterns:
            if p in lower:
                return severity.upper()
    return None


def flatten_keys(obj, prefix=""):
    keys = []
    for k, v in obj.items():
        full = f"{prefix}.{k}" if prefix else k
        keys.append(full)
        if isinstance(v, dict):
            keys.extend(flatten_keys(v, full))
    return keys


def test_excessive_exposure(base_url, endpoint, expected_fields, headers):
    findings = []
    url = f"{base_url.rstrip('/')}{endpoint}"
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code != 200:
            return findings
        data = resp.json()
        objects = data if isinstance(data, list) else [data]
        if isinstance(data, dict) and "data" in data:
            inner = data["data"]
            objects = inner if isinstance(inner, list) else [inner]
        for obj in objects[:5]:
            if not isinstance(obj, dict):
                continue
            response_fields = set(flatten_keys(obj))
            unexpected = response_fields - set(expected_fields)
            for field in unexpected:
                sev = classify_field(field)
                if sev:
                    findings.append({
                        "endpoint": endpoint, "method": "GET",
                        "type": "excessive_exposure", "severity": sev,
                        "property": field,
                        "detail": f"Unexpected sensitive field '{field}' in response"
                    })
    except (requests.RequestException, json.JSONDecodeError) as e:
        findings.append({"error": str(e)})
    return findings


def test_mass_assignment(base_url, endpoint, headers, method="PUT"):
    findings = []
    url = f"{base_url.rstrip('/')}{endpoint}"
    try:
        original = requests.get(url, headers=headers, timeout=10)
        original_data = original.json() if original.status_code == 200 else {}
    except (requests.RequestException, json.JSONDecodeError):
        original_data = {}

    for field_name, injected_value in MASS_ASSIGNMENT_PAYLOADS:
        if original_data.get(field_name) == injected_value:
            continue
        test_data = deepcopy(original_data)
        test_data[field_name] = injected_value
        try:
            h = {**headers, "Content-Type": "application/json"}
            if method == "PUT":
                resp = requests.put(url, json=test_data, headers=h, timeout=10)
            elif method == "PATCH":
                resp = requests.patch(url, json={field_name: injected_value}, headers=h, timeout=10)
            else:
                resp = requests.post(url, json=test_data, headers=h, timeout=10)
            if resp.status_code in (200, 201, 204):
                verify = requests.get(url, headers=headers, timeout=10)
                if verify.status_code == 200 and verify.json().get(field_name) == injected_value:
                    sev = "CRITICAL" if field_name in ("role", "is_admin", "permissions") else "HIGH"
                    findings.append({
                        "endpoint": endpoint, "method": method,
                        "type": "mass_assignment", "severity": sev,
                        "property": field_name,
                        "detail": f"Injected {field_name}={injected_value} accepted"
                    })
                    if field_name in original_data:
                        requests.patch(url, json={field_name: original_data[field_name]},
                                       headers=h, timeout=10)
        except requests.RequestException:
            continue
    return findings


def main():
    parser = argparse.ArgumentParser(description="BOPLA Vulnerability Scanner (OWASP API3:2023)")
    parser.add_argument("--base-url", required=True, help="API base URL")
    parser.add_argument("--endpoint", required=True, help="Endpoint to test (e.g. /api/v1/users/1)")
    parser.add_argument("--token", help="Bearer token for Authorization header")
    parser.add_argument("--expected-fields", nargs="+", default=[], help="Expected response fields")
    parser.add_argument("--test", choices=["exposure", "mass_assignment", "both"], default="both")
    parser.add_argument("--method", choices=["PUT", "PATCH", "POST"], default="PUT")
    args = parser.parse_args()

    headers = {}
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"

    results = {"endpoint": args.endpoint, "findings": []}
    if args.test in ("exposure", "both"):
        results["findings"].extend(
            test_excessive_exposure(args.base_url, args.endpoint, args.expected_fields, headers))
    if args.test in ("mass_assignment", "both"):
        results["findings"].extend(
            test_mass_assignment(args.base_url, args.endpoint, headers, args.method))

    results["total_findings"] = len(results["findings"])
    results["by_severity"] = {}
    for f in results["findings"]:
        sev = f.get("severity", "UNKNOWN")
        results["by_severity"][sev] = results["by_severity"].get(sev, 0) + 1

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
