#!/usr/bin/env python3
# For authorized testing only
"""Postman API security testing orchestration agent using Newman CLI."""

import json
import sys
import argparse
import subprocess
import os
from datetime import datetime


def run_newman_collection(collection_path, environment_path=None, reporters=None):
    """Execute a Postman collection using Newman CLI."""
    cmd = ["newman", "run", collection_path]
    if environment_path:
        cmd.extend(["-e", environment_path])
    if reporters:
        cmd.extend(["--reporters", reporters])
    else:
        cmd.extend(["--reporters", "cli,json"])
    cmd.extend(["--reporter-json-export", "newman-results.json"])
    cmd.extend(["--timeout-request", "10000"])
    cmd.extend(["--delay-request", "100"])

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    output = {
        "exit_code": result.returncode,
        "stdout_tail": result.stdout[-2000:] if result.stdout else "",
        "stderr": result.stderr[:500] if result.stderr else "",
    }

    if os.path.exists("newman-results.json"):
        with open("newman-results.json", "r") as f:
            output["results"] = json.load(f)
    return output


def parse_newman_results(results_path):
    """Parse Newman JSON results for security test outcomes."""
    with open(results_path, "r") as f:
        data = json.load(f)

    run_data = data.get("run", {})
    stats = run_data.get("stats", {})
    executions = run_data.get("executions", [])

    test_results = []
    for execution in executions:
        item = execution.get("item", {})
        response = execution.get("response", {})
        assertions = execution.get("assertions", [])

        for assertion in assertions:
            test_results.append({
                "request_name": item.get("name", ""),
                "test_name": assertion.get("assertion", ""),
                "passed": not assertion.get("error"),
                "status_code": response.get("code", 0),
                "response_time_ms": response.get("responseTime", 0),
                "error": assertion.get("error", {}).get("message", "") if assertion.get("error") else "",
            })

    failures = [t for t in test_results if not t["passed"]]
    return {
        "total_requests": stats.get("requests", {}).get("total", 0),
        "total_assertions": stats.get("assertions", {}).get("total", 0),
        "failed_assertions": stats.get("assertions", {}).get("failed", 0),
        "test_results": test_results,
        "failures": failures,
    }


def generate_bola_collection(base_url, endpoints, user_a_token, user_b_token):
    """Generate Postman collection for BOLA/IDOR testing across two user contexts."""
    items = []
    for ep in endpoints:
        method = ep.get("method", "GET")
        path = ep.get("path", "")
        items.append({
            "name": f"BOLA: {method} {path} (User B accessing User A resource)",
            "request": {
                "method": method,
                "header": [
                    {"key": "Authorization", "value": f"Bearer {user_b_token}"},
                    {"key": "Content-Type", "value": "application/json"},
                ],
                "url": {"raw": f"{base_url}{path}", "host": [base_url], "path": path.strip("/").split("/")},
            },
            "event": [{
                "listen": "test",
                "script": {
                    "exec": [
                        "pm.test('BOLA Check: Should return 403 or 404', function () {",
                        "    pm.expect(pm.response.code).to.be.oneOf([403, 404]);",
                        "});",
                        "pm.test('No data leakage in response', function () {",
                        f"    pm.expect(pm.response.text()).to.not.include('{user_a_token[:10]}');",
                        "});",
                    ],
                    "type": "text/javascript",
                },
            }],
        })

    collection = {
        "info": {
            "name": "BOLA/IDOR Security Tests",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "item": items,
    }
    return collection


def generate_injection_collection(base_url, endpoints):
    """Generate Postman collection for injection testing."""
    injection_payloads = [
        ("SQL Injection", "' OR '1'='1"),
        ("XSS", "<script>alert(1)</script>"),
        ("Command Injection", "; cat /etc/passwd"),
        ("SSTI", "{{7*7}}"),
        ("Path Traversal", "../../../etc/passwd"),
    ]

    items = []
    for ep in endpoints:
        path = ep.get("path", "")
        params = ep.get("params", [])
        for param in params:
            for payload_name, payload in injection_payloads:
                items.append({
                    "name": f"{payload_name}: {path}?{param}",
                    "request": {
                        "method": "GET",
                        "url": {
                            "raw": f"{base_url}{path}?{param}={payload}",
                            "host": [base_url],
                            "path": path.strip("/").split("/"),
                            "query": [{"key": param, "value": payload}],
                        },
                    },
                    "event": [{
                        "listen": "test",
                        "script": {
                            "exec": [
                                f"pm.test('{payload_name} — no 500 error', function () {{",
                                "    pm.expect(pm.response.code).to.not.equal(500);",
                                "});",
                                f"pm.test('{payload_name} — no stack trace', function () {{",
                                "    pm.expect(pm.response.text()).to.not.include('Traceback');",
                                "    pm.expect(pm.response.text()).to.not.include('Exception');",
                                "});",
                            ],
                            "type": "text/javascript",
                        },
                    }],
                })

    return {
        "info": {
            "name": "Injection Security Tests",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "item": items,
    }


def run_audit(args):
    """Execute Postman API security testing audit."""
    print(f"\n{'='*60}")
    print(f"  POSTMAN API SECURITY TESTING")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    report = {}

    if args.collection:
        newman = run_newman_collection(args.collection, args.environment)
        report["newman_run"] = {"exit_code": newman["exit_code"]}
        print(f"--- NEWMAN EXECUTION ---")
        print(f"  Exit code: {newman['exit_code']}")

        if os.path.exists("newman-results.json"):
            parsed = parse_newman_results("newman-results.json")
            report["test_results"] = parsed
            print(f"\n--- TEST RESULTS ---")
            print(f"  Total requests: {parsed['total_requests']}")
            print(f"  Total assertions: {parsed['total_assertions']}")
            print(f"  Failed: {parsed['failed_assertions']}")
            for f in parsed["failures"][:15]:
                print(f"  FAIL: {f['request_name']} — {f['test_name']}")
                if f["error"]:
                    print(f"        {f['error'][:80]}")

    if args.gen_bola:
        endpoints = json.loads(args.gen_bola)
        collection = generate_bola_collection(
            args.base_url or "http://localhost:8080",
            endpoints, args.token_a or "token_a", args.token_b or "token_b",
        )
        output_path = "bola-tests.postman_collection.json"
        with open(output_path, "w") as f_out:
            json.dump(collection, f_out, indent=2)
        report["bola_collection"] = output_path
        print(f"\n--- GENERATED BOLA COLLECTION ---")
        print(f"  Path: {output_path}")
        print(f"  Tests: {len(collection['item'])}")

    return report


def main():
    parser = argparse.ArgumentParser(description="Postman API Security Testing Agent")
    parser.add_argument("--collection", help="Postman collection JSON to run with Newman")
    parser.add_argument("--environment", help="Postman environment JSON")
    parser.add_argument("--gen-bola", help="JSON array of endpoints for BOLA test generation")
    parser.add_argument("--base-url", help="Base URL for generated collections")
    parser.add_argument("--token-a", help="User A auth token for BOLA tests")
    parser.add_argument("--token-b", help="User B auth token for BOLA tests")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
