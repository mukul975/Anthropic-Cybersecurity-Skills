#!/usr/bin/env python3
"""Open Policy Agent (OPA) policy-as-code agent.

Evaluates security policies against infrastructure configurations using
the OPA REST API or CLI. Supports evaluating Rego policies for Kubernetes
admission control, Terraform plans, IAM policies, and custom security rules.
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    requests = None


def find_opa_binary():
    """Locate the OPA binary on the system."""
    custom_path = os.environ.get("OPA_PATH")
    if custom_path and os.path.isfile(custom_path):
        return custom_path
    for name in ["opa", "opa.exe"]:
        for directory in os.environ.get("PATH", "").split(os.pathsep):
            full_path = os.path.join(directory, name)
            if os.path.isfile(full_path):
                return full_path
    return None


def eval_policy_cli(opa_bin, policy_path, input_path, data_path=None, query="data"):
    """Evaluate a Rego policy using OPA CLI."""
    cmd = [opa_bin, "eval", "--format", "json"]
    cmd.extend(["--bundle", policy_path])
    if input_path:
        cmd.extend(["--input", input_path])
    if data_path:
        cmd.extend(["--data", data_path])
    cmd.append(query)

    print(f"[*] Running: {' '.join(cmd)}")
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        print(f"[!] OPA error: {result.stderr}", file=sys.stderr)
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print("[!] Failed to parse OPA output", file=sys.stderr)
        return None


def eval_policy_api(opa_url, policy_path, input_data):
    """Evaluate a policy via OPA REST API."""
    if not requests:
        print("[!] 'requests' library required for API mode", file=sys.stderr)
        sys.exit(1)
    url = f"{opa_url}/v1/data/{policy_path.replace('.', '/')}"
    print(f"[*] Querying OPA API: {url}")
    resp = requests.post(
        url,
        json={"input": input_data},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def test_policies(opa_bin, policy_dir):
    """Run OPA test suite against policy directory."""
    cmd = [opa_bin, "test", "--format", "json", policy_dir, "-v"]
    print(f"[*] Running policy tests: {' '.join(cmd)}")
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=120,
    )
    try:
        test_results = json.loads(result.stdout)
    except json.JSONDecodeError:
        test_results = []
    return test_results, result.returncode


def check_policy_syntax(opa_bin, policy_path):
    """Check Rego policy syntax."""
    cmd = [opa_bin, "check", "--format", "json", policy_path]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode == 0:
        print(f"[+] Policy syntax valid: {policy_path}")
        return True, []
    try:
        errors = json.loads(result.stdout)
    except json.JSONDecodeError:
        errors = [{"message": result.stderr}]
    print(f"[!] Syntax errors in {policy_path}")
    return False, errors


def extract_violations(eval_result, violation_key="violations"):
    """Extract policy violations from OPA evaluation result."""
    violations = []
    if not eval_result:
        return violations

    results = eval_result.get("result", [])
    if isinstance(results, list):
        for entry in results:
            bindings = entry.get("bindings", {})
            expressions = entry.get("expressions", [])
            for expr in expressions:
                value = expr.get("value", {})
                if isinstance(value, dict):
                    for key, val in value.items():
                        if key == violation_key and isinstance(val, list):
                            violations.extend(val)
                        elif isinstance(val, dict):
                            nested_violations = val.get(violation_key, [])
                            if isinstance(nested_violations, list):
                                violations.extend(nested_violations)
    elif isinstance(results, dict):
        violations = results.get(violation_key, [])

    return violations


def format_summary(violations, test_results, policy_path, input_path):
    """Print evaluation summary."""
    print(f"\n{'='*60}")
    print("  OPA Policy Evaluation Report")
    print(f"{'='*60}")
    print(f"  Policy    : {policy_path}")
    print(f"  Input     : {input_path or 'N/A'}")
    print(f"  Violations: {len(violations)}")

    if test_results:
        passed = sum(1 for t in test_results if t.get("pass", t.get("result") == "pass"))
        failed = len(test_results) - passed
        print(f"  Tests     : {passed} passed, {failed} failed")

    if violations:
        severity_counts = {}
        for v in violations:
            sev = "HIGH"
            if isinstance(v, dict):
                sev = v.get("severity", v.get("level", "HIGH"))
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        print("\n  Violations by Severity:")
        for sev, count in sorted(severity_counts.items()):
            print(f"    {sev:10s}: {count}")

        print("\n  Violation Details:")
        for v in violations[:20]:
            if isinstance(v, dict):
                msg = v.get("msg", v.get("message", str(v)))
                resource = v.get("resource", v.get("name", ""))
                sev = v.get("severity", "HIGH")
                print(f"    [{sev:6s}] {resource:30s} | {msg[:60]}")
            else:
                print(f"    {str(v)[:80]}")

    return len(violations)


def main():
    parser = argparse.ArgumentParser(
        description="Open Policy Agent policy-as-code evaluation agent"
    )
    sub = parser.add_subparsers(dest="command", help="Action")

    p_eval = sub.add_parser("eval", help="Evaluate policy against input")
    p_eval.add_argument("--policy", required=True, help="Path to Rego policy or bundle dir")
    p_eval.add_argument("--input", dest="input_file", help="Path to input JSON")
    p_eval.add_argument("--data", help="Path to external data JSON")
    p_eval.add_argument("--query", default="data", help="OPA query (default: data)")
    p_eval.add_argument("--violation-key", default="violations",
                        help="Key in result containing violations")

    p_api = sub.add_parser("api", help="Evaluate via OPA REST API")
    p_api.add_argument("--url", default="http://localhost:8181", help="OPA server URL")
    p_api.add_argument("--policy-path", required=True, help="OPA document path (e.g., authz.allow)")
    p_api.add_argument("--input", dest="input_file", required=True, help="Input JSON file")

    p_test = sub.add_parser("test", help="Run OPA test suite")
    p_test.add_argument("--policy-dir", required=True, help="Directory containing policies and tests")

    p_check = sub.add_parser("check", help="Check Rego syntax")
    p_check.add_argument("--policy", required=True, help="Policy file or directory")

    parser.add_argument("--output", "-o", help="Output JSON report path")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    opa_bin = find_opa_binary()
    violations = []
    test_results = []

    if args.command == "eval":
        if not opa_bin:
            print("[!] OPA binary not found", file=sys.stderr)
            sys.exit(1)
        eval_result = eval_policy_cli(
            opa_bin, args.policy, args.input_file, args.data, args.query
        )
        violations = extract_violations(eval_result, args.violation_key)
        format_summary(violations, [], args.policy, args.input_file)

    elif args.command == "api":
        with open(args.input_file, "r") as f:
            input_data = json.load(f)
        eval_result = eval_policy_api(args.url, args.policy_path, input_data)
        violations = extract_violations(eval_result)
        format_summary(violations, [], args.policy_path, args.input_file)

    elif args.command == "test":
        if not opa_bin:
            print("[!] OPA binary not found", file=sys.stderr)
            sys.exit(1)
        test_results, returncode = test_policies(opa_bin, args.policy_dir)
        format_summary([], test_results, args.policy_dir, None)

    elif args.command == "check":
        if not opa_bin:
            print("[!] OPA binary not found", file=sys.stderr)
            sys.exit(1)
        valid, errors = check_policy_syntax(opa_bin, args.policy)
        if not valid:
            for e in errors:
                print(f"    Error: {e}")

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "Open Policy Agent",
        "command": args.command,
        "violations_count": len(violations),
        "violations": violations,
        "test_results": test_results,
        "risk_level": (
            "CRITICAL" if len(violations) > 10
            else "HIGH" if len(violations) > 0
            else "LOW"
        ),
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
