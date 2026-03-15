#!/usr/bin/env python3
"""
OPA Policy Evaluation Pipeline Script

Runs conftest against Kubernetes manifests and Terraform files,
evaluates policy compliance, and generates reports.

Usage:
    python process.py --manifests-dir ./k8s --policies-dir ./policies
    python process.py --manifests-dir ./terraform --policies-dir ./policies --parser hcl2
"""

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class PolicyViolation:
    file: str
    rule: str
    message: str
    severity: str = "HIGH"


def run_conftest(manifests_dir: str, policies_dir: str,
                 parser: str = "yaml") -> dict:
    """Run conftest and return JSON results."""
    files = []
    extensions = {"yaml": [".yaml", ".yml"], "hcl2": [".tf"], "dockerfile": ["Dockerfile"]}
    for ext in extensions.get(parser, [".yaml", ".yml"]):
        files.extend(str(p) for p in Path(manifests_dir).rglob(f"*{ext}"))

    if not files:
        return {"results": [], "error": f"No {parser} files found in {manifests_dir}"}

    cmd = [
        "conftest", "test",
        "--policy", policies_dir,
        "--output", "json",
        "--parser", parser
    ] + files

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if proc.stdout:
            return {"results": json.loads(proc.stdout), "error": ""}
        return {"results": [], "error": proc.stderr[:300]}
    except subprocess.TimeoutExpired:
        return {"results": [], "error": "conftest timed out"}
    except FileNotFoundError:
        return {"results": [], "error": "conftest not found"}
    except json.JSONDecodeError:
        return {"results": [], "error": "Failed to parse conftest output"}


def parse_conftest_results(results: list) -> list:
    """Parse conftest JSON results into violations."""
    violations = []
    for result in results:
        filename = result.get("filename", "unknown")
        for failure in result.get("failures", []):
            violations.append(PolicyViolation(
                file=filename,
                rule=failure.get("metadata", {}).get("rule", "unknown"),
                message=failure.get("msg", ""),
                severity="HIGH"
            ))
        for warning in result.get("warnings", []):
            violations.append(PolicyViolation(
                file=filename,
                rule=warning.get("metadata", {}).get("rule", "unknown"),
                message=warning.get("msg", ""),
                severity="MEDIUM"
            ))
    return violations


def check_gatekeeper_violations(namespace: str = "") -> list:
    """Query Gatekeeper audit violations from the cluster."""
    cmd = ["kubectl", "get", "constraints", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            return []

        data = json.loads(proc.stdout)
        violations = []
        for item in data.get("items", []):
            status = item.get("status", {})
            for v in status.get("violations", []):
                violations.append(PolicyViolation(
                    file=f"{v.get('kind', '')}/{v.get('name', '')}",
                    rule=item.get("kind", ""),
                    message=v.get("message", ""),
                    severity="HIGH" if item.get("spec", {}).get("enforcementAction") == "deny" else "MEDIUM"
                ))
        return violations
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        return []


def main():
    parser = argparse.ArgumentParser(description="OPA Policy Evaluation Pipeline")
    parser.add_argument("--manifests-dir", required=True)
    parser.add_argument("--policies-dir", required=True)
    parser.add_argument("--parser", default="yaml", choices=["yaml", "hcl2", "dockerfile"])
    parser.add_argument("--output", default="policy-report.json")
    parser.add_argument("--fail-on-violations", action="store_true")
    parser.add_argument("--check-cluster", action="store_true",
                        help="Also check Gatekeeper violations in cluster")
    args = parser.parse_args()

    violations = []

    print(f"[*] Evaluating policies from {args.policies_dir} against {args.manifests_dir}")
    result = run_conftest(os.path.abspath(args.manifests_dir),
                          os.path.abspath(args.policies_dir), args.parser)

    if result.get("error"):
        print(f"[WARN] {result['error']}")
    else:
        violations.extend(parse_conftest_results(result["results"]))
        print(f"    conftest: {len(violations)} violations")

    if args.check_cluster:
        cluster_violations = check_gatekeeper_violations()
        violations.extend(cluster_violations)
        print(f"    cluster: {len(cluster_violations)} audit violations")

    report = {
        "metadata": {"date": datetime.now(timezone.utc).isoformat()},
        "summary": {
            "total_violations": len(violations),
            "high": sum(1 for v in violations if v.severity == "HIGH"),
            "medium": sum(1 for v in violations if v.severity == "MEDIUM")
        },
        "violations": [
            {"file": v.file, "rule": v.rule, "message": v.message, "severity": v.severity}
            for v in violations
        ]
    }

    output_path = os.path.abspath(args.output)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[*] Report: {output_path}")

    passed = len(violations) == 0
    print(f"\n[{'PASS' if passed else 'FAIL'}] {len(violations)} policy violations found")
    for v in violations[:10]:
        print(f"  [{v.severity}] {v.file}: {v.message[:100]}")

    if args.fail_on_violations and not passed:
        sys.exit(1)


if __name__ == "__main__":
    main()
