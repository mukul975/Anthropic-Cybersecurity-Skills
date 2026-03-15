#!/usr/bin/env python3
"""Agent for threat emulation with Atomic Red Team test execution."""

import os
import json
import yaml
import argparse
import subprocess
from pathlib import Path
from datetime import datetime


def load_atomic_tests(atomics_path, technique_id):
    """Load Atomic Red Team test definitions for a technique."""
    technique_dir = Path(atomics_path) / technique_id
    yaml_path = technique_dir / f"{technique_id}.yaml"
    if not yaml_path.exists():
        return None
    with open(yaml_path) as f:
        return yaml.safe_load(f)


def list_available_techniques(atomics_path):
    """List all available Atomic Red Team techniques."""
    techniques = []
    atomics_dir = Path(atomics_path)
    for technique_dir in sorted(atomics_dir.iterdir()):
        if technique_dir.is_dir() and technique_dir.name.startswith("T"):
            yaml_file = technique_dir / f"{technique_dir.name}.yaml"
            if yaml_file.exists():
                with open(yaml_file) as f:
                    data = yaml.safe_load(f)
                techniques.append({
                    "technique_id": technique_dir.name,
                    "name": data.get("display_name", ""),
                    "test_count": len(data.get("atomic_tests", [])),
                    "platforms": list(set(
                        p for t in data.get("atomic_tests", [])
                        for p in t.get("supported_platforms", [])
                    )),
                })
    return techniques


def get_test_details(atomics_path, technique_id):
    """Get detailed information about tests for a technique."""
    data = load_atomic_tests(atomics_path, technique_id)
    if not data:
        return []
    tests = []
    for i, test in enumerate(data.get("atomic_tests", [])):
        tests.append({
            "test_number": i + 1,
            "name": test.get("name", ""),
            "description": test.get("description", ""),
            "platforms": test.get("supported_platforms", []),
            "executor": test.get("executor", {}).get("name", ""),
            "command": test.get("executor", {}).get("command", "")[:200],
            "cleanup": test.get("executor", {}).get("cleanup_command", "")[:200],
            "input_arguments": list(test.get("input_arguments", {}).keys()),
        })
    return tests


def execute_atomic_test(atomics_path, technique_id, test_number=1, platform="linux"):
    """Execute an Atomic Red Team test using atomic-operator."""
    try:
        from atomic_operator import AtomicOperator
        operator = AtomicOperator()
        result = operator.run(
            technique=technique_id,
            atomics_path=str(atomics_path),
            test_numbers=[test_number],
        )
        return {"status": "executed", "technique": technique_id,
                "test_number": test_number, "result": str(result)}
    except ImportError:
        return execute_atomic_manual(atomics_path, technique_id, test_number, platform)


def execute_atomic_manual(atomics_path, technique_id, test_number, platform):
    """Execute atomic test manually by parsing YAML and running commands."""
    data = load_atomic_tests(atomics_path, technique_id)
    if not data:
        return {"status": "error", "message": f"Technique {technique_id} not found"}
    tests = data.get("atomic_tests", [])
    if test_number > len(tests):
        return {"status": "error", "message": f"Test {test_number} not found"}
    test = tests[test_number - 1]
    executor = test.get("executor", {})
    command = executor.get("command", "")
    if not command:
        return {"status": "error", "message": "No command defined"}
    for arg_name, arg_def in test.get("input_arguments", {}).items():
        default = arg_def.get("default", "")
        command = command.replace(f"#{{{arg_name}}}", str(default))
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=60,
        )
        return {
            "status": "executed",
            "technique": technique_id,
            "test_name": test.get("name", ""),
            "return_code": result.returncode,
            "stdout": result.stdout[:500],
            "stderr": result.stderr[:500],
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "technique": technique_id}


def run_cleanup(atomics_path, technique_id, test_number=1):
    """Run cleanup commands for an atomic test."""
    data = load_atomic_tests(atomics_path, technique_id)
    if not data:
        return {"status": "error"}
    tests = data.get("atomic_tests", [])
    if test_number > len(tests):
        return {"status": "error"}
    test = tests[test_number - 1]
    cleanup_cmd = test.get("executor", {}).get("cleanup_command", "")
    if not cleanup_cmd:
        return {"status": "no_cleanup_defined"}
    for arg_name, arg_def in test.get("input_arguments", {}).items():
        cleanup_cmd = cleanup_cmd.replace(f"#{{{arg_name}}}", str(arg_def.get("default", "")))
    try:
        subprocess.run(cleanup_cmd, shell=True, capture_output=True, timeout=30)
        return {"status": "cleaned_up", "technique": technique_id}
    except subprocess.TimeoutExpired:
        return {"status": "cleanup_timeout"}


def build_coverage_matrix(atomics_path, detection_rules):
    """Compare available atomic tests against detection rules for gap analysis."""
    techniques = list_available_techniques(atomics_path)
    covered = set()
    for rule in detection_rules:
        for tag in rule.get("tags", []):
            if tag.startswith("attack.t"):
                covered.add(tag.replace("attack.", "").upper())
    matrix = []
    for t in techniques:
        tid = t["technique_id"]
        matrix.append({
            "technique_id": tid,
            "name": t["name"],
            "has_atomic_test": True,
            "has_detection_rule": tid in covered,
            "gap": tid not in covered,
        })
    return matrix


def main():
    parser = argparse.ArgumentParser(description="Atomic Red Team Threat Emulation Agent")
    parser.add_argument("--atomics-path", default="./atomic-red-team/atomics")
    parser.add_argument("--technique", help="ATT&CK technique ID (e.g., T1059.001)")
    parser.add_argument("--test-number", type=int, default=1)
    parser.add_argument("--output", default="atomic_report.json")
    parser.add_argument("--action", choices=[
        "list", "details", "execute", "cleanup", "coverage"
    ], default="list")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "results": {}}

    if args.action == "list":
        techniques = list_available_techniques(args.atomics_path)
        report["results"]["techniques"] = techniques
        print(f"[+] Available techniques: {len(techniques)}")

    if args.action == "details" and args.technique:
        tests = get_test_details(args.atomics_path, args.technique)
        report["results"]["tests"] = tests
        print(f"[+] Tests for {args.technique}: {len(tests)}")

    if args.action == "execute" and args.technique:
        result = execute_atomic_test(args.atomics_path, args.technique, args.test_number)
        report["results"]["execution"] = result
        print(f"[+] Executed {args.technique} test #{args.test_number}: {result['status']}")

    if args.action == "cleanup" and args.technique:
        result = run_cleanup(args.atomics_path, args.technique, args.test_number)
        report["results"]["cleanup"] = result
        print(f"[+] Cleanup: {result['status']}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
