#!/usr/bin/env python3
"""
Pod Security Admission Manager - Audit namespaces for PSA compliance,
apply labels, and generate migration reports.
"""

import json
import subprocess
import sys
import argparse


PSA_LABELS = {
    "enforce": "pod-security.kubernetes.io/enforce",
    "enforce-version": "pod-security.kubernetes.io/enforce-version",
    "audit": "pod-security.kubernetes.io/audit",
    "audit-version": "pod-security.kubernetes.io/audit-version",
    "warn": "pod-security.kubernetes.io/warn",
    "warn-version": "pod-security.kubernetes.io/warn-version",
}

SYSTEM_NAMESPACES = {
    "kube-system", "kube-public", "kube-node-lease",
    "calico-system", "tigera-operator", "gatekeeper-system", "falco",
}


def run_kubectl(args: list) -> str:
    """Execute kubectl command."""
    cmd = ["kubectl"] + args
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout, result.stderr, result.returncode


def get_namespace_psa_labels() -> list:
    """Get PSA labels for all namespaces."""
    stdout, _, _ = run_kubectl(["get", "namespaces", "-o", "json"])
    data = json.loads(stdout)
    results = []
    for ns in data.get("items", []):
        name = ns["metadata"]["name"]
        labels = ns["metadata"].get("labels", {})
        psa_info = {
            "namespace": name,
            "enforce": labels.get(PSA_LABELS["enforce"], "none"),
            "audit": labels.get(PSA_LABELS["audit"], "none"),
            "warn": labels.get(PSA_LABELS["warn"], "none"),
            "is_system": name in SYSTEM_NAMESPACES,
        }
        results.append(psa_info)
    return results


def dry_run_enforcement(namespace: str, level: str) -> dict:
    """Test what would happen if PSA enforcement was applied."""
    stdout, stderr, rc = run_kubectl([
        "label", "--dry-run=server", "--overwrite", "namespace", namespace,
        f"pod-security.kubernetes.io/enforce={level}"
    ])
    violations = []
    if "Warning" in stderr or "Warning" in stdout:
        for line in (stderr + stdout).split("\n"):
            if "Warning" in line or "violate" in line:
                violations.append(line.strip())

    return {
        "namespace": namespace,
        "level": level,
        "would_pass": rc == 0 and len(violations) == 0,
        "violations": violations,
    }


def audit_all_namespaces() -> list:
    """Audit all namespaces for PSA configuration."""
    ns_info = get_namespace_psa_labels()

    print("\n=== Pod Security Admission Audit ===\n")
    print(f"{'Namespace':<30} {'Enforce':<12} {'Audit':<12} {'Warn':<12} {'System'}")
    print("-" * 85)

    compliant = 0
    total = 0

    for ns in ns_info:
        if ns["is_system"]:
            status = "EXEMPT"
        elif ns["enforce"] == "restricted":
            status = "COMPLIANT"
            compliant += 1
        elif ns["enforce"] == "baseline":
            status = "PARTIAL"
        else:
            status = "NON-COMPLIANT"

        if not ns["is_system"]:
            total += 1

        system = "Yes" if ns["is_system"] else "No"
        print(f"{ns['namespace']:<30} {ns['enforce']:<12} {ns['audit']:<12} {ns['warn']:<12} {system}")

    print(f"\n{compliant}/{total} non-system namespaces at restricted level")
    return ns_info


def apply_psa_labels(namespace: str, level: str, version: str = "latest"):
    """Apply PSA labels to a namespace."""
    labels = [
        f"pod-security.kubernetes.io/enforce={level}",
        f"pod-security.kubernetes.io/enforce-version={version}",
        f"pod-security.kubernetes.io/audit=restricted",
        f"pod-security.kubernetes.io/audit-version={version}",
        f"pod-security.kubernetes.io/warn=restricted",
        f"pod-security.kubernetes.io/warn-version={version}",
    ]
    cmd = ["label", "--overwrite", "namespace", namespace] + labels
    stdout, stderr, rc = run_kubectl(cmd)
    if rc == 0:
        print(f"Applied {level} PSA labels to {namespace}")
    else:
        print(f"Failed: {stderr}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Pod Security Admission Manager")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("audit", help="Audit namespace PSA labels")

    test_cmd = subparsers.add_parser("test", help="Dry-run PSA enforcement")
    test_cmd.add_argument("--namespace", "-n", required=True)
    test_cmd.add_argument("--level", default="restricted", choices=["baseline", "restricted"])

    apply_cmd = subparsers.add_parser("apply", help="Apply PSA labels")
    apply_cmd.add_argument("--namespace", "-n", required=True)
    apply_cmd.add_argument("--level", required=True, choices=["privileged", "baseline", "restricted"])
    apply_cmd.add_argument("--version", default="latest")

    args = parser.parse_args()

    if args.command == "audit":
        audit_all_namespaces()
    elif args.command == "test":
        result = dry_run_enforcement(args.namespace, args.level)
        print(json.dumps(result, indent=2))
    elif args.command == "apply":
        apply_psa_labels(args.namespace, args.level, args.version)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
