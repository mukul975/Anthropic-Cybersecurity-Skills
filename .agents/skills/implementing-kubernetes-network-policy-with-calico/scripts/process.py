#!/usr/bin/env python3
"""
Calico Network Policy Manager - Generate, validate, and audit Kubernetes
network policies using Calico for zero-trust pod communication.
"""

import json
import subprocess
import sys
import argparse
import yaml
from typing import Optional


def run_kubectl(args: list, namespace: Optional[str] = None) -> str:
    """Execute kubectl command and return output."""
    cmd = ["kubectl"]
    if namespace:
        cmd.extend(["-n", namespace])
    cmd.extend(args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"kubectl error: {result.stderr}", file=sys.stderr)
    return result.stdout


def get_namespaces() -> list:
    """Get all non-system namespaces."""
    output = run_kubectl(["get", "namespaces", "-o", "json"])
    ns_data = json.loads(output)
    system_ns = {"kube-system", "kube-public", "kube-node-lease", "calico-system", "tigera-operator"}
    return [
        ns["metadata"]["name"]
        for ns in ns_data["items"]
        if ns["metadata"]["name"] not in system_ns
    ]


def get_network_policies(namespace: str) -> list:
    """Get all network policies in a namespace."""
    output = run_kubectl(["get", "networkpolicy", "-o", "json"], namespace=namespace)
    if not output.strip():
        return []
    data = json.loads(output)
    return data.get("items", [])


def check_default_deny(namespace: str) -> dict:
    """Check if default deny policies exist for a namespace."""
    policies = get_network_policies(namespace)
    has_ingress_deny = False
    has_egress_deny = False

    for pol in policies:
        spec = pol.get("spec", {})
        selector = spec.get("podSelector", {})
        policy_types = spec.get("policyTypes", [])

        if selector == {} or selector.get("matchLabels") is None:
            if "Ingress" in policy_types and not spec.get("ingress"):
                has_ingress_deny = True
            if "Egress" in policy_types and not spec.get("egress"):
                has_egress_deny = True

    return {
        "namespace": namespace,
        "default_deny_ingress": has_ingress_deny,
        "default_deny_egress": has_egress_deny,
        "policy_count": len(policies),
    }


def audit_all_namespaces() -> list:
    """Audit all namespaces for network policy coverage."""
    namespaces = get_namespaces()
    results = []
    for ns in namespaces:
        result = check_default_deny(ns)
        results.append(result)
    return results


def generate_default_deny(namespace: str) -> str:
    """Generate default deny ingress and egress policies for a namespace."""
    policies = [
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "default-deny-ingress",
                "namespace": namespace,
            },
            "spec": {
                "podSelector": {},
                "policyTypes": ["Ingress"],
            },
        },
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "default-deny-egress",
                "namespace": namespace,
            },
            "spec": {
                "podSelector": {},
                "policyTypes": ["Egress"],
            },
        },
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "allow-dns-egress",
                "namespace": namespace,
            },
            "spec": {
                "podSelector": {},
                "policyTypes": ["Egress"],
                "egress": [
                    {
                        "ports": [
                            {"protocol": "UDP", "port": 53},
                            {"protocol": "TCP", "port": 53},
                        ]
                    }
                ],
            },
        },
    ]

    return yaml.dump_all(policies, default_flow_style=False)


def generate_allow_policy(
    namespace: str,
    name: str,
    target_labels: dict,
    source_labels: dict,
    port: int,
    protocol: str = "TCP",
) -> str:
    """Generate an allow ingress policy."""
    policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": name,
            "namespace": namespace,
        },
        "spec": {
            "podSelector": {"matchLabels": target_labels},
            "policyTypes": ["Ingress"],
            "ingress": [
                {
                    "from": [{"podSelector": {"matchLabels": source_labels}}],
                    "ports": [{"protocol": protocol, "port": port}],
                }
            ],
        },
    }
    return yaml.dump(policy, default_flow_style=False)


def print_audit_report(results: list):
    """Print formatted audit report."""
    print("\n=== Kubernetes Network Policy Audit Report ===\n")
    print(f"{'Namespace':<30} {'Deny Ingress':<15} {'Deny Egress':<15} {'Policies':<10} {'Status'}")
    print("-" * 85)

    compliant = 0
    total = len(results)

    for r in results:
        ingress = "YES" if r["default_deny_ingress"] else "NO"
        egress = "YES" if r["default_deny_egress"] else "NO"
        status = "COMPLIANT" if r["default_deny_ingress"] and r["default_deny_egress"] else "NON-COMPLIANT"
        if status == "COMPLIANT":
            compliant += 1
        print(f"{r['namespace']:<30} {ingress:<15} {egress:<15} {r['policy_count']:<10} {status}")

    print(f"\n{compliant}/{total} namespaces compliant with default-deny policy")


def main():
    parser = argparse.ArgumentParser(description="Calico Network Policy Manager")
    subparsers = parser.add_subparsers(dest="command")

    # Audit command
    subparsers.add_parser("audit", help="Audit all namespaces for network policy coverage")

    # Generate deny command
    gen_deny = subparsers.add_parser("generate-deny", help="Generate default deny policies")
    gen_deny.add_argument("--namespace", "-n", required=True, help="Target namespace")
    gen_deny.add_argument("--apply", action="store_true", help="Apply policies directly")

    # Generate allow command
    gen_allow = subparsers.add_parser("generate-allow", help="Generate allow policy")
    gen_allow.add_argument("--namespace", "-n", required=True)
    gen_allow.add_argument("--name", required=True, help="Policy name")
    gen_allow.add_argument("--target-app", required=True, help="Target pod app label")
    gen_allow.add_argument("--source-app", required=True, help="Source pod app label")
    gen_allow.add_argument("--port", type=int, required=True, help="Allowed port")
    gen_allow.add_argument("--protocol", default="TCP", choices=["TCP", "UDP"])

    args = parser.parse_args()

    if args.command == "audit":
        results = audit_all_namespaces()
        print_audit_report(results)

    elif args.command == "generate-deny":
        policy_yaml = generate_default_deny(args.namespace)
        if args.apply:
            proc = subprocess.run(
                ["kubectl", "apply", "-f", "-"],
                input=policy_yaml,
                capture_output=True,
                text=True,
            )
            print(proc.stdout)
            if proc.stderr:
                print(proc.stderr, file=sys.stderr)
        else:
            print(policy_yaml)

    elif args.command == "generate-allow":
        policy_yaml = generate_allow_policy(
            namespace=args.namespace,
            name=args.name,
            target_labels={"app": args.target_app},
            source_labels={"app": args.source_app},
            port=args.port,
            protocol=args.protocol,
        )
        print(policy_yaml)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
