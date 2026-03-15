#!/usr/bin/env python3
"""Agent for auditing and generating Calico Kubernetes network policies."""

import json
import argparse
import subprocess
import yaml
from datetime import datetime
from collections import Counter


def kubectl_get(resource, namespace=None, label_selector=None):
    """Get Kubernetes resources via kubectl."""
    cmd = ["kubectl", "get", resource, "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")
    if label_selector:
        cmd.extend(["-l", label_selector])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        return {"error": result.stderr.strip()}
    return json.loads(result.stdout) if result.stdout.strip() else {}


def list_network_policies():
    """List all NetworkPolicy and Calico GlobalNetworkPolicy resources."""
    k8s_np = kubectl_get("networkpolicy")
    calico_gnp = kubectl_get("globalnetworkpolicy")
    return {
        "k8s_network_policies": k8s_np.get("items", []) if isinstance(k8s_np, dict) else [],
        "calico_global_policies": calico_gnp.get("items", []) if isinstance(calico_gnp, dict) else [],
    }


def audit_network_policies(policies_path):
    """Audit network policies for security gaps."""
    with open(policies_path) as f:
        data = json.load(f)
    policies = data if isinstance(data, list) else data.get("items", data.get("policies", []))
    findings = []
    namespaces_covered = set()

    for policy in policies:
        metadata = policy.get("metadata", {})
        spec = policy.get("spec", {})
        ns = metadata.get("namespace", "default")
        namespaces_covered.add(ns)

        policy_types = spec.get("policyTypes", [])
        if "Ingress" not in policy_types and "Egress" not in policy_types:
            findings.append({
                "policy": metadata.get("name", ""),
                "namespace": ns,
                "issue": "No policyTypes defined (defaults to ingress-only)",
                "severity": "MEDIUM",
            })

        if "Egress" not in policy_types:
            findings.append({
                "policy": metadata.get("name", ""),
                "namespace": ns,
                "issue": "No egress policy - all outbound traffic allowed",
                "severity": "HIGH",
            })

        ingress_rules = spec.get("ingress", [])
        for rule in ingress_rules:
            if not rule.get("from"):
                findings.append({
                    "policy": metadata.get("name", ""),
                    "issue": "Ingress rule allows from all sources",
                    "severity": "HIGH",
                })

        egress_rules = spec.get("egress", [])
        for rule in egress_rules:
            if not rule.get("to"):
                findings.append({
                    "policy": metadata.get("name", ""),
                    "issue": "Egress rule allows to all destinations",
                    "severity": "MEDIUM",
                })

    return {"findings": findings, "namespaces_covered": list(namespaces_covered),
            "total_policies": len(policies)}


def generate_default_deny(namespace):
    """Generate a default deny-all NetworkPolicy for a namespace."""
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "default-deny-all", "namespace": namespace},
        "spec": {
            "podSelector": {},
            "policyTypes": ["Ingress", "Egress"],
        },
    }


def generate_allow_dns_egress(namespace):
    """Generate a policy allowing DNS egress to kube-dns."""
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "allow-dns-egress", "namespace": namespace},
        "spec": {
            "podSelector": {},
            "policyTypes": ["Egress"],
            "egress": [{
                "to": [{"namespaceSelector": {"matchLabels": {
                    "kubernetes.io/metadata.name": "kube-system"}}}],
                "ports": [{"protocol": "UDP", "port": 53},
                           {"protocol": "TCP", "port": 53}],
            }],
        },
    }


def generate_app_policy(namespace, app_label, allowed_ingress_labels=None,
                         allowed_egress_ports=None):
    """Generate a Calico-style network policy for an application."""
    policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": f"allow-{app_label}", "namespace": namespace},
        "spec": {
            "podSelector": {"matchLabels": {"app": app_label}},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [],
            "egress": [],
        },
    }
    if allowed_ingress_labels:
        for label in allowed_ingress_labels:
            policy["spec"]["ingress"].append({
                "from": [{"podSelector": {"matchLabels": {"app": label}}}],
            })
    if allowed_egress_ports:
        for port_info in allowed_egress_ports:
            policy["spec"]["egress"].append({
                "ports": [{"protocol": port_info.get("protocol", "TCP"),
                           "port": port_info["port"]}],
            })
    return policy


def check_unprotected_namespaces():
    """Find namespaces without any network policies."""
    namespaces = kubectl_get("namespaces")
    policies = kubectl_get("networkpolicy")
    if isinstance(namespaces, dict) and "error" not in namespaces:
        all_ns = {item["metadata"]["name"] for item in namespaces.get("items", [])}
    else:
        return {"error": "Cannot list namespaces"}

    protected_ns = set()
    if isinstance(policies, dict) and "error" not in policies:
        for item in policies.get("items", []):
            protected_ns.add(item.get("metadata", {}).get("namespace", "default"))

    system_ns = {"kube-system", "kube-public", "kube-node-lease"}
    unprotected = all_ns - protected_ns - system_ns
    return {
        "total_namespaces": len(all_ns),
        "protected": len(protected_ns),
        "unprotected": list(unprotected),
        "severity": "HIGH" if unprotected else "INFO",
    }


def main():
    parser = argparse.ArgumentParser(description="Calico Network Policy Agent")
    parser.add_argument("--audit", help="Network policies JSON to audit")
    parser.add_argument("--namespace", help="Namespace for policy generation")
    parser.add_argument("--app", help="App label for policy generation")
    parser.add_argument("--action", choices=["audit", "generate", "check", "full"],
                        default="full")
    parser.add_argument("--output", default="calico_netpol_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "results": {}}

    if args.action in ("audit", "full") and args.audit:
        result = audit_network_policies(args.audit)
        report["results"]["audit"] = result
        print(f"[+] Audit: {len(result['findings'])} findings across {result['total_policies']} policies")

    if args.action in ("generate", "full") and args.namespace:
        policies = [
            generate_default_deny(args.namespace),
            generate_allow_dns_egress(args.namespace),
        ]
        if args.app:
            policies.append(generate_app_policy(args.namespace, args.app))
        report["results"]["generated"] = policies
        print(f"[+] Generated {len(policies)} policies for {args.namespace}")

    if args.action in ("check", "full"):
        result = check_unprotected_namespaces()
        report["results"]["unprotected"] = result
        print(f"[+] Unprotected namespaces: {result.get('unprotected', [])}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
