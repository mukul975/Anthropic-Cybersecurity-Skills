#!/usr/bin/env python3
"""Kubernetes Network Policy Agent - audits pod-to-pod communication and network policy coverage."""

import json
import argparse
import logging
import subprocess
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def kubectl_json(args_list):
    """Execute kubectl command and return JSON output."""
    cmd = ["kubectl"] + args_list + ["-o", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout) if result.returncode == 0 else {}


def get_namespaces():
    return kubectl_json(["get", "namespaces"])


def get_network_policies(namespace="--all-namespaces"):
    if namespace == "--all-namespaces":
        return kubectl_json(["get", "networkpolicies", "--all-namespaces"])
    return kubectl_json(["get", "networkpolicies", "-n", namespace])


def get_pods(namespace="--all-namespaces"):
    if namespace == "--all-namespaces":
        return kubectl_json(["get", "pods", "--all-namespaces"])
    return kubectl_json(["get", "pods", "-n", namespace])


def analyze_policy_coverage(policies, pods):
    """Determine which pods are covered by network policies."""
    policy_selectors = []
    for item in policies.get("items", []):
        ns = item.get("metadata", {}).get("namespace", "")
        spec = item.get("spec", {})
        selector = spec.get("podSelector", {}).get("matchLabels", {})
        policy_types = spec.get("policyTypes", [])
        policy_selectors.append({
            "namespace": ns,
            "selector": selector,
            "ingress": "Ingress" in policy_types or spec.get("ingress") is not None,
            "egress": "Egress" in policy_types or spec.get("egress") is not None,
        })
    covered_pods = set()
    uncovered_pods = []
    for pod in pods.get("items", []):
        pod_ns = pod.get("metadata", {}).get("namespace", "")
        pod_name = pod.get("metadata", {}).get("name", "")
        pod_labels = pod.get("metadata", {}).get("labels", {})
        is_covered = False
        for policy in policy_selectors:
            if policy["namespace"] != pod_ns:
                continue
            if not policy["selector"]:
                is_covered = True
                break
            if all(pod_labels.get(k) == v for k, v in policy["selector"].items()):
                is_covered = True
                break
        if is_covered:
            covered_pods.add(f"{pod_ns}/{pod_name}")
        else:
            uncovered_pods.append({"namespace": pod_ns, "pod": pod_name, "labels": pod_labels})
    total = len(pods.get("items", []))
    return {
        "total_pods": total,
        "covered_pods": len(covered_pods),
        "uncovered_pods": len(uncovered_pods),
        "coverage_percent": round(len(covered_pods) / max(total, 1) * 100, 1),
        "uncovered_pod_list": uncovered_pods[:20],
    }


def detect_overly_permissive_policies(policies):
    """Find network policies that allow all traffic."""
    findings = []
    for item in policies.get("items", []):
        name = item.get("metadata", {}).get("name", "")
        ns = item.get("metadata", {}).get("namespace", "")
        spec = item.get("spec", {})
        if not spec.get("podSelector", {}).get("matchLabels"):
            ingress_rules = spec.get("ingress", [])
            for rule in ingress_rules:
                if not rule.get("from"):
                    findings.append({"policy": name, "namespace": ns,
                                   "issue": "allows_all_ingress", "severity": "high"})
            egress_rules = spec.get("egress", [])
            for rule in egress_rules:
                if not rule.get("to"):
                    findings.append({"policy": name, "namespace": ns,
                                   "issue": "allows_all_egress", "severity": "medium"})
    return findings


def analyze_namespace_isolation(policies, namespaces):
    """Check which namespaces have default-deny policies."""
    ns_with_deny = set()
    for item in policies.get("items", []):
        spec = item.get("spec", {})
        if (not spec.get("podSelector", {}).get("matchLabels") and
            not spec.get("ingress") and "Ingress" in spec.get("policyTypes", [])):
            ns_with_deny.add(item.get("metadata", {}).get("namespace", ""))
    all_ns = [ns.get("metadata", {}).get("name", "") for ns in namespaces.get("items", [])]
    system_ns = {"kube-system", "kube-public", "kube-node-lease"}
    user_ns = [ns for ns in all_ns if ns not in system_ns]
    return {
        "total_namespaces": len(user_ns),
        "namespaces_with_default_deny": len(ns_with_deny),
        "isolation_percent": round(len(ns_with_deny) / max(len(user_ns), 1) * 100, 1),
        "unprotected_namespaces": [ns for ns in user_ns if ns not in ns_with_deny],
    }


def generate_report(policies, pods, namespaces):
    coverage = analyze_policy_coverage(policies, pods)
    permissive = detect_overly_permissive_policies(policies)
    isolation = analyze_namespace_isolation(policies, namespaces)
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "total_network_policies": len(policies.get("items", [])),
        "pod_coverage": coverage,
        "namespace_isolation": isolation,
        "overly_permissive_policies": permissive,
        "total_findings": len(permissive),
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="Kubernetes Network Policy Audit Agent")
    parser.add_argument("--namespace", default="--all-namespaces", help="Namespace to audit")
    parser.add_argument("--output", default="k8s_netpol_report.json")
    args = parser.parse_args()

    policies = get_network_policies(args.namespace)
    pods = get_pods(args.namespace)
    namespaces = get_namespaces()
    report = generate_report(policies, pods, namespaces)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("K8s NetPol: %.1f%% pod coverage, %.1f%% namespace isolation, %d findings",
                report["pod_coverage"]["coverage_percent"],
                report["namespace_isolation"]["isolation_percent"],
                report["total_findings"])
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
