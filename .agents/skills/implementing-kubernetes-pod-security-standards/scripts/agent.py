#!/usr/bin/env python3
"""Agent for auditing Kubernetes Pod Security Standards enforcement."""

import json
import argparse
import subprocess
from datetime import datetime
from collections import Counter


PSS_LEVELS = {
    "privileged": {"order": 0, "description": "Unrestricted, for system workloads"},
    "baseline": {"order": 1, "description": "Minimally restrictive, prevents known escalations"},
    "restricted": {"order": 2, "description": "Heavily restricted, hardened best practices"},
}

BASELINE_VIOLATIONS = [
    "hostNetwork", "hostPID", "hostIPC", "hostPorts",
    "privileged", "allowPrivilegeEscalation",
    "capabilities.add (non-default)", "seccomp (unconfined)",
]

RESTRICTED_VIOLATIONS = BASELINE_VIOLATIONS + [
    "runAsNonRoot not set", "runAsUser=0",
    "seccompProfile not RuntimeDefault/Localhost",
    "capabilities.drop not ALL", "readOnlyRootFilesystem not set",
]


def kubectl_json(args_list):
    """Run kubectl and return JSON."""
    cmd = ["kubectl"] + args_list + ["-o", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        return {"error": result.stderr.strip()}
    return json.loads(result.stdout) if result.stdout.strip() else {}


def audit_namespace_labels():
    """Audit PSA labels on all namespaces."""
    ns_data = kubectl_json(["get", "namespaces"])
    if "error" in ns_data:
        return ns_data
    results = []
    for ns in ns_data.get("items", []):
        name = ns["metadata"]["name"]
        labels = ns["metadata"].get("labels", {})
        enforce = labels.get("pod-security.kubernetes.io/enforce", "")
        audit = labels.get("pod-security.kubernetes.io/audit", "")
        warn = labels.get("pod-security.kubernetes.io/warn", "")
        system = name in ("kube-system", "kube-public", "kube-node-lease")
        results.append({
            "namespace": name, "system": system,
            "enforce": enforce, "audit": audit, "warn": warn,
            "protected": bool(enforce),
            "severity": "INFO" if enforce or system else "HIGH",
        })
    return results


def audit_pod_security(pods_path):
    """Audit pods against Pod Security Standards."""
    with open(pods_path) as f:
        data = json.load(f)
    pods = data if isinstance(data, list) else data.get("items", [])
    findings = []

    for pod in pods:
        metadata = pod.get("metadata", {})
        spec = pod.get("spec", {})
        pod_name = metadata.get("name", "")
        ns = metadata.get("namespace", "default")

        if spec.get("hostNetwork"):
            findings.append({"pod": pod_name, "ns": ns, "violation": "hostNetwork",
                             "level": "baseline", "severity": "HIGH"})
        if spec.get("hostPID"):
            findings.append({"pod": pod_name, "ns": ns, "violation": "hostPID",
                             "level": "baseline", "severity": "HIGH"})

        for container in spec.get("containers", []) + spec.get("initContainers", []):
            sc = container.get("securityContext", {})
            c_name = container.get("name", "")

            if sc.get("privileged"):
                findings.append({"pod": pod_name, "container": c_name, "ns": ns,
                                 "violation": "privileged", "level": "baseline",
                                 "severity": "CRITICAL"})

            if sc.get("allowPrivilegeEscalation", True):
                findings.append({"pod": pod_name, "container": c_name, "ns": ns,
                                 "violation": "allowPrivilegeEscalation",
                                 "level": "restricted", "severity": "MEDIUM"})

            if not sc.get("runAsNonRoot"):
                findings.append({"pod": pod_name, "container": c_name, "ns": ns,
                                 "violation": "runAsNonRoot not set",
                                 "level": "restricted", "severity": "MEDIUM"})

            caps = sc.get("capabilities", {})
            added = caps.get("add", [])
            if added and any(c not in ("NET_BIND_SERVICE",) for c in added):
                findings.append({"pod": pod_name, "container": c_name, "ns": ns,
                                 "violation": f"capabilities.add: {added}",
                                 "level": "baseline", "severity": "HIGH"})

            dropped = caps.get("drop", [])
            if "ALL" not in dropped:
                findings.append({"pod": pod_name, "container": c_name, "ns": ns,
                                 "violation": "capabilities.drop not ALL",
                                 "level": "restricted", "severity": "MEDIUM"})

    return findings


def generate_namespace_labels(namespace, level="restricted"):
    """Generate PSA label patch for a namespace."""
    labels = {
        f"pod-security.kubernetes.io/enforce": level,
        f"pod-security.kubernetes.io/audit": level,
        f"pod-security.kubernetes.io/warn": level,
    }
    return {
        "command": f'kubectl label namespace {namespace} '
                   f'pod-security.kubernetes.io/enforce={level} '
                   f'pod-security.kubernetes.io/audit={level} '
                   f'pod-security.kubernetes.io/warn={level} --overwrite',
        "labels": labels,
    }


def generate_compliance_report(findings):
    """Generate PSS compliance summary."""
    by_level = Counter(f.get("level", "unknown") for f in findings)
    by_severity = Counter(f.get("severity", "unknown") for f in findings)
    by_violation = Counter(f.get("violation", "unknown") for f in findings)
    return {
        "total_violations": len(findings),
        "by_level": dict(by_level),
        "by_severity": dict(by_severity),
        "top_violations": dict(by_violation.most_common(10)),
        "baseline_violations": by_level.get("baseline", 0),
        "restricted_violations": by_level.get("restricted", 0),
    }


def main():
    parser = argparse.ArgumentParser(description="Kubernetes Pod Security Standards Agent")
    parser.add_argument("--pods", help="Pods JSON to audit")
    parser.add_argument("--namespace", help="Namespace for label generation")
    parser.add_argument("--level", choices=["privileged", "baseline", "restricted"],
                        default="restricted")
    parser.add_argument("--action", choices=["audit-ns", "audit-pods", "generate", "full"],
                        default="full")
    parser.add_argument("--output", default="pss_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "results": {}}

    if args.action in ("audit-ns", "full"):
        ns_audit = audit_namespace_labels()
        report["results"]["namespace_audit"] = ns_audit
        if isinstance(ns_audit, list):
            unprotected = sum(1 for n in ns_audit if not n["protected"] and not n["system"])
            print(f"[+] Namespaces: {unprotected} unprotected")

    if args.action in ("audit-pods", "full") and args.pods:
        findings = audit_pod_security(args.pods)
        summary = generate_compliance_report(findings)
        report["results"]["pod_audit"] = findings
        report["results"]["summary"] = summary
        print(f"[+] Pod violations: {summary['total_violations']}")

    if args.action in ("generate", "full") and args.namespace:
        labels = generate_namespace_labels(args.namespace, args.level)
        report["results"]["generated"] = labels
        print(f"[+] Labels for {args.namespace}: {args.level}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
