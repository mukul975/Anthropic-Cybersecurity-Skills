#!/usr/bin/env python3
"""
Kubernetes Network Policy Auditor

Checks for missing network policies, default-deny enforcement,
and identifies namespaces without proper segmentation.
"""

import subprocess
import json
import sys
from dataclasses import dataclass, field


@dataclass
class NetPolFinding:
    namespace: str
    severity: str
    issue: str
    remediation: str


def run_kubectl_json(args: list):
    cmd = ["kubectl"] + args + ["-o", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return None
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return None


def audit_network_policies():
    findings = []
    system_ns = {"kube-system", "kube-public", "kube-node-lease"}

    namespaces = run_kubectl_json(["get", "namespaces"])
    if not namespaces:
        print("[!] Cannot list namespaces")
        return findings

    for ns in namespaces.get("items", []):
        ns_name = ns["metadata"]["name"]
        if ns_name in system_ns:
            continue

        netpols = run_kubectl_json(["get", "networkpolicies", "-n", ns_name])
        policies = netpols.get("items", []) if netpols else []

        if not policies:
            findings.append(NetPolFinding(
                namespace=ns_name, severity="HIGH",
                issue="No NetworkPolicies defined",
                remediation=f"Create default-deny ingress/egress policy in namespace '{ns_name}'"
            ))
            continue

        # Check for default-deny
        has_default_deny_ingress = False
        has_default_deny_egress = False

        for pol in policies:
            spec = pol.get("spec", {})
            pod_selector = spec.get("podSelector", {})
            policy_types = spec.get("policyTypes", [])

            if not pod_selector.get("matchLabels") and not pod_selector.get("matchExpressions"):
                if "Ingress" in policy_types and not spec.get("ingress"):
                    has_default_deny_ingress = True
                if "Egress" in policy_types and not spec.get("egress"):
                    has_default_deny_egress = True

        if not has_default_deny_ingress:
            findings.append(NetPolFinding(
                namespace=ns_name, severity="HIGH",
                issue="Missing default-deny ingress policy",
                remediation="Create NetworkPolicy with empty podSelector and Ingress policyType with no ingress rules"
            ))

        if not has_default_deny_egress:
            findings.append(NetPolFinding(
                namespace=ns_name, severity="MEDIUM",
                issue="Missing default-deny egress policy",
                remediation="Create NetworkPolicy with empty podSelector and Egress policyType with no egress rules"
            ))

    return findings


def main():
    print("[*] Kubernetes Network Policy Auditor\n")
    findings = audit_network_policies()

    print(f"\n{'='*60}")
    print(f"NETWORK POLICY AUDIT REPORT")
    print(f"{'='*60}")
    print(f"Total Findings: {len(findings)}")

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        sev_findings = [f for f in findings if f.severity == sev]
        if sev_findings:
            print(f"\n{sev}:")
            for f in sev_findings:
                print(f"  [{f.namespace}] {f.issue}")
                print(f"    Fix: {f.remediation}")

    with open("netpol_audit_report.json", "w") as fh:
        json.dump({"findings": [{"namespace": f.namespace, "severity": f.severity,
                                  "issue": f.issue, "remediation": f.remediation}
                                 for f in findings]}, fh, indent=2)
    print("\n[*] Report saved to netpol_audit_report.json")

    if any(f.severity in ("CRITICAL", "HIGH") for f in findings):
        sys.exit(1)


if __name__ == "__main__":
    main()
