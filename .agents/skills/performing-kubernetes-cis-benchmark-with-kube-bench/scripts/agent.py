#!/usr/bin/env python3
"""Agent for performing Kubernetes CIS benchmark assessment with kube-bench."""

import json
import argparse
import subprocess
from datetime import datetime


def run_kube_bench(target="node", benchmark=None):
    """Execute kube-bench CIS benchmark scan."""
    cmd = ["kube-bench", "run", "--json"]
    if target in ("master", "controlplane"):
        cmd += ["--targets", "master"]
    elif target == "node":
        cmd += ["--targets", "node"]
    elif target == "etcd":
        cmd += ["--targets", "etcd"]
    elif target == "policies":
        cmd += ["--targets", "policies"]
    if benchmark:
        cmd += ["--benchmark", benchmark]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        data = json.loads(result.stdout)
        tests = data.get("Tests", data.get("tests", []))
        summary = {"pass": 0, "fail": 0, "warn": 0, "info": 0}
        failures = []
        for section in tests:
            for test in section.get("results", section.get("Results", [])):
                status = test.get("status", "").lower()
                summary[status] = summary.get(status, 0) + 1
                if status == "fail":
                    failures.append({
                        "id": test.get("test_number", test.get("TestNumber", "")),
                        "desc": test.get("test_desc", test.get("TestDesc", ""))[:200],
                        "remediation": test.get("remediation", test.get("Remediation", ""))[:300],
                        "scored": test.get("scored", test.get("IsScored", True)),
                    })
        return {
            "target": target, "timestamp": datetime.utcnow().isoformat(),
            "summary": summary, "total_checks": sum(summary.values()),
            "compliance_pct": round(summary["pass"] / max(sum(summary.values()), 1) * 100, 1),
            "failures": failures,
        }
    except FileNotFoundError:
        return {"error": "kube-bench not found — install from github.com/aquasecurity/kube-bench"}
    except json.JSONDecodeError:
        return {"error": "Failed to parse kube-bench output", "raw": result.stdout[:500]}
    except Exception as e:
        return {"error": str(e)}


def check_pod_security(namespace="default"):
    """Check pod security settings via kubectl."""
    cmd = ["kubectl", "get", "pods", "-n", namespace, "-o", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        data = json.loads(result.stdout)
        pods = data.get("items", [])
        findings = []
        for pod in pods:
            name = pod.get("metadata", {}).get("name", "")
            for container in pod.get("spec", {}).get("containers", []):
                sc = container.get("securityContext", {})
                issues = []
                if sc.get("privileged"):
                    issues.append("PRIVILEGED_CONTAINER")
                if sc.get("runAsUser") == 0 or not sc.get("runAsNonRoot"):
                    issues.append("RUNS_AS_ROOT")
                if not sc.get("readOnlyRootFilesystem"):
                    issues.append("WRITABLE_ROOT_FS")
                caps = sc.get("capabilities", {})
                if caps.get("add") and any(c in caps["add"] for c in ["SYS_ADMIN", "NET_ADMIN", "ALL"]):
                    issues.append("DANGEROUS_CAPABILITIES")
                if not sc.get("allowPrivilegeEscalation") is False:
                    issues.append("PRIVILEGE_ESCALATION_ALLOWED")
                if issues:
                    findings.append({"pod": name, "container": container.get("name"), "issues": issues})
        return {
            "namespace": namespace, "total_pods": len(pods),
            "pods_with_issues": len(findings), "findings": findings,
        }
    except FileNotFoundError:
        return {"error": "kubectl not found"}
    except Exception as e:
        return {"error": str(e)}


def check_rbac_config():
    """Audit RBAC configuration for overly permissive roles."""
    findings = []
    for resource in ["clusterroles", "clusterrolebindings"]:
        cmd = ["kubectl", "get", resource, "-o", "json"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            data = json.loads(result.stdout)
            for item in data.get("items", []):
                name = item.get("metadata", {}).get("name", "")
                if resource == "clusterroles":
                    for rule in item.get("rules", []):
                        verbs = rule.get("verbs", [])
                        resources = rule.get("resources", [])
                        if "*" in verbs and "*" in resources:
                            findings.append({"type": "clusterrole", "name": name, "issue": "WILDCARD_ALL_PERMISSIONS"})
                        elif "create" in verbs and "pods" in resources:
                            findings.append({"type": "clusterrole", "name": name, "issue": "CAN_CREATE_PODS"})
                elif resource == "clusterrolebindings":
                    subjects = item.get("subjects", [])
                    role_ref = item.get("roleRef", {}).get("name", "")
                    if role_ref == "cluster-admin":
                        for subj in subjects:
                            findings.append({
                                "type": "clusterrolebinding", "name": name,
                                "issue": f"CLUSTER_ADMIN_BOUND_TO_{subj.get('kind', '')}:{subj.get('name', '')}",
                            })
        except Exception as e:
            findings.append({"type": resource, "error": str(e)})
    return {"total_findings": len(findings), "findings": findings}


def check_network_policies(namespace="default"):
    """Verify network policies exist and cover pods."""
    cmd = ["kubectl", "get", "networkpolicies", "-n", namespace, "-o", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        data = json.loads(result.stdout)
        policies = data.get("items", [])
        if not policies:
            return {"namespace": namespace, "finding": "NO_NETWORK_POLICIES", "severity": "HIGH",
                    "recommendation": "Implement default-deny NetworkPolicy"}
        return {
            "namespace": namespace, "policy_count": len(policies),
            "policies": [{"name": p["metadata"]["name"],
                          "pod_selector": p.get("spec", {}).get("podSelector", {}),
                          "ingress_rules": len(p.get("spec", {}).get("ingress", [])),
                          "egress_rules": len(p.get("spec", {}).get("egress", []))}
                         for p in policies],
        }
    except Exception as e:
        return {"error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Kubernetes CIS Benchmark Agent (kube-bench)")
    sub = parser.add_subparsers(dest="command")
    b = sub.add_parser("bench", help="Run kube-bench CIS scan")
    b.add_argument("--target", default="node", choices=["master", "controlplane", "node", "etcd", "policies"])
    b.add_argument("--benchmark", help="CIS benchmark version")
    p = sub.add_parser("pods", help="Check pod security settings")
    p.add_argument("--namespace", default="default")
    sub.add_parser("rbac", help="Audit RBAC configuration")
    n = sub.add_parser("netpol", help="Check network policies")
    n.add_argument("--namespace", default="default")
    args = parser.parse_args()
    if args.command == "bench":
        result = run_kube_bench(args.target, args.benchmark)
    elif args.command == "pods":
        result = check_pod_security(args.namespace)
    elif args.command == "rbac":
        result = check_rbac_config()
    elif args.command == "netpol":
        result = check_network_policies(args.namespace)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
